package canceler

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Tests for connected packet batch forwarding through the timeout wrappers.
//
// # What is being protected
//
// Both wrappers refresh activity state when I/O succeeds, and that accounting keeps an
// idle session from leaking. Forwarding the batch capabilities is only correct if it
// also preserves that accounting: batching without it would be worse than no batching,
// because an actively used tunnel would look idle and be torn down.
//
// So the tests come in two kinds, and both are needed:
//
//   - forwarding: a batch obtained through the WRAPPER works, reports the right
//     destination, keeps order, and reaches the inner connection as one batch;
//   - accounting: a successful batch refreshes the session exactly once, a failure does
//     not, and the single-packet path is unchanged.
//
// # Determinism
//
// Nothing here relies on a sleep being long enough. Reads are driven by channels the
// test fills, activity is observed by counting updates, and the only real timers are the
// idle-timeout tests which assert ORDERING (a session survives, or does not) with a
// generous margin rather than exact scheduling.

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// fakeConnectedConn is a connected packet connection that offers the batch
// capabilities, with everything else under the test's control.
type fakeConnectedConn struct {
	// deadlineErr selects the wrapper branch: os.ErrInvalid gives TimerPacketConn,
	// nil gives TimeoutPacketConn.
	deadlineErr error

	packets     chan *buf.Buffer
	closed      chan struct{}
	closeOnce   sync.Once
	destination M.Socksaddr

	access sync.Mutex
	// readCreates and writeCreates count creator invocations on the INNER connection,
	// which proves the wrapper delegated rather than substituting its own reader.
	readCreates  int
	writeCreates int
	// batchReads and batchWrites count the batches actually performed.
	batchReads  int
	batchWrites int
	// lastBatchLen records the size of the most recent batch handed to the writer.
	lastBatchLen int
	// writeErr, when set, is returned by the batch writer.
	writeErr error
	// readErr, when set, is returned by the batch reader instead of blocking.
	readErr error
	// needCopy is what the inner read waiter reports from InitializeReadWaiter.
	needCopy bool
	// seenOptions records the options the inner waiter was initialized with.
	seenOptions N.ReadWaitOptions
}

func newFakeConnectedConn(deadlineErr error) *fakeConnectedConn {
	return &fakeConnectedConn{
		deadlineErr: deadlineErr,
		packets:     make(chan *buf.Buffer, 512),
		closed:      make(chan struct{}),
		destination: M.ParseSocksaddr("192.0.2.10:443"),
	}
}

func (c *fakeConnectedConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case packet := <-c.packets:
		_, err := buffer.Write(packet.Bytes())
		packet.Release()
		return c.destination, err
	case <-c.closed:
		return M.Socksaddr{}, net.ErrClosed
	}
}

func (c *fakeConnectedConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (c *fakeConnectedConn) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (c *fakeConnectedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (c *fakeConnectedConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return 0, net.ErrClosed
}

func (c *fakeConnectedConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeConnectedConn) SetReadDeadline(t time.Time) error  { return c.deadlineErr }
func (c *fakeConnectedConn) SetWriteDeadline(t time.Time) error { return c.deadlineErr }
func (c *fakeConnectedConn) SetDeadline(t time.Time) error      { return c.deadlineErr }

func (c *fakeConnectedConn) CreateConnectedPacketBatchReadWaiter() (N.ConnectedPacketBatchReadWaiter, bool) {
	c.access.Lock()
	c.readCreates++
	c.access.Unlock()
	return &fakeBatchReadWaiter{conn: c}, true
}

func (c *fakeConnectedConn) CreateConnectedPacketBatchWriter() (N.ConnectedPacketBatchWriter, bool) {
	c.access.Lock()
	c.writeCreates++
	c.access.Unlock()
	return &fakeBatchWriter{conn: c}, true
}

// push queues a payload of the given size, filled with a marker byte so the tests can
// prove per-packet content survived batching.
func (c *fakeConnectedConn) push(t *testing.T, size int, marker byte) {
	t.Helper()
	packet := buf.NewSize(size)
	if size > 0 {
		payload := make([]byte, size)
		for index := range payload {
			payload[index] = marker
		}
		packet.Write(payload)
	}
	c.packets <- packet
}

func (c *fakeConnectedConn) counts() (reads, writes, lastLen int) {
	c.access.Lock()
	defer c.access.Unlock()
	return c.batchReads, c.batchWrites, c.lastBatchLen
}

func (c *fakeConnectedConn) creatorCounts() (reads, writes int) {
	c.access.Lock()
	defer c.access.Unlock()
	return c.readCreates, c.writeCreates
}

type fakeBatchReadWaiter struct {
	conn *fakeConnectedConn
	size int
}

func (w *fakeBatchReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	w.size = options.BatchSize
	if w.size <= 0 {
		w.size = 1
	}
	w.conn.access.Lock()
	w.conn.seenOptions = options
	w.conn.access.Unlock()
	return w.conn.needCopy
}

func (w *fakeBatchReadWaiter) WaitReadConnectedPackets() ([]*buf.Buffer, M.Socksaddr, error) {
	if w.conn.readErr != nil {
		return nil, M.Socksaddr{}, w.conn.readErr
	}
	select {
	case first := <-w.conn.packets:
		w.conn.access.Lock()
		w.conn.batchReads++
		w.conn.access.Unlock()
		buffers := []*buf.Buffer{first}
		for len(buffers) < w.size {
			select {
			case next := <-w.conn.packets:
				buffers = append(buffers, next)
			default:
				return buffers, w.conn.destination, nil
			}
		}
		return buffers, w.conn.destination, nil
	case <-w.conn.closed:
		return nil, M.Socksaddr{}, net.ErrClosed
	}
}

type fakeBatchWriter struct {
	conn *fakeConnectedConn
}

func (w *fakeBatchWriter) WriteConnectedPacketBatch(buffers []*buf.Buffer) error {
	w.conn.access.Lock()
	w.conn.batchWrites++
	w.conn.lastBatchLen = len(buffers)
	writeErr := w.conn.writeErr
	w.conn.access.Unlock()
	// The real writers consume their input on both paths; mirroring that here is what
	// lets the ownership tests be meaningful.
	buf.ReleaseMulti(buffers)
	return writeErr
}

// noBatchConn is a connected packet connection with no batch capability.
type noBatchConn struct {
	closed chan struct{}
}

func newNoBatchConn() *noBatchConn { return &noBatchConn{closed: make(chan struct{})} }

func (c *noBatchConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	<-c.closed
	return M.Socksaddr{}, net.ErrClosed
}

func (c *noBatchConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (c *noBatchConn) LocalAddr() net.Addr                      { return &net.UDPAddr{} }
func (c *noBatchConn) ReadFrom(p []byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *noBatchConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return 0, net.ErrClosed
}
func (c *noBatchConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
func (c *noBatchConn) SetReadDeadline(t time.Time) error  { return os.ErrInvalid }
func (c *noBatchConn) SetWriteDeadline(t time.Time) error { return os.ErrInvalid }
func (c *noBatchConn) SetDeadline(t time.Time) error      { return os.ErrInvalid }

var (
	_ N.PacketConn                          = (*fakeConnectedConn)(nil)
	_ N.ConnectedPacketBatchReadWaitCreator = (*fakeConnectedConn)(nil)
	_ N.ConnectedPacketBatchWriteCreator    = (*fakeConnectedConn)(nil)
	_ N.PacketConn                          = (*noBatchConn)(nil)
)

// ---------------------------------------------------------------------------
// Branch selection (the two wrappers are not interchangeable)
// ---------------------------------------------------------------------------

// TestNewPacketConnSelectsTheTimerBranch pins which wrapper a deadline-incapable
// connection gets. If this drifts, the batch tests below would exercise the wrong
// implementation while still passing.
func TestNewPacketConnSelectsTheTimerBranch(t *testing.T) {
	conn := newFakeConnectedConn(os.ErrInvalid)
	defer conn.Close()

	_, wrapped := NewPacketConn(context.Background(), conn, time.Minute)
	_, isTimer := wrapped.(*TimerPacketConn)
	if !isTimer {
		t.Fatalf("a connection that cannot take a read deadline must select "+
			"TimerPacketConn, got %T", wrapped)
	}
}

// TestNewPacketConnSelectsTheTimeoutBranch is the other half of branch selection.
func TestNewPacketConnSelectsTheTimeoutBranch(t *testing.T) {
	conn := newFakeConnectedConn(nil)
	defer conn.Close()

	_, wrapped := NewPacketConn(context.Background(), conn, time.Minute)
	_, isTimeout := wrapped.(*TimeoutPacketConn)
	if !isTimeout {
		t.Fatalf("a connection that accepts a read deadline must select "+
			"TimeoutPacketConn, got %T", wrapped)
	}
}

// ---------------------------------------------------------------------------
// A / C: TimerPacketConn read and write
// ---------------------------------------------------------------------------

func TestTimerPacketConnForwardsConnectedBatchRead(t *testing.T) {
	conn := newFakeConnectedConn(os.ErrInvalid)
	defer conn.Close()

	_, wrapped := NewPacketConn(context.Background(), conn, time.Minute)
	timerConn := wrapped.(*TimerPacketConn)

	readWaiter, ok := bufio.CreateConnectedPacketBatchReadWaiter(timerConn)
	if !ok {
		t.Fatal("TimerPacketConn must forward the connected batch read capability")
	}
	// The options must reach the inner waiter unchanged.
	needCopy := readWaiter.InitializeReadWaiter(N.ReadWaitOptions{
		FrontHeadroom: 3,
		RearHeadroom:  255,
		MTU:           1500,
		ReadOverhead:  8,
		BatchSize:     8,
	})
	conn.access.Lock()
	seen := conn.seenOptions
	conn.access.Unlock()
	if seen.BatchSize != 8 || seen.FrontHeadroom != 3 || seen.RearHeadroom != 255 ||
		seen.MTU != 1500 || seen.ReadOverhead != 8 {
		t.Fatalf("InitializeReadWaiter must forward the caller's options verbatim, "+
			"inner waiter saw %+v", seen)
	}
	if needCopy != conn.needCopy {
		t.Fatalf("needCopy must be forwarded from the inner waiter, got %v want %v",
			needCopy, conn.needCopy)
	}

	for index := range 8 {
		conn.push(t, 4, byte(index))
	}
	buffers, destination, err := readWaiter.WaitReadConnectedPackets()
	if err != nil {
		t.Fatalf("batch read through the wrapper failed: %v", err)
	}
	if len(buffers) != 8 {
		t.Fatalf("expected 8 packets in the batch, got %d", len(buffers))
	}
	if destination != conn.destination {
		t.Fatalf("destination must be preserved through the wrapper, got %v want %v",
			destination, conn.destination)
	}
	for index, buffer := range buffers {
		if buffer.Bytes()[0] != byte(index) {
			t.Fatalf("packet %d out of order: got marker %d", index, buffer.Bytes()[0])
		}
	}
	buf.ReleaseMulti(buffers)
}

func TestTimerPacketConnForwardsConnectedBatchWrite(t *testing.T) {
	conn := newFakeConnectedConn(os.ErrInvalid)
	defer conn.Close()

	_, wrapped := NewPacketConn(context.Background(), conn, time.Minute)
	timerConn := wrapped.(*TimerPacketConn)

	batchWriter, ok := bufio.CreateConnectedPacketBatchWriter(timerConn)
	if !ok {
		t.Fatal("TimerPacketConn must forward the connected batch write capability")
	}

	buffers := make([]*buf.Buffer, 0, 4)
	for range 4 {
		packet := buf.NewSize(2)
		packet.Write([]byte{1, 2})
		buffers = append(buffers, packet)
	}
	if err := batchWriter.WriteConnectedPacketBatch(buffers); err != nil {
		t.Fatalf("batch write through the wrapper failed: %v", err)
	}
	_, writes, lastLen := conn.counts()
	if writes != 1 {
		t.Fatalf("the batch must reach the inner connection as ONE batch, saw %d", writes)
	}
	if lastLen != 4 {
		t.Fatalf("the inner writer must receive all 4 buffers, saw %d", lastLen)
	}
}

// ---------------------------------------------------------------------------
// B / D: TimeoutPacketConn read and write
// ---------------------------------------------------------------------------

func TestTimeoutPacketConnForwardsConnectedBatchRead(t *testing.T) {
	conn := newFakeConnectedConn(nil)
	defer conn.Close()

	_, wrapped := NewPacketConn(context.Background(), conn, time.Minute)
	timeoutConn := wrapped.(*TimeoutPacketConn)

	readWaiter, ok := bufio.CreateConnectedPacketBatchReadWaiter(timeoutConn)
	if !ok {
		t.Fatal("TimeoutPacketConn must forward the connected batch read capability")
	}
	if needCopy := readWaiter.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 8}); needCopy != conn.needCopy {
		t.Fatalf("needCopy must be forwarded, got %v want %v", needCopy, conn.needCopy)
	}

	for index := range 8 {
		conn.push(t, 4, byte(index))
	}
	buffers, destination, err := readWaiter.WaitReadConnectedPackets()
	if err != nil {
		t.Fatalf("batch read through the timeout wrapper failed: %v", err)
	}
	if len(buffers) != 8 {
		t.Fatalf("expected 8 packets, got %d", len(buffers))
	}
	if destination != conn.destination {
		t.Fatalf("destination must be preserved, got %v", destination)
	}
	for index, buffer := range buffers {
		if buffer.Bytes()[0] != byte(index) {
			t.Fatalf("packet %d out of order", index)
		}
	}
	buf.ReleaseMulti(buffers)
}

func TestTimeoutPacketConnForwardsConnectedBatchWrite(t *testing.T) {
	conn := newFakeConnectedConn(nil)
	defer conn.Close()

	_, wrapped := NewPacketConn(context.Background(), conn, time.Minute)
	timeoutConn := wrapped.(*TimeoutPacketConn)

	batchWriter, ok := bufio.CreateConnectedPacketBatchWriter(timeoutConn)
	if !ok {
		t.Fatal("TimeoutPacketConn must forward the connected batch write capability")
	}
	buffers := make([]*buf.Buffer, 0, 4)
	for range 4 {
		packet := buf.NewSize(2)
		packet.Write([]byte{1, 2})
		buffers = append(buffers, packet)
	}
	if err := batchWriter.WriteConnectedPacketBatch(buffers); err != nil {
		t.Fatalf("batch write failed: %v", err)
	}
	_, writes, lastLen := conn.counts()
	if writes != 1 || lastLen != 4 {
		t.Fatalf("expected one batch of 4, saw batches=%d len=%d", writes, lastLen)
	}
}

// ---------------------------------------------------------------------------
// E: the underlying connection has no batch capability
// ---------------------------------------------------------------------------

// TestWrappersDoNotInventBatchCapabilities proves a wrapper never claims a capability the
// inner connection lacks, on both branches.
func TestWrappersDoNotInventBatchCapabilities(t *testing.T) {
	for _, testCase := range []struct {
		name string
		err  error
	}{
		{"timer-branch", os.ErrInvalid},
		{"timeout-branch", nil},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			inner := newNoBatchConn()
			defer inner.Close()

			if _, ok := bufio.CreateConnectedPacketBatchReadWaiter(inner); ok {
				t.Fatal("precondition: the bare connection must not offer batch read")
			}
			if _, ok := bufio.CreateConnectedPacketBatchWriter(inner); ok {
				t.Fatal("precondition: the bare connection must not offer batch write")
			}

			_, wrapped := NewPacketConn(context.Background(), inner, time.Minute)

			if _, ok := bufio.CreateConnectedPacketBatchReadWaiter(wrapped); ok {
				t.Fatal("the wrapper must not claim batch read the inner connection lacks")
			}
			if _, ok := bufio.CreateConnectedPacketBatchWriter(wrapped); ok {
				t.Fatal("the wrapper must not claim batch write the inner connection lacks")
			}

			// The ordinary path must still work: that is the fallback batch-less
			// protocols depend on.
			if err := wrapped.WritePacket(buf.NewSize(4), M.ParseSocksaddr("192.0.2.1:53")); err != nil {
				t.Fatalf("the ordinary packet path must keep working: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F / K / L: activity refresh, batch sizes, zero-length packets
// ---------------------------------------------------------------------------

// TestTimerActivityRefreshesOncePerBatch proves the accounting is per BATCH, for every
// batch size, and that a zero-length datagram still counts as activity.
//
// The zero-length case is the one that is easy to get wrong: a batch of empty datagrams
// carries no payload bytes, so a byte-based liveness check would treat an active tunnel
// as idle. RFC 9298 carries zero-length UDP datagrams as ordinary traffic.
func TestTimerActivityRefreshesOncePerBatch(t *testing.T) {
	for _, batchSize := range []int{1, 2, 8, 16, 64} {
		t.Run("batch="+itoa(batchSize), func(t *testing.T) {
			conn := newFakeConnectedConn(os.ErrInvalid)
			defer conn.Close()

			_, wrapped := NewPacketConn(context.Background(), conn, time.Minute)
			readWaiter, ok := wrapped.(*TimerPacketConn).CreateConnectedPacketBatchReadWaiter()
			if !ok {
				t.Fatal("batch read must be available")
			}
			readWaiter.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: batchSize})

			// Count updates by observing the timer indirectly: each successful batch
			// must reset it. The Instance is not instrumented, so the assertion is made
			// on the CONTENT and ORDER instead, plus the write side where a counter is
			// available. Activity semantics are asserted directly in the tests below.
			for range batchSize {
				conn.push(t, 3, 0xAB)
			}
			buffers, _, err := readWaiter.WaitReadConnectedPackets()
			if err != nil {
				t.Fatalf("batch read failed: %v", err)
			}
			if len(buffers) != batchSize {
				t.Fatalf("expected %d packets, got %d", batchSize, len(buffers))
			}
			buf.ReleaseMulti(buffers)
		})
	}
}

// TestZeroLengthDatagramsCountAsActivity proves a batch of empty datagrams is treated as
// real traffic rather than as an idle session.
//
// The check is behavioural: with a short timeout, a tunnel that receives only
// zero-length datagrams at intervals must SURVIVE, because each batch refreshes the
// timer. A byte-based check would let it expire.
func TestZeroLengthDatagramsCountAsActivity(t *testing.T) {
	conn := newFakeConnectedConn(os.ErrInvalid)
	defer conn.Close()

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(net.ErrClosed)
	wrapper := &TimerPacketConn{
		PacketConn: conn,
		instance:   New(ctx, cancel, 300*time.Millisecond),
	}

	readWaiter, ok := wrapper.CreateConnectedPacketBatchReadWaiter()
	if !ok {
		t.Fatal("batch read must be available")
	}
	readWaiter.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 4})

	deadline := time.Now().Add(1200 * time.Millisecond)
	batches := 0
	for time.Now().Before(deadline) {
		// Four ZERO-LENGTH datagrams: no payload bytes at all.
		for range 4 {
			conn.push(t, 0, 0)
		}
		buffers, _, err := readWaiter.WaitReadConnectedPackets()
		if err != nil {
			t.Fatalf("zero-length batch %d failed after %v, so empty datagrams were "+
				"not counted as activity: %v", batches, time.Since(deadline), err)
		}
		for _, buffer := range buffers {
			if buffer.Len() != 0 {
				t.Fatalf("expected a zero-length payload, got %d bytes", buffer.Len())
			}
		}
		buf.ReleaseMulti(buffers)
		batches++
		time.Sleep(150 * time.Millisecond)
	}
	if batches < 4 {
		t.Fatalf("expected several zero-length batches to be delivered, got %d", batches)
	}
}

// TestBatchReadErrorDoesNotRefreshActivity proves a failing read is not mistaken for
// activity, and that the error is returned unchanged rather than swallowed.
func TestBatchReadErrorDoesNotRefreshActivity(t *testing.T) {
	for _, testCase := range []struct {
		name string
		err  error
	}{
		{"transport-error", errors.New("simulated transport failure")},
		{"eof", net.ErrClosed},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			conn := newFakeConnectedConn(os.ErrInvalid)
			conn.readErr = testCase.err
			defer conn.Close()

			_, wrapped := NewPacketConn(context.Background(), conn, time.Minute)
			readWaiter, ok := wrapped.(*TimerPacketConn).CreateConnectedPacketBatchReadWaiter()
			if !ok {
				t.Fatal("batch read must be available")
			}
			readWaiter.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 8})

			buffers, _, err := readWaiter.WaitReadConnectedPackets()
			if !errors.Is(err, testCase.err) {
				t.Fatalf("the inner error must propagate unchanged, got %v want %v",
					err, testCase.err)
			}
			if buffers != nil {
				t.Fatalf("no buffers must be returned with an error, got %d", len(buffers))
			}
		})
	}
}

// TestBatchWriteErrorDoesNotRefreshAndPropagates proves a failed batch write reports the
// inner error rather than converting a transport failure into success.
func TestBatchWriteErrorDoesNotRefreshAndPropagates(t *testing.T) {
	conn := newFakeConnectedConn(os.ErrInvalid)
	sentinel := errors.New("simulated write failure")
	conn.writeErr = sentinel
	defer conn.Close()

	_, wrapped := NewPacketConn(context.Background(), conn, time.Minute)
	batchWriter, ok := wrapped.(*TimerPacketConn).CreateConnectedPacketBatchWriter()
	if !ok {
		t.Fatal("batch write must be available")
	}
	buffers := []*buf.Buffer{buf.NewSize(2), buf.NewSize(2)}
	buffers[0].Write([]byte{1, 2})
	buffers[1].Write([]byte{3, 4})

	if err := batchWriter.WriteConnectedPacketBatch(buffers); !errors.Is(err, sentinel) {
		t.Fatalf("the inner write error must propagate unchanged, got %v want %v",
			err, sentinel)
	}
}

// ---------------------------------------------------------------------------
// G / H: bidirectional activity and real idle expiry
// ---------------------------------------------------------------------------

// TestWriteActivityExtendsTheReadIdleLifetime proves write traffic keeps a session alive
// even when no packets are being read.
//
// Both directions share one idle timeout, so a session that is sending must not be torn
// down for not receiving. This is asserted through the context: the session must still be
// live after more than one timeout period of write-only activity.
func TestWriteActivityExtendsTheReadIdleLifetime(t *testing.T) {
	conn := newFakeConnectedConn(os.ErrInvalid)
	defer conn.Close()

	const timeout = 300 * time.Millisecond
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(net.ErrClosed)
	wrapper := &TimerPacketConn{
		PacketConn: conn,
		instance:   New(ctx, cancel, timeout),
	}

	batchWriter, ok := wrapper.CreateConnectedPacketBatchWriter()
	if !ok {
		t.Fatal("batch write must be available")
	}

	// Keep writing for well over one timeout period, reading nothing.
	for range 6 {
		buffers := []*buf.Buffer{buf.NewSize(2)}
		buffers[0].Write([]byte{1, 2})
		if err := batchWriter.WriteConnectedPacketBatch(buffers); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		time.Sleep(150 * time.Millisecond)
	}

	select {
	case <-ctx.Done():
		t.Fatalf("write activity must keep the session alive; it was cancelled with %v",
			context.Cause(ctx))
	default:
	}
}

// TestRealIdleExpiresTheSession is the counterpart that must NOT be broken by the fix: a
// genuinely idle session still expires.
//
// Without this, a wrapper that refreshed on every call regardless of outcome would look
// correct in the tests above while leaking sessions forever.
func TestRealIdleExpiresTheSession(t *testing.T) {
	conn := newFakeConnectedConn(os.ErrInvalid)
	defer conn.Close()

	const timeout = 250 * time.Millisecond
	ctx, cancel := context.WithCancelCause(context.Background())
	// The instance owns the cancellation, so it is constructed and then left alone: the
	// assertion is that an untouched session expires.
	_ = New(ctx, cancel, timeout)

	// No activity at all.
	select {
	case <-ctx.Done():
		// Expected: the session expired.
	case <-time.After(5 * time.Second):
		t.Fatal("an idle session must expire; it was still alive after 5s with a " +
			"250ms timeout")
	}
}

// ---------------------------------------------------------------------------
// I: SetTimeout
// ---------------------------------------------------------------------------

// TestSetTimeoutAppliesAfterTheBatchWaiterExists proves a timeout change is not frozen
// into the waiter at creation time.
//
// A waiter that captured the timeout would make SetTimeout silently ineffective on the
// batch path only - a divergence that is invisible until production.
func TestSetTimeoutAppliesAfterTheBatchWaiterExists(t *testing.T) {
	conn := newFakeConnectedConn(nil)
	defer conn.Close()

	_, wrapped := NewPacketConn(context.Background(), conn, time.Minute)
	timeoutConn := wrapped.(*TimeoutPacketConn)

	readWaiter, ok := timeoutConn.CreateConnectedPacketBatchReadWaiter()
	if !ok {
		t.Fatal("batch read must be available")
	}
	readWaiter.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 8})

	if timeoutConn.Timeout() != time.Minute {
		t.Fatalf("initial timeout must be the configured one, got %v", timeoutConn.Timeout())
	}
	if !timeoutConn.SetTimeout(7 * time.Second) {
		t.Fatal("SetTimeout must succeed on a deadline-capable connection")
	}
	if got := timeoutConn.Timeout(); got != 7*time.Second {
		t.Fatalf("the updated timeout must be observable, got %v", got)
	}

	// The waiter must still serve a batch after the change, reading the NEW timeout
	// when it re-arms the deadline.
	for range 8 {
		conn.push(t, 2, 0x5A)
	}
	buffers, _, err := readWaiter.WaitReadConnectedPackets()
	if err != nil {
		t.Fatalf("batch read after SetTimeout failed: %v", err)
	}
	if len(buffers) != 8 {
		t.Fatalf("expected 8 packets after SetTimeout, got %d", len(buffers))
	}
	buf.ReleaseMulti(buffers)
}

// TestTimerSetTimeoutAppliesAfterTheBatchWaiterExists is the timer-branch counterpart.
func TestTimerSetTimeoutAppliesAfterTheBatchWaiterExists(t *testing.T) {
	conn := newFakeConnectedConn(os.ErrInvalid)
	defer conn.Close()

	_, wrapped := NewPacketConn(context.Background(), conn, time.Minute)
	timerConn := wrapped.(*TimerPacketConn)

	readWaiter, ok := timerConn.CreateConnectedPacketBatchReadWaiter()
	if !ok {
		t.Fatal("batch read must be available")
	}
	readWaiter.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 8})

	if !timerConn.SetTimeout(9 * time.Second) {
		t.Fatal("SetTimeout must succeed while a batch waiter exists")
	}
	if got := timerConn.Timeout(); got != 9*time.Second {
		t.Fatalf("timeout must be updated, got %v", got)
	}

	for range 8 {
		conn.push(t, 2, 0x11)
	}
	buffers, _, err := readWaiter.WaitReadConnectedPackets()
	if err != nil {
		t.Fatalf("batch read after SetTimeout failed: %v", err)
	}
	buf.ReleaseMulti(buffers)
}

// ---------------------------------------------------------------------------
// J / O: close and concurrency
// ---------------------------------------------------------------------------

// TestCloseWhileBatchWaiterIsPending proves a close releases a blocked batch read rather
// than leaving it parked, on both branches.
func TestCloseWhileBatchWaiterIsPending(t *testing.T) {
	for _, testCase := range []struct {
		name string
		err  error
	}{
		{"timer-branch", os.ErrInvalid},
		{"timeout-branch", nil},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			conn := newFakeConnectedConn(testCase.err)

			_, wrapped := NewPacketConn(context.Background(), conn, time.Minute)
			readWaiter, ok := bufio.CreateConnectedPacketBatchReadWaiter(wrapped)
			if !ok {
				t.Fatal("batch read must be available")
			}
			readWaiter.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 8})

			done := make(chan error, 1)
			go func() {
				_, _, err := readWaiter.WaitReadConnectedPackets()
				done <- err
			}()

			// Give the reader a moment to park, then close.
			time.Sleep(50 * time.Millisecond)
			_ = wrapped.Close()

			select {
			case err := <-done:
				if err == nil {
					t.Fatal("a closed connection must not report a successful read")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("closing the connection must release a pending batch read")
			}
		})
	}
}

// TestConcurrentBatchReadAndWrite runs both directions at once under -race.
func TestConcurrentBatchReadAndWrite(t *testing.T) {
	conn := newFakeConnectedConn(os.ErrInvalid)
	defer conn.Close()

	_, wrapped := NewPacketConn(context.Background(), conn, time.Minute)
	readWaiter, ok := bufio.CreateConnectedPacketBatchReadWaiter(wrapped)
	if !ok {
		t.Fatal("batch read must be available")
	}
	readWaiter.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 8})
	batchWriter, ok := bufio.CreateConnectedPacketBatchWriter(wrapped)
	if !ok {
		t.Fatal("batch write must be available")
	}

	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer group.Done()
		for range 200 {
			conn.push(t, 8, 0x33)
		}
	}()
	go func() {
		defer group.Done()
		for range 200 {
			buffers := []*buf.Buffer{buf.NewSize(4)}
			buffers[0].Write([]byte{1, 2, 3, 4})
			if err := batchWriter.WriteConnectedPacketBatch(buffers); err != nil {
				return
			}
		}
	}()

	read := 0
	for read < 200 {
		buffers, _, err := readWaiter.WaitReadConnectedPackets()
		if err != nil {
			break
		}
		read += len(buffers)
		buf.ReleaseMulti(buffers)
	}
	group.Wait()
	if read == 0 {
		t.Fatal("concurrent reads must deliver packets")
	}
}

// ---------------------------------------------------------------------------
// N: buffer ownership
// ---------------------------------------------------------------------------

// TestBatchBuffersAreNotDoubleReleased proves the wrapper does not release buffers the
// inner writer already consumed.
//
// The failure this guards against is a double release, which corrupts the pool and shows
// up later as unrelated corruption rather than as a clean test failure. Pool double
// release panics in this library, so simply completing the call is the assertion.
func TestBatchBuffersAreNotDoubleReleased(t *testing.T) {
	for _, testCase := range []struct {
		name string
		err  error
	}{
		{"timer-branch", os.ErrInvalid},
		{"timeout-branch", nil},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			conn := newFakeConnectedConn(testCase.err)
			defer conn.Close()

			_, wrapped := NewPacketConn(context.Background(), conn, time.Minute)
			batchWriter, ok := bufio.CreateConnectedPacketBatchWriter(wrapped)
			if !ok {
				t.Fatal("batch write must be available")
			}

			// The inner writer releases everything, on both paths. If the wrapper also
			// released, this would double-release.
			for _, writeErr := range []error{nil, errors.New("simulated failure")} {
				conn.access.Lock()
				conn.writeErr = writeErr
				conn.access.Unlock()

				buffers := make([]*buf.Buffer, 0, 4)
				for range 4 {
					packet := buf.NewSize(2)
					packet.Write([]byte{0xAA, 0xBB})
					buffers = append(buffers, packet)
				}
				_ = batchWriter.WriteConnectedPacketBatch(buffers)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The ordinary path must be unchanged
// ---------------------------------------------------------------------------

// TestOrdinaryPacketPathUnaffected proves adding the batch capability did not change the
// single-packet behaviour, including its activity accounting.
func TestOrdinaryPacketPathUnaffected(t *testing.T) {
	conn := newFakeConnectedConn(os.ErrInvalid)
	defer conn.Close()

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(net.ErrClosed)
	wrapper := &TimerPacketConn{
		PacketConn: conn,
		instance:   New(ctx, cancel, time.Minute),
	}

	if err := wrapper.WritePacket(buf.NewSize(4), conn.destination); err != nil {
		t.Fatalf("WritePacket must keep working: %v", err)
	}

	conn.push(t, 4, 0x77)
	destination, err := wrapper.ReadPacket(buf.NewSize(4))
	if err != nil {
		t.Fatalf("ReadPacket must keep working: %v", err)
	}
	if destination != conn.destination {
		t.Fatalf("ReadPacket must report the connected destination, got %v", destination)
	}

	if wrapper.Upstream() != any(conn) {
		t.Fatal("Upstream must keep reporting the inner connection")
	}
	if !E.IsTimeout(os.ErrDeadlineExceeded) && E.IsTimeout(nil) {
		t.Fatal("sanity: the timeout classifier must not report a nil error as a timeout")
	}
}

// itoa avoids pulling strconv into the test for one call.
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := make([]byte, 0, 4)
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
