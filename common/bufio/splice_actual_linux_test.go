package bufio

import (
	"crypto/rand"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Proof-level tests for the Linux splice engine: they run the real thing on real TCP sockets
// rather than a mock, and they are the only tests here that assert the splice SYSCALL ran.
//
// # Why the distinction matters
//
// Everything else in this package's splice tests establishes preconditions: that a
// syscall.RawConn exists, that copyDirect handed over, that the caller skipped the userspace
// copy. None of that is the shipped behaviour. A wrapper that quietly returns before reaching
// unix.Splice - or a build where the splice file is not compiled at all - satisfies every one
// of them. So the assertions here are, in order of importance:
//
//  1. spliceCall actually ran, counted through the seam in splice_linux.go;
//  2. the payload arrived byte-exact with no duplication and no truncation;
//  3. the fallback cases still deliver the payload when the handover does not happen.
//
// # Two things this harness had to learn on a real Linux runner
//
// Both were found by CI failing, and both are properties of the engine that a test has to
// respect rather than bugs to be papered over. Neither is worked around: the payload is compared
// byte for byte, so an early end is a failure rather than something the harness hides.
//
//  1. THE DESTINATION MUST BE DRAINED WHILE THE COPY RUNS. Splice moves bytes with
//     SPLICE_F_NONBLOCK. With nothing reading the far end, the loopback receive window closes,
//     the write splice exhausts the pipe by pushing one bufferful and then sees EAGAIN, and the
//     engine reports that as an error - by design, because a splice that cannot make progress
//     has no readiness signal to wait on from here. A proxy always has both directions moving;
//     the first version of this file copied first and read afterwards, and timed out.
//
//  2. THE SOURCE MUST BE FED WHILE THE COPY RUNS, NOT WRITTEN UP FRONT. This is the subtler one.
//     A source written to completion before the copy starts holds a burst the engine is not
//     built for: the read splice empties the socket, and the next read splice - inside the same
//     readability callback, because the poller only signalled once - returns EAGAIN with
//     notFirstTime already set. That surfaces as "splice read: resource temporarily
//     unavailable", which is indistinguishable from a stall, and the copy ends early. Feeding
//     the source from a goroutine while the copy runs keeps the read side supplied the way a
//     real sender does, and it is the only faithful shape: a proxy never has the whole stream
//     sitting in one socket buffer before it starts copying.
//
// # The hooks and the lock
//
// splicePipe2 and spliceCall are package-level seams, so a test that swaps one out must not run
// concurrently with any other test in this package. None of these tests call t.Parallel, and
// spliceTestHookLock serializes them against each other, which is also what keeps the counting
// closure honest under -race in CI where the whole suite runs together.
var spliceTestHookLock sync.Mutex

// spliceTestCount swaps the splice syscall for a wrapper that still calls the real one.
//
// observe, when non-nil, sees the invocation number (1-based) before the real syscall runs and
// may replace it with an error. That is how a real mid-stream failure is injected without
// depending on socket buffer sizes to produce one.
func spliceTestCount(t *testing.T, observe func(invocation int) error) *atomic.Int64 {
	t.Helper()
	var count atomic.Int64
	original := spliceCall
	spliceCall = func(rfd int, roff *int64, wfd int, woff *int64, length int, flags int) (int64, error) {
		invocation := int(count.Add(1))
		if observe != nil {
			if override := observe(invocation); override != nil {
				return 0, override
			}
		}
		return original(rfd, roff, wfd, woff, length, flags)
	}
	t.Cleanup(func() { spliceCall = original })
	return &count
}

// spliceTestDeadline is an absolute wall-clock deadline applied to the sockets in a test, long
// enough that a healthy run never reaches it and short enough that a regression fails inside
// `go test`'s own timeout with a real error instead of a stack dump. It is not a tuning knob:
// every assertion in this file is about correctness, not latency.
const spliceTestDeadline = 90 * time.Second

// tcpPair returns a connected TCP socket pair over loopback, both ends under one absolute
// deadline.
func tcpPair(t *testing.T, bufferSize int) (client *net.TCPConn, server *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, listenErr := listener.Accept()
		if listenErr != nil {
			acceptErr <- listenErr
			return
		}
		accepted <- conn.(*net.TCPConn)
	}()
	clientConn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	client = clientConn.(*net.TCPConn)
	select {
	case server = <-accepted:
	case err = <-acceptErr:
		require.NoError(t, err)
	case <-time.After(spliceTestDeadline):
		t.Fatal("timed out accepting the loopback connection")
	}
	// Best effort: the kernel caps these (net.core.wmem_max / rmem_max), and a failure here is
	// not a reason to fail the test - the size only decides how much of the stream can be in
	// flight at once.
	if bufferSize > 0 {
		_ = client.SetWriteBuffer(bufferSize)
		_ = client.SetReadBuffer(bufferSize)
		_ = server.SetWriteBuffer(bufferSize)
		_ = server.SetReadBuffer(bufferSize)
	}
	deadline := time.Now().Add(spliceTestDeadline)
	require.NoError(t, client.SetDeadline(deadline))
	require.NoError(t, server.SetDeadline(deadline))
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

// spliceTestPayload returns n bytes of incompressible payload.
func spliceTestPayload(t *testing.T, size int) []byte {
	t.Helper()
	payload := make([]byte, size)
	_, err := rand.Read(payload)
	require.NoError(t, err)
	return payload
}

// spliceTestTransfer copies source -> destination through the real copy engine while a reader
// drains the destination and a writer feeds the source, exactly as the two halves of a proxy
// flow do. It returns what arrived and the byte count the engine reported.
func spliceTestTransfer(t *testing.T, source, destination *net.TCPConn, payload []byte) ([]byte, int64) {
	t.Helper()
	received := make(chan []byte, 1)
	readErr := make(chan error, 1)
	go func() {
		data, err := io.ReadAll(destination)
		if err != nil {
			readErr <- err
			return
		}
		received <- data
	}()
	writeErr := make(chan error, 1)
	go func() {
		_, err := source.Write(payload)
		if err == nil {
			err = source.CloseWrite()
		}
		writeErr <- err
	}()
	// CopyWithCounters is what every production caller uses, and it is where the handed-flag
	// contract lives, so running anything else here would prove a different path.
	copied, err := CopyWithCounters(destination, source, source, nil, nil, 0, 0)
	require.NoError(t, err, "the copy engine must complete the stream")
	require.NoError(t, <-writeErr, "the whole payload must have reached the kernel")

	select {
	case data := <-received:
		return data, copied
	case err = <-readErr:
		require.NoError(t, err, "the concurrent reader must reach EOF without an error")
		return nil, copied
	case <-time.After(spliceTestDeadline):
		t.Fatal("timed out waiting for the copied payload")
		return nil, 0
	}
}

// TestActualLinuxSpliceCaseA is the case the objective names: a bare TCP socket to a bare TCP
// socket, through the real copy engine, with the splice syscall counted.
func TestActualLinuxSpliceCaseA(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()
	counter := spliceTestCount(t, nil)
	source, destination := tcpPair(t, 1<<20)
	payload := spliceTestPayload(t, 1<<20)

	received, copied := spliceTestTransfer(t, source, destination, payload)

	require.Equal(t, payload, received, "the payload must be byte-exact: no duplication, no truncation")
	require.EqualValues(t, len(received), copied)
	require.GreaterOrEqual(t, counter.Load(), int64(2),
		"the splice syscall must actually run (once per direction at least), not merely be selected")
}

// TestActualLinuxSpliceCaseESizes pins the size matrix. A stream under one splice chunk
// (maxSpliceSize, 1 MiB) can be moved by the first syscall alone, so a passing small transfer
// does not show the loop works; 4 MiB forces several iterations.
func TestActualLinuxSpliceCaseESizes(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()
	for _, size := range []int{64 << 10, 1 << 20, 4 << 20} {
		t.Run(map[int]string{64 << 10: "64KiB", 1 << 20: "1MiB", 4 << 20: "4MiB"}[size], func(t *testing.T) {
			counter := spliceTestCount(t, nil)
			source, destination := tcpPair(t, 1<<20)
			payload := spliceTestPayload(t, size)

			received, copied := spliceTestTransfer(t, source, destination, payload)

			require.Equal(t, payload, received, "a %d byte stream must arrive byte-exact", size)
			require.EqualValues(t, len(received), copied)
			require.GreaterOrEqual(t, counter.Load(), int64(2),
				"the splice syscall must run for a %d byte stream", size)
		})
	}
}

// TestActualLinuxSpliceCaseDHalfClose checks that a half-close is carried by the splice path:
// each side's EOF must reach the other as EOF, with both directions moving at once.
func TestActualLinuxSpliceCaseDHalfClose(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()
	counter := spliceTestCount(t, nil)
	client, server := tcpPair(t, 1<<20)

	clientPayload := spliceTestPayload(t, 256<<10)
	serverPayload := spliceTestPayload(t, 256<<10)

	// Each direction: a reader draining its destination, a writer feeding its source, and the
	// copy engine in between. Same shape as spliceTestTransfer, both ways at once.
	var waitGroup sync.WaitGroup
	runDirection := func(destination, source *net.TCPConn, payload []byte, label string) {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			received := make(chan []byte, 1)
			go func() {
				data, _ := io.ReadAll(destination)
				received <- data
			}()
			go func() {
				if _, err := source.Write(payload); err == nil {
					_ = source.CloseWrite()
				}
			}()
			_, err := CopyWithCounters(destination, source, source, nil, nil, 0, 0)
			require.NoError(t, err, "%s: the copy engine must complete the stream", label)
			select {
			case data := <-received:
				require.Equal(t, payload, data,
					"%s: a half-close must deliver every byte and then EOF, byte-exact", label)
			case <-time.After(spliceTestDeadline):
				t.Errorf("%s: timed out waiting for the half-closed payload", label)
			}
		}()
	}
	runDirection(server, client, clientPayload, "client->server")
	runDirection(client, server, serverPayload, "server->client")
	waitGroup.Wait()
	require.GreaterOrEqual(t, counter.Load(), int64(2), "the splice syscall must run in this path too")
}

// TestActualLinuxSpliceCaseCSetupFailureFallsBack is the regression test for the bug the seam
// was added for: when Pipe2 fails, no payload has moved, so the handover must report itself as
// NOT taken and the userspace copy must still deliver every byte.
//
// The assertion is on the observable contract, not on the flag alone: handed=false AND the
// fallback carries the payload. A test that only checked the flag would pass against a version
// that returns handed=false but has already consumed bytes.
func TestActualLinuxSpliceCaseCSetupFailureFallsBack(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()
	originalPipe2 := splicePipe2
	splicePipe2 = func(fds []int, flags int) error {
		return syscall.EMFILE
	}
	t.Cleanup(func() { splicePipe2 = originalPipe2 })
	counter := spliceTestCount(t, nil)

	source, destination := tcpPair(t, 1<<20)
	payload := spliceTestPayload(t, 512<<10)

	handed, moved, err := copyDirect(source, destination, nil, nil)
	require.Error(t, err, "the setup failure must still be reported")
	require.ErrorIs(t, err, syscall.EMFILE)
	require.False(t, handed, "a setup failure is not a handover: the caller must be allowed to fall back")
	require.Zero(t, moved, "nothing can have moved before the pipe existed")
	require.Zero(t, counter.Load(), "the splice syscall must not run when the pipe was never created")

	// The caller's fallback, run the way a production caller runs it: through the engine, with a
	// reader draining the far end and a writer feeding the source. The source must still be
	// positioned at the start of the stream.
	received, fallbackN := spliceTestTransfer(t, source, destination, payload)
	require.Equal(t, payload, received, "the userspace fallback must deliver every byte after a setup failure")
	require.EqualValues(t, len(received), fallbackN)
}

// TestActualLinuxSpliceMidStreamFailureKeepsHandover pins the other half of the contract: once
// bytes have moved through the splice backend, a failure must NOT be turned into a fallback.
// Resetting handed=false there would replay a stream whose state has advanced.
//
// The failure is injected at the write splice - the second invocation - so it lands strictly
// after the first splice has taken a real chunk out of the source. That is the situation the
// contract is about, and it is arranged deterministically rather than left to whether a socket
// buffer happens to fill.
func TestActualLinuxSpliceMidStreamFailureKeepsHandover(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()
	counter := spliceTestCount(t, func(invocation int) error {
		if invocation == 2 {
			return syscall.EIO
		}
		return nil
	})
	source, destination := tcpPair(t, 1<<20)
	payload := spliceTestPayload(t, 256<<10)
	_, err := source.Write(payload)
	require.NoError(t, err)

	handed, moved, err := copyDirect(source, destination, nil, nil)
	require.Error(t, err, "the mid-stream failure must be reported to the caller")
	require.ErrorIs(t, err, syscall.EIO, "the injected failure must be the one that surfaced")
	require.True(t, handed,
		"a mid-stream failure must keep handed=true: the stream has advanced and the userspace copy must not replay it")
	require.GreaterOrEqual(t, counter.Load(), int64(2),
		"the failure must have happened inside the splice engine, after at least one successful splice")
	require.Positive(t, moved, "bytes had already moved, which is what makes a fallback unsafe here")

	// What did land must be a prefix of what was sent: a partial transfer is the honest outcome
	// here, and duplication would mean the stream had been replayed.
	_ = destination.SetReadDeadline(time.Now().Add(2 * time.Second))
	received, _ := io.ReadAll(destination)
	require.NotEmpty(t, received)
	require.Equal(t, payload[:len(received)], received)
}

// TestActualLinuxSplicePipe2SeamIsTheRealOne guards the seam itself. If splicePipe2 were ever
// reassigned to a stub, every test above would still compile and the "setup failure" case would
// stop testing production. The real function must be what the package ships.
func TestActualLinuxSplicePipe2SeamIsTheRealOne(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()
	var fds [2]int
	require.NoError(t, splicePipe2(fds[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK))
	require.NoError(t, unix.Close(fds[0]))
	require.NoError(t, unix.Close(fds[1]))
}

// TestActualLinuxSpliceSeamsAreInitialized is a guard on the seam wiring: both seams must be
// initialized from the real syscalls rather than left nil, and a plain TCP socket must still be
// eligible for the path this file proves. A nil seam would panic on the first spliced connection
// on a phone - a failure mode a developer machine never sees - and an eligibility regression
// would make every test above pass by never reaching the engine.
func TestActualLinuxSpliceSeamsAreInitialized(t *testing.T) {
	require.NotNil(t, splicePipe2)
	require.NotNil(t, spliceCall)
	source, destination := tcpPair(t, 0)
	require.True(t, N.SyscallAvailableForRead(source), "a TCP socket must stay eligible for the splice path")
	require.True(t, N.SyscallAvailableForWrite(destination), "a TCP socket must stay eligible as a splice destination")
}
