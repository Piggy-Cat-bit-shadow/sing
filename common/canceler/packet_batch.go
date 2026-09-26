package canceler

import (
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Connected packet batch forwarding through the timeout wrappers.
//
// # The gap this closes
//
// Both wrappers implemented ReadPacket/WritePacket and the single-packet read waiter,
// but neither forwarded the CONNECTED BATCH capabilities. A connection that offered
// them therefore lost them the moment it was wrapped:
//
//	conn with batch  ->  canceler.NewPacketConn  ->  batch invisible  ->  one packet at a time
//
// The connection kept working, so nothing failed; the batching was simply unreachable.
// That matters for the same reason it is easy to miss: the wrapper is applied on the
// ordinary data path (an idle-timeout wrapper around every UDP session), so a tunnel
// that implemented batching never got to use it in production.
//
// # Why the wrappers cannot simply expose the inner waiter
//
// Both wrappers refresh their activity state when I/O succeeds, and that accounting is
// the only thing standing between an idle tunnel and a leak. Handing the inner waiter
// straight back would make batching work while silently BYPASSING it: a batch would
// arrive with no activity recorded, and an actively-used session would be torn down as
// idle. So each capability is re-wrapped, and the wrapper records activity once per
// BATCH.
//
// # Why once per batch and not once per packet
//
// Updating per packet would mean walking the batch and touching the timer N times, which
// reintroduces exactly the per-packet cost that batching exists to remove. A batch is one
// unit of I/O as far as the session is concerned, so it counts once.
//
// Ownership is deliberately NOT touched. The underlying readers and writers already
// define whether they consume the buffers they are handed, and those contracts differ
// between implementations, so the wrappers pass the slices through unchanged and add
// nothing of their own. See the note on each method.

// ---------------------------------------------------------------------------
// TimerPacketConn
// ---------------------------------------------------------------------------

// CreateConnectedPacketBatchReadWaiter forwards the connected batch read capability.
//
// The wrapper asks the inner connection through the same bufio entry point the copy path
// uses, so every route to a batch reader - a creator, a direct implementation, or a
// syscall-level reader - keeps working. It reports false when the inner connection has
// none, which is what stops a batch-less protocol from being handed an empty promise.
func (c *TimerPacketConn) CreateConnectedPacketBatchReadWaiter() (N.ConnectedPacketBatchReadWaiter, bool) {
	readWaiter, isReadWaiter := bufio.CreateConnectedPacketBatchReadWaiter(c.PacketConn)
	if !isReadWaiter {
		return nil, false
	}
	return &timerConnectedPacketReadWaiter{c, readWaiter}, true
}

type timerConnectedPacketReadWaiter struct {
	*TimerPacketConn
	readWaiter N.ConnectedPacketBatchReadWaiter
}

// InitializeReadWaiter forwards the caller's options verbatim and returns the inner
// needCopy unchanged.
//
// Forwarding rather than re-deriving is the point: FrontHeadroom, RearHeadroom, MTU,
// ReadOverhead and BatchSize all describe how the READER should prepare buffers, and
// this wrapper does not read anything itself. Returning a different needCopy would make
// the copy path allocate and copy a payload that the inner reader was prepared to hand
// over directly, and changing BatchSize would silently retune the tunnel.
func (w *timerConnectedPacketReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	return w.readWaiter.InitializeReadWaiter(options)
}

// WaitReadConnectedPackets refreshes the activity timer on a successful batch.
//
// The refresh is keyed on the CALL SUCCEEDING, not on the batch being non-empty in
// bytes: a batch of zero-length UDP datagrams is ordinary traffic (RFC 9298 carries
// them) and would otherwise look like an idle session and be torn down. The underlying
// contract is that a nil error means at least one packet was returned, so no byte-level
// check is needed or wanted.
//
// A failure does NOT refresh: EOF, a timeout, a closed connection and a transport error
// all mean no activity happened, and counting them would keep a dead session alive.
// The error is returned to the caller unchanged.
func (w *timerConnectedPacketReadWaiter) WaitReadConnectedPackets() ([]*buf.Buffer, M.Socksaddr, error) {
	buffers, destination, err := w.readWaiter.WaitReadConnectedPackets()
	if err == nil {
		w.instance.Update()
	}
	return buffers, destination, err
}

// CreateConnectedPacketBatchWriter forwards the connected batch write capability.
func (c *TimerPacketConn) CreateConnectedPacketBatchWriter() (N.ConnectedPacketBatchWriter, bool) {
	batchWriter, isBatchWriter := bufio.CreateConnectedPacketBatchWriter(c.PacketConn)
	if !isBatchWriter {
		return nil, false
	}
	return &timerConnectedPacketBatchWriter{c, batchWriter}, true
}

type timerConnectedPacketBatchWriter struct {
	*TimerPacketConn
	batchWriter N.ConnectedPacketBatchWriter
}

// WriteConnectedPacketBatch refreshes the activity timer once for the whole batch.
//
// Once, not once per buffer: the batch is one write as far as the session is concerned,
// and iterating to update per packet would add back the per-packet work batching
// removes.
//
// Buffer ownership is left entirely to the inner writer. Some implementations release
// every buffer they are handed (on success AND on failure) and some release only what
// they consumed, so this wrapper must not release anything itself - doing so would
// double-release under the first contract and leak under the second. Passing the slice
// through unchanged is the only behaviour that is correct under both.
func (w *timerConnectedPacketBatchWriter) WriteConnectedPacketBatch(buffers []*buf.Buffer) error {
	err := w.batchWriter.WriteConnectedPacketBatch(buffers)
	if err == nil {
		w.instance.Update()
	}
	return err
}

// ---------------------------------------------------------------------------
// TimeoutPacketConn
// ---------------------------------------------------------------------------

// CreateConnectedPacketBatchReadWaiter forwards the connected batch read capability for
// the deadline-based wrapper.
//
// It is a separate implementation from the timer one rather than shared code, because
// the two wrappers enforce their timeout in completely different ways: the timer wrapper
// refreshes a running timer, while this one re-arms a socket deadline and then decides
// from elapsed time whether the session is genuinely idle.
func (c *TimeoutPacketConn) CreateConnectedPacketBatchReadWaiter() (N.ConnectedPacketBatchReadWaiter, bool) {
	readWaiter, isReadWaiter := bufio.CreateConnectedPacketBatchReadWaiter(c.PacketConn)
	if !isReadWaiter {
		return nil, false
	}
	return &timeoutConnectedPacketReadWaiter{c, readWaiter}, true
}

type timeoutConnectedPacketReadWaiter struct {
	*TimeoutPacketConn
	readWaiter N.ConnectedPacketBatchReadWaiter
}

func (w *timeoutConnectedPacketReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	return w.readWaiter.InitializeReadWaiter(options)
}

// WaitReadConnectedPackets applies the deadline-and-liveness loop to a whole batch.
//
// The loop mirrors the single-packet waiter exactly, because the semantics being
// preserved are the same ones:
//
//   - re-arm the read deadline from the CURRENT timeout, so a SetTimeout issued after
//     this waiter was created takes effect on the next read;
//   - block for a batch;
//   - on success, record activity and return;
//   - on a timeout, ask whether any activity happened recently. If it did, the session
//     is merely idle at this instant and the read is retried with a fresh deadline; if
//     it did not, the session really is idle and is cancelled;
//   - on anything else, return the error unchanged.
//
// A batch that returns successfully counts as ONE activity update, so an active tunnel
// stays alive without paying per-packet timer work.
//
// Buffers on the error path are NOT released here. The inner waiter either returns
// buffers with a nil error or returns none, so there is nothing for this wrapper to
// clean up; releasing defensively would double-release whatever a partial implementation
// chose to return.
func (w *timeoutConnectedPacketReadWaiter) WaitReadConnectedPackets() ([]*buf.Buffer, M.Socksaddr, error) {
	for {
		err := w.setReadDeadline()
		if err != nil {
			return nil, M.Socksaddr{}, err
		}
		buffers, destination, err := w.readWaiter.WaitReadConnectedPackets()
		if err == nil {
			w.updateActive()
			return buffers, destination, nil
		} else if E.IsTimeout(err) {
			if w.isInactive() {
				w.cancel(err)
				return nil, M.Socksaddr{}, err
			}
		} else {
			return nil, M.Socksaddr{}, err
		}
	}
}

// CreateConnectedPacketBatchWriter forwards the connected batch write capability.
func (c *TimeoutPacketConn) CreateConnectedPacketBatchWriter() (N.ConnectedPacketBatchWriter, bool) {
	batchWriter, isBatchWriter := bufio.CreateConnectedPacketBatchWriter(c.PacketConn)
	if !isBatchWriter {
		return nil, false
	}
	return &timeoutConnectedPacketBatchWriter{c, batchWriter}, true
}

type timeoutConnectedPacketBatchWriter struct {
	*TimeoutPacketConn
	batchWriter N.ConnectedPacketBatchWriter
}

// WriteConnectedPacketBatch records one activity update for the batch and returns the
// inner error unchanged.
//
// Buffer ownership is the inner writer's, for the same reason as the timer variant: the
// release contract differs between implementations, so this wrapper releases nothing.
func (w *timeoutConnectedPacketBatchWriter) WriteConnectedPacketBatch(buffers []*buf.Buffer) error {
	err := w.batchWriter.WriteConnectedPacketBatch(buffers)
	if err == nil {
		w.updateActive()
	}
	return err
}
