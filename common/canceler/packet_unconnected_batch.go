package canceler

import (
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Unconnected packet batch forwarding through the timeout wrappers.
//
// # The gap this closes
//
// packet_batch.go forwards the CONNECTED batch capabilities. Those are what a tunnel that
// hands every datagram to one fixed peer asks for. They are not what a NAT session asks for:
// a NAT session writes each datagram to its own destination, so the copy engine reaches for
// `N.CreatePacketBatchWriter` / `N.CreatePacketBatchReadWaiter` - the unconnected pair - and
// neither wrapper implemented them. The wrapper is installed on every UDP session with a
// timeout, which is every UDP NAT session, so:
//
//	conn with batch  ->  canceler.NewPacketConn  ->  batch invisible  ->  one syscall per datagram
//
// Nothing failed, which is why this survived: the datagrams still arrive, they just each cost
// their own syscall on the hottest UDP path in the process.
//
// # Why the wrapper cannot hand the inner capability straight back
//
// The same reason packet_batch.go gives for the connected half, and it is not a style
// preference: both wrappers refresh their activity state when I/O succeeds, and that accounting
// is what stops an actively-used session from being torn down as idle. Returning the inner
// capability unchanged would make batching work while silently bypassing the refresh: a batch
// would arrive with no activity recorded. So each capability is re-wrapped and records activity
// once per BATCH - once, not once per packet, or the per-packet work batching removes comes
// straight back.
//
// # Why the wrapper does not advertise replaceability
//
// `bufio.CreatePacketBatchWriter` unwraps a replaceable writer to find a capability behind it.
// If these wrappers advertised that, the copy engine would reach the inner writer directly and
// the activity refresh would be gone - the failure above. They deliberately expose the
// capability as a wrapped creator instead, which is the same choice packet_batch.go makes.
//
// Ownership is untouched for the reason packet_batch.go states: inner implementations differ on
// whether they release the buffers they are handed, so the wrappers pass the slices through and
// release nothing themselves.

// ---------------------------------------------------------------------------
// TimerPacketConn
// ---------------------------------------------------------------------------

// CreatePacketBatchReadWaiter forwards the unconnected batch read capability.
func (c *TimerPacketConn) CreatePacketBatchReadWaiter() (N.PacketBatchReadWaiter, bool) {
	readWaiter, isReadWaiter := bufio.CreatePacketBatchReadWaiter(c.PacketConn)
	if !isReadWaiter {
		return nil, false
	}
	return &timerPacketBatchReadWaiter{c, readWaiter}, true
}

type timerPacketBatchReadWaiter struct {
	*TimerPacketConn
	readWaiter N.PacketBatchReadWaiter
}

// InitializeReadWaiter forwards the caller's options verbatim and returns the inner needCopy
// unchanged: this wrapper reads nothing itself, so re-deriving the geometry here could only
// make the copy path allocate a payload the inner reader was prepared to hand over.
func (w *timerPacketBatchReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	return w.readWaiter.InitializeReadWaiter(options)
}

// WaitReadPackets refreshes the activity timer once on a successful batch. A failure does not
// refresh - EOF, a timeout, a closed connection and a transport error all mean no activity
// happened - and the error is returned unchanged.
func (w *timerPacketBatchReadWaiter) WaitReadPackets() (buffers []*buf.Buffer, destinations []M.Socksaddr, err error) {
	buffers, destinations, err = w.readWaiter.WaitReadPackets()
	if err == nil {
		w.instance.Update()
	}
	return
}

// CreatePacketBatchWriter forwards the unconnected batch write capability.
func (c *TimerPacketConn) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	batchWriter, isBatchWriter := bufio.CreatePacketBatchWriter(c.PacketConn)
	if !isBatchWriter {
		return nil, false
	}
	return &timerPacketBatchWriter{c, batchWriter}, true
}

type timerPacketBatchWriter struct {
	*TimerPacketConn
	batchWriter N.PacketBatchWriter
}

// WritePacketBatch refreshes the activity timer once for the whole batch.
func (w *timerPacketBatchWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	err := w.batchWriter.WritePacketBatch(buffers, destinations)
	if err == nil {
		w.instance.Update()
	}
	return err
}

// ---------------------------------------------------------------------------
// TimeoutPacketConn
// ---------------------------------------------------------------------------

// CreatePacketBatchReadWaiter forwards the unconnected batch read capability for the
// deadline-based wrapper. It is a separate implementation rather than shared code because the
// two wrappers enforce their timeout differently, exactly as packet_batch.go explains for the
// connected pair.
func (c *TimeoutPacketConn) CreatePacketBatchReadWaiter() (N.PacketBatchReadWaiter, bool) {
	readWaiter, isReadWaiter := bufio.CreatePacketBatchReadWaiter(c.PacketConn)
	if !isReadWaiter {
		return nil, false
	}
	return &timeoutPacketBatchReadWaiter{c, readWaiter}, true
}

type timeoutPacketBatchReadWaiter struct {
	*TimeoutPacketConn
	readWaiter N.PacketBatchReadWaiter
}

func (w *timeoutPacketBatchReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	return w.readWaiter.InitializeReadWaiter(options)
}

// WaitReadPackets applies the deadline-and-liveness loop to a whole batch, mirroring the
// single-packet waiter:
//
//   - re-arm the read deadline from the CURRENT timeout, so a SetTimeout issued after this
//     waiter was created takes effect on the next read;
//   - block for a batch;
//   - on success, record activity and return;
//   - on a timeout, ask whether any activity happened recently: if it did, the session is
//     merely idle at this instant and the read is retried with a fresh deadline; if it did not,
//     the session really is idle and is cancelled;
//   - on anything else, return the error unchanged.
func (w *timeoutPacketBatchReadWaiter) WaitReadPackets() (buffers []*buf.Buffer, destinations []M.Socksaddr, err error) {
	for {
		err = w.setReadDeadline()
		if err != nil {
			return nil, nil, err
		}
		buffers, destinations, err = w.readWaiter.WaitReadPackets()
		if err == nil {
			w.updateActive()
			return buffers, destinations, nil
		} else if E.IsTimeout(err) {
			if w.isInactive() {
				w.cancel(err)
				return nil, nil, err
			}
		} else {
			return nil, nil, err
		}
	}
}

// CreatePacketBatchWriter forwards the unconnected batch write capability.
func (c *TimeoutPacketConn) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	batchWriter, isBatchWriter := bufio.CreatePacketBatchWriter(c.PacketConn)
	if !isBatchWriter {
		return nil, false
	}
	return &timeoutPacketBatchWriter{c, batchWriter}, true
}

type timeoutPacketBatchWriter struct {
	*TimeoutPacketConn
	batchWriter N.PacketBatchWriter
}

// WritePacketBatch records one activity update for the batch and returns the inner error
// unchanged. Buffer ownership is the inner writer's.
func (w *timeoutPacketBatchWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	err := w.batchWriter.WritePacketBatch(buffers, destinations)
	if err == nil {
		w.updateActive()
	}
	return err
}
