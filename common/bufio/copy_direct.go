package bufio

import (
	"errors"
	"io"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func copyDirect(source io.Reader, destination io.Writer, readCounters []N.CountFunc, writeCounters []N.CountFunc) (handed bool, n int64, err error) {
	if !N.SyscallAvailableForRead(source) || !N.SyscallAvailableForWrite(destination) {
		return
	}
	sourceReader, sourceConn := N.SyscallConnForRead(source)
	destinationWriter, destinationConn := N.SyscallConnForWrite(destination)
	if sourceConn == nil || destinationConn == nil {
		return
	}
	handed, n, err = splice(sourceConn, sourceReader, destinationConn, destinationWriter, readCounters, writeCounters)
	return
}

func copyWaitWithPool(session *CopySession, destination N.ExtendedWriter, source N.ExtendedReader, readWaiter N.ReadWaiter, options N.ReadWaitOptions) (handled bool, n int64, err error) {
	handled = true
	var (
		buffer       *buf.Buffer
		notFirstTime bool
	)
	for {
		buffer, err = readWaiter.WaitReadBuffer()
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = nil
				return
			}
			return
		}
		dataLen := buffer.Len()
		err = destination.WriteBuffer(buffer)
		if err != nil {
			buffer.Leak()
			if !notFirstTime {
				err = N.ReportHandshakeFailure(session.originSource, err)
			}
			return
		}
		n += int64(dataLen)
		if err = session.Transfer(int64(dataLen)); err != nil {
			return
		}
		notFirstTime = true
		if !options.IncreaseBuffer && session.options.IncreaseBufferAfter > 0 && n >= session.options.IncreaseBufferAfter {
			options.IncreaseBuffer = true
			vectorisedReadWaiter, isVectorisedReadWaiter := CreateVectorisedReadWaiter(source)
			vectorisedWriter, isVectorisedWriter := CreateVectorisedWriter(destination)
			if !isVectorisedReadWaiter || !isVectorisedWriter {
				readWaiter.InitializeReadWaiter(options)
				continue
			} else {
				vectorisedReadWaiter.InitializeReadWaiter(options)
			}
			n, err = copyWaitVectorisedWithPool(session, vectorisedWriter, vectorisedReadWaiter, n)
			return
		}
	}
}

func copyWaitVectorisedWithPool(session *CopySession, vectorisedWriter N.VectorisedWriter, readWaiter N.VectorisedReadWaiter, inputN int64) (n int64, err error) {
	n += inputN
	var buffers []*buf.Buffer
	for {
		buffers, err = readWaiter.WaitReadBuffers()
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = nil
				return
			}
			return
		}
		var dataLen int
		for _, buffer := range buffers {
			dataLen += buffer.Len()
		}
		err = vectorisedWriter.WriteVectorised(buffers)
		if err != nil {
			for _, buffer := range buffers {
				buffer.Leak()
			}
			return
		}
		n += int64(dataLen)
		if err = session.Transfer(int64(dataLen)); err != nil {
			return
		}
	}
}

func copyPacketWaitWithPool(session *packetCopySession, destinationConn N.PacketWriter, source N.PacketReadWaiter, notFirstTime bool) (handled bool, n int64, err error) {
	handled = true
	var (
		buffer      *buf.Buffer
		destination M.Socksaddr
	)
	for {
		buffer, destination, err = source.WaitReadPacket()
		if err != nil {
			return
		}
		dataLen := buffer.Len()
		err = destinationConn.WritePacket(buffer, destination)
		if err != nil {
			buffer.Leak()
			if !notFirstTime {
				handshakeErr := N.ReportHandshakeFailure(session.originSource, err)
				if handshakeErr != nil {
					err = handshakeErr
				}
			}
			return
		}
		n += int64(dataLen)
		if err = session.Transfer(int64(dataLen)); err != nil {
			return
		}
		notFirstTime = true
	}
}

// batchScratch provides the per-batch scratch arrays the packet batch copy loops
// need, without a heap allocation in the common case.
//
// # Why this exists
//
// Every batch copy iteration previously allocated its own slice:
//
//	dataLens := make([]int, len(buffers))
//
// With DefaultPacketReadBatchSize at 64 and a batch per iteration, that is one
// allocation per batch on the hottest UDP path in the process - the one that carries
// game, VoIP and QUIC traffic. The arrays are pure scratch: they are filled, read once,
// and never leave the iteration.
//
// # Why a stack array is safe here
//
// The returned slices do not escape beyond the copy loop. The caller fills them, passes
// them to WritePacketBatch / TransferBatch, and the iteration ends. Neither callee
// retains the slice: TransferBatch only iterates it, and the batch writers only read it
// for the duration of the syscall. So the arrays need only outlive the loop, which a
// function-local value does - and escape analysis confirms it stays on the stack.
//
// The scratch is declared ONCE per copy loop, not inside the batch loop. The struct is
// ~4.8 KiB; allocating it per iteration would cost more than the small slices it
// replaces. Each copy loop runs on a single goroutine for its session, so a
// function-local scratch is not shared and needs no synchronisation.
//
// # The fallback
//
// Batch size is a read-wait option, not a constant: a caller may ask for more than
// DefaultPacketReadBatchSize. Taking the stack array as a fixed ceiling and indexing
// past it would be a buffer overrun, so an oversized batch falls back to the heap. The
// fast path is the one that matters; correctness is kept for the rest.
type batchScratch struct {
	lensInt   [DefaultPacketReadBatchSize]int
	lensInt64 [DefaultPacketReadBatchSize]int64
	dest      [DefaultPacketReadBatchSize]M.Socksaddr
}

// ints returns a length-n int slice backed by the scratch when it fits, else a fresh one.
func (s *batchScratch) ints(n int) []int {
	if n <= len(s.lensInt) {
		return s.lensInt[:n]
	}
	return make([]int, n)
}

// int64s returns a length-n int64 slice backed by the scratch when it fits, else a fresh one.
func (s *batchScratch) int64s(n int) []int64 {
	if n <= len(s.lensInt64) {
		return s.lensInt64[:n]
	}
	return make([]int64, n)
}

// destinations returns a length-n Socksaddr slice backed by the scratch when it fits,
// else a fresh one.
func (s *batchScratch) destinations(n int) []M.Socksaddr {
	if n <= len(s.dest) {
		return s.dest[:n]
	}
	return make([]M.Socksaddr, n)
}

func copyPacketBatchWaitWithPool(session *packetCopySession, destinationConn N.PacketBatchWriter, source N.PacketBatchReadWaiter, notFirstTime bool) (handled bool, n int64, err error) {
	// Declared once per copy loop, NOT per batch. The struct is ~4.8 KiB, so
	// allocating it inside the loop would cost more than the small slices it
	// replaces. Each copy loop runs on one goroutine per session, so a function-local
	// scratch is not shared and needs no lock.
	var scratch batchScratch
	handled = true
	for {
		var (
			buffers      []*buf.Buffer
			destinations []M.Socksaddr
		)
		buffers, destinations, err = source.WaitReadPackets()
		if err != nil {
			return handled, n, err
		}
		dataLens := scratch.ints(len(buffers))
		for index, buffer := range buffers {
			dataLens[index] = buffer.Len()
		}
		err = destinationConn.WritePacketBatch(buffers, destinations)
		if err != nil {
			if !notFirstTime {
				handshakeErr := N.ReportHandshakeFailure(session.originSource, err)
				if handshakeErr != nil {
					err = handshakeErr
				}
			}
			return
		}
		for _, dataLen := range dataLens {
			n += int64(dataLen)
		}
		if err = session.TransferBatch(dataLens); err != nil {
			return
		}
		notFirstTime = true
	}
}

func copyPacketBatchToConnectedWaitWithPool(session *packetCopySession, destinationConn N.ConnectedPacketBatchWriter, source N.PacketBatchReadWaiter, notFirstTime bool) (handled bool, n int64, err error) {
	// Declared once per copy loop, NOT per batch. The struct is ~4.8 KiB, so
	// allocating it inside the loop would cost more than the small slices it
	// replaces. Each copy loop runs on one goroutine per session, so a function-local
	// scratch is not shared and needs no lock.
	var scratch batchScratch
	handled = true
	for {
		var buffers []*buf.Buffer
		buffers, _, err = source.WaitReadPackets()
		if err != nil {
			return handled, n, err
		}
		dataLens := scratch.ints(len(buffers))
		for index, buffer := range buffers {
			dataLens[index] = buffer.Len()
		}
		err = destinationConn.WriteConnectedPacketBatch(buffers)
		if err != nil {
			if !notFirstTime {
				handshakeErr := N.ReportHandshakeFailure(session.originSource, err)
				if handshakeErr != nil {
					err = handshakeErr
				}
			}
			return
		}
		for _, dataLen := range dataLens {
			n += int64(dataLen)
		}
		if err = session.TransferBatch(dataLens); err != nil {
			return
		}
		notFirstTime = true
	}
}

func copyConnectedPacketBatchWaitWithPool(session *packetCopySession, destinationConn N.PacketBatchWriter, source N.ConnectedPacketBatchReadWaiter, notFirstTime bool) (handled bool, n int64, err error) {
	// Declared once per copy loop, NOT per batch. The struct is ~4.8 KiB, so
	// allocating it inside the loop would cost more than the small slices it
	// replaces. Each copy loop runs on one goroutine per session, so a function-local
	// scratch is not shared and needs no lock.
	var scratch batchScratch
	handled = true
	for {
		var (
			buffers     []*buf.Buffer
			destination M.Socksaddr
		)
		buffers, destination, err = source.WaitReadConnectedPackets()
		if err != nil {
			return handled, n, err
		}
		destinations := scratch.destinations(len(buffers))
		dataLens := scratch.ints(len(buffers))
		for index, buffer := range buffers {
			destinations[index] = destination
			dataLens[index] = buffer.Len()
		}
		err = destinationConn.WritePacketBatch(buffers, destinations)
		if err != nil {
			if !notFirstTime {
				handshakeErr := N.ReportHandshakeFailure(session.originSource, err)
				if handshakeErr != nil {
					err = handshakeErr
				}
			}
			return
		}
		for _, dataLen := range dataLens {
			n += int64(dataLen)
		}
		if err = session.TransferBatch(dataLens); err != nil {
			return
		}
		notFirstTime = true
	}
}

func copyConnectedPacketBatchToConnectedWaitWithPool(session *packetCopySession, destinationConn N.ConnectedPacketBatchWriter, source N.ConnectedPacketBatchReadWaiter, notFirstTime bool) (handled bool, n int64, err error) {
	// Declared once per copy loop, NOT per batch. The struct is ~4.8 KiB, so
	// allocating it inside the loop would cost more than the small slices it
	// replaces. Each copy loop runs on one goroutine per session, so a function-local
	// scratch is not shared and needs no lock.
	var scratch batchScratch
	handled = true
	for {
		var buffers []*buf.Buffer
		buffers, _, err = source.WaitReadConnectedPackets()
		if err != nil {
			return handled, n, err
		}
		dataLens := scratch.ints(len(buffers))
		for index, buffer := range buffers {
			dataLens[index] = buffer.Len()
		}
		err = destinationConn.WriteConnectedPacketBatch(buffers)
		if err != nil {
			if !notFirstTime {
				handshakeErr := N.ReportHandshakeFailure(session.originSource, err)
				if handshakeErr != nil {
					err = handshakeErr
				}
			}
			return
		}
		for _, dataLen := range dataLens {
			n += int64(dataLen)
		}
		if err = session.TransferBatch(dataLens); err != nil {
			return
		}
		notFirstTime = true
	}
}
