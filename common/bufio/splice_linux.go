package bufio

import (
	"syscall"

	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

const maxSpliceSize = 1 << 20

// The two syscalls the splice engine cannot be tested without sit behind package-level
// function values, initialized to the real ones at package load.
//
// # Why this is not a hot-path cost
//
// Each is called once per splice iteration - not per byte, not per packet - and a call
// through a function value is one indirect call in place of a direct one. There is no
// branch, no atomic and no logging here: a test that needs to observe a call swaps the
// variable out and counts in its own closure. A nil hook is not a state the engine can be
// in, because the initializers below ARE the real syscalls, so production behaves exactly
// as it did when the symbols were called directly.
//
// # What each seam exists to prove
//
// splicePipe2 exists because a Pipe2 failure used to be reported as a completed handover,
// and the regression test for that has to be able to make Pipe2 fail on demand. There is
// no way to exhaust pipe descriptors reliably enough inside a unit test to reach the path
// any other way.
//
// spliceCall exists because "the splice backend was selected" and "the splice syscall ran"
// are different claims, and only the second one is the thing being shipped. A test can
// count invocations and still call the real syscall: it observes, it does not replace.
var (
	splicePipe2 = unix.Pipe2
	spliceCall  = unix.Splice
)

func splice(source syscall.RawConn, sourceReader N.SyscallReader, destination syscall.RawConn, destinationWriter N.SyscallWriter, readCounters []N.CountFunc, writeCounters []N.CountFunc) (handed bool, n int64, err error) {
	// handed is set once the splice backend has been entered, and cleared again on any
	// failure that happens before a single payload byte has moved.
	//
	// The contract with the caller (bufio.CopyWithCounters) is: handed=true means "this
	// function owns the stream now, do not run the userspace copy"; handed=false means
	// "nothing was consumed, run your fallback". A setup failure that leaves handed true
	// is therefore not a small inaccuracy: the caller returns, the userspace copy never
	// runs, and a session that moved zero bytes is indistinguishable from a stall.
	var pipeFDs [2]int
	err = splicePipe2(pipeFDs[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK)
	if err != nil {
		// Setup failure. No payload has been read from the source and nothing has been
		// written anywhere, so the stream is exactly where the caller left it and the
		// userspace copy can take over from here. handed is left false for that reason.
		return false, 0, err
	}
	handed = true
	defer unix.Close(pipeFDs[0])
	defer unix.Close(pipeFDs[1])
	_, _ = unix.FcntlInt(uintptr(pipeFDs[0]), unix.F_SETPIPE_SZ, maxSpliceSize)
	var (
		readN        int
		readErr      error
		writeSize    int
		writeErr     error
		notFirstTime bool
	)
	readFunc := func(fd uintptr) (done bool) {
		p0, p1 := spliceCall(int(fd), nil, pipeFDs[1], nil, maxSpliceSize, unix.SPLICE_F_NONBLOCK)
		readN = int(p0)
		readErr = p1
		return readErr != unix.EAGAIN
	}
	writeFunc := func(fd uintptr) (done bool) {
		for writeSize > 0 {
			p0, p1 := spliceCall(pipeFDs[0], nil, int(fd), nil, writeSize, unix.SPLICE_F_NONBLOCK|unix.SPLICE_F_MOVE)
			writeN := int(p0)
			writeErr = p1
			if writeErr != nil {
				return writeErr != unix.EAGAIN
			}
			writeSize -= writeN
		}
		return true
	}
	for {
		err = source.Read(readFunc)
		if readErr != nil {
			err = readErr
		}
		if err != nil {
			if sourceReader != nil {
				newBuffer, newErr := sourceReader.HandleSyscallReadError(err)
				if newErr != nil {
					err = newErr
				} else {
					err = nil
					if len(newBuffer) > 0 {
						readN, readErr = unix.Write(pipeFDs[1], newBuffer)
						if readErr != nil {
							err = E.Cause(err, "write handled data")
						}
					}
				}
			} else if !notFirstTime && E.IsMulti(err, unix.EINVAL, unix.ENOSYS) {
				handed = false
				return
			}
			err = E.Cause(err, "splice read")
			return
		}
		if readN == 0 {
			return
		}
		for _, readCounter := range readCounters {
			readCounter(int64(readN))
		}
		writeSize = readN
		err = destination.Write(writeFunc)
		if writeErr != nil {
			err = writeErr
		}
		written := int64(readN - writeSize)
		if written > 0 {
			n += written
			for _, writeCounter := range writeCounters {
				writeCounter(written)
			}
		}
		if err != nil {
			err = E.Cause(err, "splice write")
			return
		}
		notFirstTime = true
	}
}
