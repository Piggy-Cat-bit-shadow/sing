package bufio

import (
	"syscall"

	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

const maxSpliceSize = 1 << 20

// splicePipe2 is the one syscall in the engine a test has to be able to make fail.
//
// It is a package-level function value initialized to the real unix.Pipe2 at package load, so
// production behaviour is unchanged: a nil hook is not a state the engine can be in, because the
// initializer below IS the real syscall. The cost is one indirect call per splice, not per byte.
//
// # Why only this one
//
// A Pipe2 failure used to be reported as a completed handover (handed was set before the pipe
// existed) and the regression test for that has to be able to fail Pipe2 on demand; there is no
// way to exhaust pipe descriptors reliably enough inside a unit test to reach the path any other
// way.
//
// The splice syscall itself is deliberately NOT behind a seam. "The splice backend was selected"
// and "the splice syscall ran" are different claims, and the second one is proved the way a
// kernel-level claim should be: by tracing the syscall on a Linux runner, not by routing
// production through a mutable function value that a test can replace. See
// .github/workflows/linux-splice-proof.yml.
var splicePipe2 = unix.Pipe2

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
		p0, p1 := unix.Splice(int(fd), nil, pipeFDs[1], nil, maxSpliceSize, unix.SPLICE_F_NONBLOCK)
		readN = int(p0)
		readErr = p1
		return readErr != unix.EAGAIN
	}
	writeFunc := func(fd uintptr) (done bool) {
		for writeSize > 0 {
			p0, p1 := unix.Splice(pipeFDs[0], nil, int(fd), nil, writeSize, unix.SPLICE_F_NONBLOCK|unix.SPLICE_F_MOVE)
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
					err = E.Cause(newErr, "splice read")
					return
				}
				// The hook consumed a non-application-data record. It may also have returned
				// application bytes that followed that record. Those bytes are in the pipe now,
				// so forward them to the destination before resuming the splice; returning here
				// would either panic on E.Cause(nil) or strand the bytes in the pipe.
				readN = 0
				for len(newBuffer) > 0 {
					written, writeErr := unix.Write(pipeFDs[1], newBuffer)
					if writeErr != nil {
						err = E.Cause(writeErr, "write handled data")
						return
					}
					if written == 0 {
						err = E.New("write handled data: short write")
						return
					}
					newBuffer = newBuffer[written:]
					readN += written
				}
				if readN > 0 {
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
				continue
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
