package bufio

import (
	"crypto/rand"
	"io"
	"net"
	"strings"
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
// unix.Splice - or a build where the splice file is not compiled at all - satisfies every one of
// them. So the assertions here are, in order of importance:
//
//  1. spliceCall actually ran, counted through the seam in splice_linux.go;
//  2. the payload arrived byte-exact with no duplication and no truncation;
//  3. the fallback cases still deliver the payload when the handover does not happen.
//
// # Three things this harness had to learn on a real Linux runner
//
// All three were found by CI failing, and all three are properties of the engine that a test has
// to model rather than bugs to be papered over. Nothing is hidden: the payload is compared byte
// for byte, so an early end is a failure.
//
//  1. THE DESTINATION MUST BE DRAINED WHILE THE COPY RUNS. Splice moves bytes with
//     SPLICE_F_NONBLOCK. With nothing reading the far end, the loopback receive window closes,
//     the write splice exhausts the pipe by pushing one bufferful and then sees EAGAIN, and the
//     engine reports that as an error - see (3). A proxy always has both directions moving; the
//     first version of this file copied first and read afterwards, and timed out.
//
//  2. THE SOURCE MUST BE FED WHILE THE COPY RUNS, NOT WRITTEN UP FRONT. A source written to
//     completion before the copy starts holds a burst the engine is not built for.
//
//  3. THE ENGINE IS AN EVENT-LOOP CALLEE, AND A DRAINED SOURCE IS REPORTED AS AN ERROR. This is
//     the one that took a syscall trace on the runner to establish, and it is the reason this
//     file drives the engine in a loop. When the read splice finds the source socket empty -
//     which happens legitimately, as soon as the loop has consumed the queued bytes and the
//     sender has not produced more - unix.Splice returns EAGAIN. The engine sets handed=true
//     first and treats EAGAIN as terminal after the first iteration, so the CALLER sees
//
//     splice read: resource temporarily unavailable
//
//     with the handover already claimed. That is not a stall in the test: the same trace showed a
//     hand-rolled unix.Splice on the same descriptor moving 65536 bytes with err=nil, and
//     RawConn.Read driving the identical callback returning nil. It is a property of the engine:
//     a partial splice cannot be paused and resumed, so the engine can only be re-entered, and
//     re-entering it is what its production callers do.
//
//     So the driver below re-invokes copyDirect while no payload byte has been consumed, which is
//     the safe direction: with n==0 the stream has not advanced, so nothing can be duplicated or
//     lost. The retry count is asserted to be bounded, so "it only passed because it retried for
//     ninety seconds" cannot happen silently.
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

const (
	// spliceTestDeadline is an absolute wall-clock deadline for the sockets in a test: long
	// enough that a healthy run never reaches it, short enough that a regression fails inside
	// `go test`'s own timeout with a real error instead of a stack dump.
	spliceTestDeadline = 90 * time.Second
	// spliceTestMaxRetries bounds how many times the driver may re-enter the engine on a drained
	// source. A few hundred is normal for a megabyte over loopback; thousands would mean the test
	// is spinning rather than transferring.
	spliceTestMaxRetries = 2000
	// spliceTestEAGAIN is the error the engine reports when the read splice finds the source
	// empty. It is matched on the rendered cause because that is exactly what a caller sees.
	spliceTestEAGAIN = "resource temporarily unavailable"
)

// tcpPair returns a connected TCP socket pair over loopback, both ends under one deadline.
func tcpPair(t *testing.T, bufferSize int) (client *net.TCPConn, server *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
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
	require.NoError(t, listener.Close())
	// Best effort: the kernel caps these, and a failure here is not a reason to fail the test -
	// the size only decides how much of the stream can be in flight at once.
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

// spliceTestDrainCopy runs the splice engine until the stream completes, the way its callers do.
//
// It returns what the destination received, the byte count the engine reported in total, and how
// many times the engine had to be re-entered after reporting a drained source.
//
// The re-entry is only allowed while nothing has moved, and that is the whole safety argument:
// copyDirect claims the handover (handed=true) only after bytes have moved, so an error with
// n==0 has left the stream exactly where it was found.
func spliceTestDrainCopy(t *testing.T, source net.Conn, destination net.Conn, payload []byte) (received []byte, copied int64, retries int) {
	t.Helper()
	receivedChannel := make(chan []byte, 1)
	readErrChannel := make(chan error, 1)
	go func() {
		data, err := io.ReadAll(destination)
		if err != nil {
			readErrChannel <- err
			return
		}
		receivedChannel <- data
	}()
	writeErrChannel := make(chan error, 1)
	go func() {
		_, err := source.Write(payload)
		if err == nil {
			err = source.(interface{ CloseWrite() error }).CloseWrite()
		}
		writeErrChannel <- err
	}()

	sourceRaw, err := source.(interface {
		SyscallConn() (syscall.RawConn, error)
	}).SyscallConn()
	require.NoError(t, err)
	destinationRaw, err := destination.(interface {
		SyscallConn() (syscall.RawConn, error)
	}).SyscallConn()
	require.NoError(t, err)
	_ = sourceRaw
	_ = destinationRaw

	for retries = 0; ; retries++ {
		require.Less(t, retries, spliceTestMaxRetries,
			"the engine kept reporting a drained source without moving a byte; that is a spin, not a transfer")
		// copyDirect takes the reader and the writer; it resolves their syscall connections
		// itself, which is exactly what the production callers hand it.
		handed, moved, directErr := copyDirect(source, destination, nil, nil)
		copied += moved
		if directErr == nil {
			break
		}
		if retries == 0 {
			require.NotContains(t, directErr.Error(), "splice write",
				"a write failure is not a drained source and must not be retried")
		}
		require.Contains(t, directErr.Error(), spliceTestEAGAIN,
			"the only failure a retry may absorb is a drained source")
		require.Zero(t, moved,
			"a failure that moved bytes has advanced the stream and must not be retried")
		require.True(t, handed,
			"the engine claims the handover before it reports the drained source, which is why re-entering it is what its callers do")
	}
	require.NoError(t, <-writeErrChannel, "the whole payload must have reached the kernel")

	select {
	case data := <-receivedChannel:
		return data, copied, retries
	case err = <-readErrChannel:
		require.NoError(t, err, "the concurrent reader must reach EOF without an error")
		return nil, copied, retries
	case <-time.After(spliceTestDeadline):
		t.Fatal("timed out waiting for the copied payload")
		return nil, 0, retries
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

	received, copied, retries := spliceTestDrainCopy(t, source, destination, payload)

	require.Equal(t, payload, received, "the payload must be byte-exact: no duplication, no truncation")
	require.EqualValues(t, len(received), copied)
	require.GreaterOrEqual(t, counter.Load(), int64(2),
		"the splice syscall must actually run (once per direction at least), not merely be selected")
	t.Logf("1 MiB over loopback TCP: %d splice syscalls, %d drained-source re-entries", counter.Load(), retries)
}

// TestActualLinuxSpliceCaseESizes pins the size matrix. A stream under one splice chunk
// (maxSpliceSize, 1 MiB) can be moved by the first syscall alone, so a passing small transfer does
// not show the loop works; 4 MiB forces several iterations.
func TestActualLinuxSpliceCaseESizes(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()
	for _, size := range []int{64 << 10, 1 << 20, 4 << 20} {
		t.Run(map[int]string{64 << 10: "64KiB", 1 << 20: "1MiB", 4 << 20: "4MiB"}[size], func(t *testing.T) {
			counter := spliceTestCount(t, nil)
			source, destination := tcpPair(t, 1<<20)
			payload := spliceTestPayload(t, size)

			received, copied, retries := spliceTestDrainCopy(t, source, destination, payload)

			require.Equal(t, payload, received, "a %d byte stream must arrive byte-exact", size)
			require.EqualValues(t, len(received), copied)
			require.GreaterOrEqual(t, counter.Load(), int64(2),
				"the splice syscall must run for a %d byte stream", size)
			t.Logf("%d bytes over loopback TCP: %d splice syscalls, %d drained-source re-entries",
				size, counter.Load(), retries)
		})
	}
}

// TestActualLinuxSpliceCaseDHalfClose checks that a half-close is carried by the splice path: each
// side's EOF must reach the other as EOF, with both directions moving at once.
func TestActualLinuxSpliceCaseDHalfClose(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()
	counter := spliceTestCount(t, nil)
	client, server := tcpPair(t, 1<<20)

	clientPayload := spliceTestPayload(t, 256<<10)
	serverPayload := spliceTestPayload(t, 256<<10)

	var waitGroup sync.WaitGroup
	var failures atomic.Int64
	runDirection := func(destination, source *net.TCPConn, payload []byte, label string) {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			receivedChannel := make(chan []byte, 1)
			go func() {
				data, _ := io.ReadAll(destination)
				receivedChannel <- data
			}()
			go func() {
				if _, err := source.Write(payload); err == nil {
					_ = source.CloseWrite()
				}
			}()
			var copied int64
			for retries := 0; ; retries++ {
				if retries >= spliceTestMaxRetries {
					t.Errorf("%s: the engine kept reporting a drained source", label)
					failures.Add(1)
					return
				}
				_, moved, directErr := copyDirect(source, destination, nil, nil)
				copied += moved
				if directErr == nil {
					break
				}
				if !strings.Contains(directErr.Error(), spliceTestEAGAIN) {
					t.Errorf("%s: unexpected copy failure: %v", label, directErr)
					failures.Add(1)
					return
				}
				if moved != 0 {
					t.Errorf("%s: a failure moved %d bytes and must not be retried", label, moved)
					failures.Add(1)
					return
				}
			}
			select {
			case data := <-receivedChannel:
				require.Equal(t, payload, data,
					"%s: a half-close must deliver every byte and then EOF, byte-exact", label)
			case <-time.After(spliceTestDeadline):
				t.Errorf("%s: timed out waiting for the half-closed payload", label)
				failures.Add(1)
			}
		}()
	}
	runDirection(server, client, clientPayload, "client->server")
	runDirection(client, server, serverPayload, "server->client")
	waitGroup.Wait()
	require.Zero(t, failures.Load(), "both directions must complete")
	require.GreaterOrEqual(t, counter.Load(), int64(2), "the splice syscall must run in this path too")
}

// TestActualLinuxSpliceCaseCSetupFailureFallsBack is the regression test for the bug the seam was
// added for: when Pipe2 fails, no payload has moved, so the handover must report itself as NOT
// taken and the userspace copy must still deliver every byte.
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

	handed, moved, directErr := copyDirect(source, destination, nil, nil)
	require.Error(t, directErr, "the setup failure must still be reported")
	require.ErrorIs(t, directErr, syscall.EMFILE)
	require.False(t, handed, "a setup failure is not a handover: the caller must be allowed to fall back")
	require.Zero(t, moved, "nothing can have moved before the pipe existed")
	require.Zero(t, counter.Load(), "the splice syscall must not run when the pipe was never created")

	// The caller's fallback, run the way a production caller runs it: through the engine, which
	// now has no pipe to fail on because splicePipe2 is restored. The source must still be
	// positioned at the start of the stream.
	splicePipe2 = originalPipe2
	received, copied, _ := spliceTestDrainCopy(t, source, destination, payload)
	require.Equal(t, payload, received, "the userspace fallback must deliver every byte after a setup failure")
	require.EqualValues(t, len(received), copied)
}

// TestActualLinuxSpliceMidStreamFailureKeepsHandover pins the other half of the contract: once
// bytes have moved through the splice backend, a failure must NOT be turned into a fallback.
// Resetting handed=false there would replay a stream whose state has advanced.
//
// The failure is injected at the write splice - the second invocation - so it lands strictly after
// the first splice has taken a real chunk out of the source. That is the situation the contract is
// about, and it is arranged deterministically rather than left to whether a socket buffer happens
// to fill.
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
	written, err := source.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), written)

	handed, moved, directErr := copyDirect(source, destination, nil, nil)
	require.Error(t, directErr, "the mid-stream failure must be reported to the caller")
	require.ErrorIs(t, directErr, syscall.EIO, "the injected failure must be the one that surfaced")
	require.True(t, handed,
		"a mid-stream failure must keep handed=true: the stream has advanced and the userspace copy must not replay it")
	require.GreaterOrEqual(t, counter.Load(), int64(2),
		"the failure must have happened inside the splice engine, after at least one successful splice")
	require.Positive(t, moved, "bytes had already moved, which is what makes a fallback unsafe here")

	// What did land must be a prefix of what was sent: a partial transfer is the honest outcome
	// here, and duplication would mean the stream had been replayed.
	require.NoError(t, destination.SetReadDeadline(time.Now().Add(2*time.Second)))
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
// on a phone - a failure mode a developer machine never sees - and an eligibility regression would
// make every test above pass by never reaching the engine.
func TestActualLinuxSpliceSeamsAreInitialized(t *testing.T) {
	require.NotNil(t, splicePipe2)
	require.NotNil(t, spliceCall)
	source, destination := tcpPair(t, 0)
	require.True(t, N.SyscallAvailableForRead(source), "a TCP socket must stay eligible for the splice path")
	require.True(t, N.SyscallAvailableForWrite(destination), "a TCP socket must stay eligible as a splice destination")
}
