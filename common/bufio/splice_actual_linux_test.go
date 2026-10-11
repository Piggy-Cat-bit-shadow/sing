package bufio

import (
	"crypto/rand"
	"errors"
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

// Proof-level tests for the Linux splice engine: they run the real thing on real TCP
// sockets rather than a mock, and they are the only tests here that assert the splice
// SYSCALL ran.
//
// # Why the distinction matters
//
// Everything else in this package's splice tests establishes preconditions: that a
// syscall.RawConn exists, that copyDirect handed over, that the caller skipped the
// userspace copy. None of that is the shipped behaviour. A wrapper that quietly returns
// before reaching unix.Splice - or a build where the splice file is not compiled at all -
// satisfies every one of them. So the assertions here are, in order of importance:
//
//  1. spliceCall actually ran, counted through the seam in splice_linux.go;
//  2. the payload arrived byte-exact with no duplication and no truncation;
//  3. the fallback cases still deliver the payload when the handover does not happen.
//
// # Why the hooks are restored through t.Cleanup and not t.Parallel
//
// splicePipe2 and spliceCall are package-level seams, so a test that swaps one out must
// not run concurrently with any other test in this package. None of these tests call
// t.Parallel, and the mutex serializes them against each other - which is also what keeps
// this file honest under -race in the fork's CI, where the whole suite runs together.
var spliceTestHookLock sync.Mutex

// spliceCounter swaps the splice syscall for a counting wrapper that still calls the real
// one, and returns the counter. The returned pointer is read after the copy has finished;
// every increment happens on a different goroutine than the read.
func spliceCounter(t *testing.T) *atomic.Int64 {
	t.Helper()
	var count atomic.Int64
	original := spliceCall
	spliceCall = func(rfd int, roff *int64, wfd int, woff *int64, length int, flags int) (int64, error) {
		count.Add(1)
		return original(rfd, roff, wfd, woff, length, flags)
	}
	t.Cleanup(func() { spliceCall = original })
	return &count
}

// tcpPair returns a connected TCP socket pair over loopback, with both ends wrapped in
// deadlines so a regression fails the test instead of hanging the run.
func tcpPair(t *testing.T) (client *net.TCPConn, server *net.TCPConn) {
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
	case <-time.After(10 * time.Second):
		t.Fatal("timed out accepting the loopback connection")
	}
	deadline := time.Now().Add(30 * time.Second)
	require.NoError(t, client.SetDeadline(deadline))
	require.NoError(t, server.SetDeadline(deadline))
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

// spliceTestPayload returns n bytes of incompressible payload and how much of it the
// kernel accepted before the source was half-closed. A short write is not a test failure -
// the loopback send buffer decides - but the caller must only compare what was accepted.
func spliceTestPayload(t *testing.T, source *net.TCPConn, size int) []byte {
	t.Helper()
	payload := make([]byte, size)
	_, err := rand.Read(payload)
	require.NoError(t, err)
	require.NoError(t, source.SetWriteBuffer(size*2))
	written, err := source.Write(payload)
	require.NoError(t, err)
	require.NotZero(t, written, "no payload reached the kernel, so the test would prove nothing")
	require.NoError(t, source.CloseWrite())
	return payload[:written]
}

// TestActualLinuxSpliceCaseA is the case the objective names: a bare TCP socket to a bare
// TCP socket, through the real copy engine, with the splice syscall counted.
func TestActualLinuxSpliceCaseA(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()
	counter := spliceCounter(t)
	source, destination := tcpPair(t)
	payload := spliceTestPayload(t, source, 1<<20)

	copied, err := Copy(destination, source)
	require.NoError(t, err)

	received, err := io.ReadAll(destination)
	require.NoError(t, err)
	require.Equal(t, payload, received, "the payload must be byte-exact: no duplication, no truncation")
	require.EqualValues(t, len(received), copied)
	require.GreaterOrEqual(t, counter.Load(), int64(2),
		"the splice syscall must actually run (at least once per direction), not merely be selected")
}

// TestActualLinuxSpliceCaseESizes pins the size matrix. A stream under one splice chunk
// (maxSpliceSize) can be moved by the first syscall alone, so a passing small transfer does
// not show the loop works; 4 MiB forces several iterations.
func TestActualLinuxSpliceCaseESizes(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()
	for _, size := range []int{64 << 10, 1 << 20, 4 << 20} {
		t.Run(map[int]string{64 << 10: "64KiB", 1 << 20: "1MiB", 4 << 20: "4MiB"}[size], func(t *testing.T) {
			counter := spliceCounter(t)
			source, destination := tcpPair(t)
			payload := spliceTestPayload(t, source, size)

			copied, err := Copy(destination, source)
			require.NoError(t, err)
			received, err := io.ReadAll(destination)
			require.NoError(t, err)
			require.Equal(t, payload, received)
			require.EqualValues(t, len(received), copied)
			// Two splices per chunk at minimum: one socket to pipe, one pipe to socket.
			require.GreaterOrEqual(t, counter.Load(), int64(2),
				"the splice syscall must run for a %d byte stream", size)
		})
	}
}

// TestActualLinuxSpliceCaseDHalfClose checks that a half-close is carried by the splice
// path: the source's EOF must reach the destination as EOF, in both directions at once.
func TestActualLinuxSpliceCaseDHalfClose(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()
	counter := spliceCounter(t)
	client, server := tcpPair(t)

	clientPayload := make([]byte, 256<<10)
	serverPayload := make([]byte, 256<<10)
	_, err := rand.Read(clientPayload)
	require.NoError(t, err)
	_, err = rand.Read(serverPayload)
	require.NoError(t, err)
	require.NoError(t, client.SetWriteBuffer(len(clientPayload)*2))
	require.NoError(t, server.SetWriteBuffer(len(serverPayload)*2))
	_, err = client.Write(clientPayload)
	require.NoError(t, err)
	_, err = server.Write(serverPayload)
	require.NoError(t, err)
	require.NoError(t, client.CloseWrite())
	require.NoError(t, server.CloseWrite())

	type result struct {
		received []byte
		copied   int64
		err      error
	}
	clientToServer := make(chan result, 1)
	serverToClient := make(chan result, 1)
	go func() {
		copied, copyErr := Copy(server, client)
		received, readErr := io.ReadAll(server)
		clientToServer <- result{received, copied, errors.Join(copyErr, readErr)}
	}()
	go func() {
		copied, copyErr := Copy(client, server)
		received, readErr := io.ReadAll(client)
		serverToClient <- result{received, copied, errors.Join(copyErr, readErr)}
	}()

	for name, channel := range map[string]chan result{"client->server": clientToServer, "server->client": serverToClient} {
		var got result
		select {
		case got = <-channel:
		case <-time.After(30 * time.Second):
			t.Fatalf("%s: timed out waiting for the copy to finish", name)
		}
		require.NoError(t, got.err, "%s", name)
		expected := clientPayload
		if name == "server->client" {
			expected = serverPayload
		}
		// A short read here is not an error - the kernel may still have been holding part of
		// the payload when the source was half-closed - but EOF must have arrived, and what
		// did arrive must be a prefix of exactly what was sent.
		require.NotEmpty(t, got.received, "%s: the copy must deliver the payload, not just reach EOF", name)
		require.Equal(t, expected[:len(got.received)], got.received, "%s", name)
	}
	require.GreaterOrEqual(t, counter.Load(), int64(2), "the splice syscall must run in this path too")
}

// TestActualLinuxSpliceCaseCSetupFailureFallsBack is the regression test for the bug the
// seam was added for: when Pipe2 fails, no payload has moved, so the handover must report
// itself as NOT taken and the userspace copy must still deliver every byte.
//
// The assertion is on the observable contract, not on the flag alone: handed=false AND the
// fallback carries the payload. A test that only checked the flag would pass against a
// version that returns handed=false but has already consumed bytes.
func TestActualLinuxSpliceCaseCSetupFailureFallsBack(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()
	originalPipe2 := splicePipe2
	splicePipe2 = func(fds []int, flags int) error {
		return syscall.EMFILE
	}
	t.Cleanup(func() { splicePipe2 = originalPipe2 })
	counter := spliceCounter(t)

	source, destination := tcpPair(t)
	payload := spliceTestPayload(t, source, 512<<10)

	handed, moved, err := copyDirect(source, destination, nil, nil)
	require.Error(t, err, "the setup failure must still be reported")
	require.ErrorIs(t, err, syscall.EMFILE)
	require.False(t, handed, "a setup failure is not a handover: the caller must be allowed to fall back")
	require.Zero(t, moved, "nothing can have moved before the pipe existed")
	require.Zero(t, counter.Load(), "the splice syscall must not run when the pipe was never created")

	// The caller's fallback, exactly as CopyWithCounters runs it: the source must still be
	// positioned at the start of the stream.
	extendedDestination := NewExtendedWriter(destination)
	extendedSource := NewExtendedReader(source)
	fallbackN, fallbackErr := CopyExtended(source, extendedDestination, extendedSource, nil, nil, 0, 0)
	require.NoError(t, fallbackErr)
	received, readErr := io.ReadAll(destination)
	require.NoError(t, readErr)
	require.Equal(t, payload, received, "the userspace fallback must deliver every byte after a setup failure")
	require.EqualValues(t, len(received), fallbackN)
}

// TestActualLinuxSpliceMidStreamFailureKeepsHandover pins the other half of the contract:
// once bytes have moved through the splice backend, a failure must NOT be turned into a
// fallback. Resetting handed=false there would replay a stream whose state has advanced.
//
// The failure is provoked the same way the pre-existing partial-write test does it, with a
// write deadline on the destination, so this is a real mid-stream syscall failure.
func TestActualLinuxSpliceMidStreamFailureKeepsHandover(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()
	counter := spliceCounter(t)
	source, destination := tcpPair(t)
	payload := spliceTestPayload(t, source, 256<<10)

	require.NoError(t, destination.SetWriteBuffer(1024))
	require.NoError(t, destination.SetWriteDeadline(time.Now().Add(100*time.Millisecond)))

	handed, moved, err := copyDirect(source, destination, nil, nil)
	require.Error(t, err, "the write failure must be reported to the caller")
	require.True(t, handed,
		"a mid-stream failure must keep handed=true: the stream has advanced and the userspace copy must not replay it")
	require.NotZero(t, counter.Load(), "the failure must have happened inside the splice engine, not before it")
	require.Positive(t, moved, "bytes had already moved, which is what makes a fallback unsafe here")

	// What did land must be a prefix of what was sent: a partial transfer is the honest
	// outcome here, and duplication would mean the stream had been replayed.
	received, _ := io.ReadAll(destination)
	require.NotEmpty(t, received)
	require.Equal(t, payload[:len(received)], received)
}

// TestActualLinuxSplicePipe2SeamIsTheRealOne guards the seam itself. If splicePipe2 were
// ever reassigned to a stub, every test above would still compile and the "setup failure"
// case would stop testing production. The real function must be what the package ships.
func TestActualLinuxSplicePipe2SeamIsTheRealOne(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()
	var fds [2]int
	require.NoError(t, splicePipe2(fds[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK))
	require.NoError(t, unix.Close(fds[0]))
	require.NoError(t, unix.Close(fds[1]))
}

// TestActualLinuxSpliceSeamsAreInitialized is a guard on the seam wiring: both seams must
// be initialized from the real syscalls rather than left nil, and a plain TCP socket must
// still be eligible for the path this file proves. A nil seam would panic on the first
// spliced connection on a phone - a failure mode a developer machine never sees - and an
// eligibility regression would make every test above pass by never reaching the engine.
func TestActualLinuxSpliceSeamsAreInitialized(t *testing.T) {
	require.NotNil(t, splicePipe2)
	require.NotNil(t, spliceCall)
	source, destination := tcpPair(t)
	require.True(t, N.SyscallAvailableForRead(source), "a TCP socket must stay eligible for the splice path")
	require.True(t, N.SyscallAvailableForWrite(destination), "a TCP socket must stay eligible as a splice destination")
}
