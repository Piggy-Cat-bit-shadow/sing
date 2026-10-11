package bufio

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
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

// Proof-level tests for the Linux splice engine: real TCP sockets, the real production copy
// entry point, and a syscall trace to show unix.Splice actually ran.
//
// # The topology, and the mistake this file made twice before it was right
//
// A spliced copy moves bytes between TWO sockets that are not connected to each other:
//
//	producer ──TCP pair A──> sourceReader ──copy engine──> destinationWriter ──TCP pair B──> consumer
//
// The payload's only possible route is through the copy engine. The first version of this file
// built ONE pair and used its two ends as source and destination, which is not that topology at
// all: producer.Write delivered straight to consumer.Read through the kernel, past copyDirect
// entirely, while copyDirect read from a socket that nothing was writing to. Every symptom that
// followed - EAGAIN, i/o timeout, "resource temporarily unavailable" - was the harness describing
// its own wiring, and none of it was evidence about the engine. Two INDEPENDENT pairs are the
// load-bearing part of this file; if that invariant is ever broken, the tests stop proving
// anything and start moving bytes behind the engine's back.
//
// # What each test is allowed to claim
//
// The transfer goes through Copy, which is the production entry point. copyDirect is not driven
// by hand: a hand-written driver would be a caller that does not exist in production, and a proof
// about an invented caller is not a proof about the product.
//
// The assertion that unix.Splice() RAN is not made here at all. It cannot be made honestly from
// inside the package without routing the production syscall through a mutable function value,
// which is instrumentation that changes the thing being measured. It is made where a kernel-level
// claim belongs: .github/workflows/linux-splice-proof.yml runs this test binary under strace and
// greps the trace for `splice(`. What these tests establish is the part Go can see - the payload
// moved byte-exact, in full, through the production copy path.
var spliceTestHookLock sync.Mutex

const (
	// spliceTestDeadline bounds a socket operation. Every assertion here is about correctness,
	// not latency; the deadline exists so a regression fails with an error instead of hanging.
	spliceTestDeadline = 60 * time.Second
	// spliceTestLeftoverDrain bounds the read of whatever the engine left behind after a
	// deliberate mid-stream failure. It is short because there is nothing to wait for.
	spliceTestLeftoverDrain = 2 * time.Second
)

// spliceTestPair is one independent TCP connection, both ends usable as a proxy would use them.
type spliceTestPair struct {
	client *net.TCPConn
	server *net.TCPConn
}

// spliceTestNewPair returns a connected loopback TCP pair with both ends under one deadline.
//
// Callers MUST use two of these, from two separate calls: see the topology note above.
func spliceTestNewPair(t *testing.T, bufferSize int) spliceTestPair {
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
	client := clientConn.(*net.TCPConn)
	var server *net.TCPConn
	select {
	case server = <-accepted:
	case err = <-acceptErr:
		require.NoError(t, err)
	case <-time.After(spliceTestDeadline):
		t.Fatal("timed out accepting the loopback connection")
	}
	require.NoError(t, listener.Close())
	// Best effort: the kernel caps these, and a failed call is not a reason to fail the test -
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
	return spliceTestPair{client: client, server: server}
}

// spliceTestPayload returns n bytes of incompressible payload.
func spliceTestPayload(t *testing.T, size int) []byte {
	t.Helper()
	payload := make([]byte, size)
	_, err := rand.Read(payload)
	require.NoError(t, err)
	return payload
}

// spliceTestProxyCopy runs the production copy path across two independent pairs and returns what
// the consumer received and the byte count Copy reported.
//
// The four roles are separate sockets and the function asserts that the engine's source and
// destination are not the two ends of one connection, because that mistake silently moves the
// payload behind the engine's back instead of failing:
//
//	producer.Write ──> sourceReader  (the socket the engine reads)
//	consumer.Read <── destinationWriter (the socket the engine writes)
func spliceTestProxyCopy(t *testing.T, producer, sourceReader, destinationWriter, consumer *net.TCPConn, payload []byte) ([]byte, int64) {
	t.Helper()

	// The invariant this whole file rests on. When the source and the destination are peers of one
	// connection, the payload can travel from producer to consumer without the engine touching it,
	// and every assertion below would still pass. Refuse to run in that shape.
	require.NotEqual(t, sourceReader.LocalAddr().String(), destinationWriter.RemoteAddr().String(),
		"the engine's source and destination must be on two independent TCP connections, not two ends of one: %s",
		describeWiring("producer", producer)+" "+describeWiring("source", sourceReader)+" "+
			describeWiring("destination", destinationWriter)+" "+describeWiring("consumer", consumer))
	require.NotEqual(t, producer.LocalAddr().String(), consumer.RemoteAddr().String(),
		"the producer and the consumer must be on two independent TCP connections: %s",
		describeWiring("producer", producer)+" "+describeWiring("consumer", consumer))

	// The consumer starts draining before anything is copied, so the destination's receive window
	// never closes on a stalled reader.
	received := make(chan []byte, 1)
	readErr := make(chan error, 1)
	go func() {
		data, err := io.ReadAll(consumer)
		if err != nil {
			readErr <- err
			return
		}
		received <- data
	}()

	// The producer feeds the socket the engine will read, and half-closes when it is done, which is
	// what gives the engine its EOF.
	writeErr := make(chan error, 1)
	go func() {
		_, err := producer.Write(payload)
		if err == nil {
			err = producer.CloseWrite()
		}
		writeErr <- err
	}()

	// The production entry point. Not copyDirect, and not a loop: a driver invented for a test
	// would prove something about the driver.
	copied, err := Copy(destinationWriter, sourceReader)
	require.NoError(t, err, "the production copy path must complete the stream")
	require.NoError(t, <-writeErr, "the whole payload must have reached the kernel")

	// Close the writer end so the consumer sees EOF rather than a connection that stays open.
	_ = destinationWriter.CloseWrite()

	select {
	case data := <-received:
		return data, copied
	case err = <-readErr:
		require.NoError(t, err, "the consumer must reach EOF without an error")
		return nil, copied
	case <-time.After(spliceTestDeadline):
		t.Fatal("timed out waiting for the consumer to reach EOF")
		return nil, 0
	}
}

// describeWiring renders one socket's identity, so a topology failure names the sockets instead of
// just failing.
func describeWiring(role string, conn *net.TCPConn) string {
	return role + "[" + conn.LocalAddr().String() + "<->" + conn.RemoteAddr().String() + "]"
}

// TestActualLinuxSpliceCaseA is the case the objective names: a real TCP stream moved by the
// production copy path over two independent pairs.
func TestActualLinuxSpliceCaseA(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()

	producerPair := spliceTestNewPair(t, 1<<20)
	proxyPair := spliceTestNewPair(t, 1<<20)
	payload := spliceTestPayload(t, 1<<20)

	received, copied := spliceTestProxyCopy(t, producerPair.client, producerPair.server, proxyPair.client, proxyPair.server, payload)

	require.Equal(t, payload, received, "the payload must be byte-exact: no duplication, no truncation")
	require.EqualValues(t, len(payload), copied, "the engine must report every byte it moved")
}

// TestActualLinuxSpliceCaseESizes pins the size matrix. A stream under one splice chunk
// (maxSpliceSize, 1 MiB) can be moved by the first syscall alone, so a passing small transfer does
// not show the loop works; 4 MiB forces several iterations.
func TestActualLinuxSpliceCaseESizes(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()
	for _, size := range []int{64 << 10, 1 << 20, 4 << 20} {
		t.Run(map[int]string{64 << 10: "64KiB", 1 << 20: "1MiB", 4 << 20: "4MiB"}[size], func(t *testing.T) {
			producerPair := spliceTestNewPair(t, 1<<20)
			proxyPair := spliceTestNewPair(t, 1<<20)
			payload := spliceTestPayload(t, size)

			received, copied := spliceTestProxyCopy(t, producerPair.client, producerPair.server, proxyPair.client, proxyPair.server, payload)

			require.Equal(t, payload, received, "a %d byte stream must arrive byte-exact", size)
			require.EqualValues(t, len(payload), copied)
		})
	}
}

// TestActualLinuxSpliceCaseDHalfClose checks that the half-close of the producer reaches the
// consumer as EOF - the property a proxied stream depends on - in both directions at once.
//
// Each direction gets its own two pairs, which is four connections in total: a direction's source
// and destination are never the two ends of one connection, for the same reason as everywhere else
// in this file.
func TestActualLinuxSpliceCaseDHalfClose(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()

	// Direction A -> B: the producer of pair A pushes into the proxy, which writes to pair B.
	aProducerPair := spliceTestNewPair(t, 1<<20)
	aProxyPair := spliceTestNewPair(t, 1<<20)
	// Direction B -> A: mirror image, on its own two pairs.
	bProducerPair := spliceTestNewPair(t, 1<<20)
	bProxyPair := spliceTestNewPair(t, 1<<20)

	payloadAB := spliceTestPayload(t, 256<<10)
	payloadBA := spliceTestPayload(t, 256<<10)

	var failures atomic.Int64
	type direction struct {
		label       string
		producer    *net.TCPConn
		source      *net.TCPConn
		destination *net.TCPConn
		consumer    *net.TCPConn
		payload     []byte
	}
	directions := []direction{
		{"A->B", aProducerPair.client, aProducerPair.server, aProxyPair.client, aProxyPair.server, payloadAB},
		{"B->A", bProducerPair.client, bProducerPair.server, bProxyPair.client, bProxyPair.server, payloadBA},
	}
	var waitGroup sync.WaitGroup
	for _, item := range directions {
		waitGroup.Add(1)
		go func(item direction) {
			defer waitGroup.Done()
			receivedChannel := make(chan []byte, 1)
			go func() {
				data, err := io.ReadAll(item.consumer)
				if err != nil {
					receivedChannel <- nil
					return
				}
				receivedChannel <- data
			}()
			writeErr := make(chan error, 1)
			go func() {
				_, err := item.producer.Write(item.payload)
				if err == nil {
					err = item.producer.CloseWrite()
				}
				writeErr <- err
			}()
			copied, err := Copy(item.destination, item.source)
			if err != nil {
				t.Errorf("%s: the production copy path failed: %v", item.label, err)
				failures.Add(1)
				return
			}
			if writeErrValue := <-writeErr; writeErrValue != nil {
				t.Errorf("%s: the producer failed: %v", item.label, writeErrValue)
				failures.Add(1)
				return
			}
			_ = item.destination.CloseWrite()
			select {
			case data := <-receivedChannel:
				if !bytes.Equal(data, item.payload) {
					t.Errorf("%s: a half-close must deliver every byte and then EOF, byte-exact (got %d of %d)",
						item.label, len(data), len(item.payload))
					failures.Add(1)
					return
				}
				if copied != int64(len(item.payload)) {
					t.Errorf("%s: the engine reported %d bytes for a %d byte payload", item.label, copied, len(item.payload))
					failures.Add(1)
				}
			case <-time.After(spliceTestDeadline):
				t.Errorf("%s: timed out waiting for the half-closed payload", item.label)
				failures.Add(1)
			}
		}(item)
	}
	waitGroup.Wait()
	require.Zero(t, failures.Load(), "both directions must complete")
}

// TestPipe2SetupFailureFallsBackWhenThePipeCannotBeCreated is the regression test for the bug this
// branch fixes: a Pipe2 setup failure used to return handed=true, so the caller skipped the
// userspace fallback and a session that moved zero bytes looked like a stall.
//
// It asserts the observable outcome rather than the internal flag, which is the stronger claim: the
// production Copy call must report NO error, must report every byte, and the consumer must receive
// the payload byte-exact. A version that returns handed=false but has already consumed bytes fails
// on the payload; a version that returns handed=true fails on all three.
//
// The topology is the same two-pair one as everything else here, so the fallback is exercised
// through the real production copy path and not through a hand-written caller.
func TestPipe2SetupFailureFallsBackWhenThePipeCannotBeCreated(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()

	originalPipe2 := splicePipe2
	splicePipe2 = func(fds []int, flags int) error {
		return syscall.EMFILE
	}
	t.Cleanup(func() { splicePipe2 = originalPipe2 })

	producerPair := spliceTestNewPair(t, 1<<20)
	proxyPair := spliceTestNewPair(t, 1<<20)
	payload := spliceTestPayload(t, 512<<10)

	received, copied := spliceTestProxyCopy(t, producerPair.client, producerPair.server, proxyPair.client, proxyPair.server, payload)

	require.Equal(t, payload, received,
		"a Pipe2 setup failure must fall back to the userspace copy and still deliver every byte")
	require.EqualValues(t, len(payload), copied)
}

// TestPipe2SeamIsTheRealPipe2 guards the seam: if splicePipe2 were ever left as a stub, the test
// above would still compile and would stop testing production. The real function must be what the
// package ships.
func TestPipe2SeamIsTheRealPipe2(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()
	var fds [2]int
	require.NoError(t, splicePipe2(fds[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK))
	require.NoError(t, unix.Close(fds[0]))
	require.NoError(t, unix.Close(fds[1]))
}

// TestActualLinuxSpliceMidStreamFailureIsReported pins the other half of the handed contract: once
// bytes have moved through the splice backend, a failure must be REPORTED rather than silently
// falling back, because a fallback there would replay a stream whose state has advanced.
//
// This one drives copyDirect instead of Copy on purpose. The claim is about copyDirect's return
// values - handed, moved and err - which Copy consumes and does not expose; and the failure is a
// real syscall result rather than a seam.
//
// # Why the source has a short read deadline
//
// The destination is deliberately unwritable, so the copy cannot make progress and the engine sits
// in the poller. Two things can then end the call, and both are honest reports of the same fact:
//
//   - the write splice fails outright once the pipe has been filled and the destination refuses
//     more, which is the failure this test is named for; or
//   - the read splice finds the source drained and the poller waits until the socket deadline,
//     which surfaces as i/o timeout.
//
// The deadline is therefore set short and the error is required to be ONE of those two, rather than
// accepting any error. What is asserted either way is the part the contract is about: the handover
// is claimed (handed), bytes have already moved (moved > 0, so a fallback would replay them), and
// what landed is a prefix of what was sent.
func TestActualLinuxSpliceMidStreamFailureIsReported(t *testing.T) {
	spliceTestHookLock.Lock()
	defer spliceTestHookLock.Unlock()

	producerPair := spliceTestNewPair(t, 0)
	proxyPair := spliceTestNewPair(t, 0)
	payload := spliceTestPayload(t, 256<<10)

	// Everything the reader will ever get is written before the copy starts, so the engine has real
	// bytes to move, and the reader side of that same connection is what the engine reads.
	written, err := producerPair.client.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), written)

	// A destination that cannot accept the bytes: a tiny send buffer and nothing reading the far
	// end. The failure happens after bytes have left the source, which is the situation the handed
	// contract is about.
	require.NoError(t, proxyPair.client.SetWriteBuffer(1024))
	require.NoError(t, producerPair.server.SetReadDeadline(time.Now().Add(5*time.Second)))

	handed, moved, directErr := copyDirect(producerPair.server, proxyPair.client, nil, nil)
	require.Error(t, directErr, "a copy that cannot make progress must report an error")
	require.True(t, handed,
		"a mid-stream failure must keep handed=true: the stream has advanced and the userspace copy must not replay it")
	require.Positive(t, moved, "bytes had already moved, which is what makes a fallback unsafe here")
	require.True(t,
		errors.Is(directErr, os.ErrDeadlineExceeded) || strings.Contains(directErr.Error(), "splice write"),
		"the failure must be the blocked write splice or the drain deadline, not something unrelated: %v", directErr)

	// What the destination received must be a prefix of what was sent: a partial transfer is the
	// honest outcome here, and duplication would mean the stream had been replayed.
	require.NoError(t, proxyPair.server.SetReadDeadline(time.Now().Add(spliceTestLeftoverDrain)))
	received, _ := io.ReadAll(proxyPair.server)
	require.NotEmpty(t, received)
	require.Equal(t, payload[:len(received)], received, "what landed must be a prefix of what was sent")
}

// TestActualLinuxSpliceSeamsAreInitialized guards the wiring the tests above depend on: the pipe
// seam must be initialized from the real syscall rather than left nil, and plain TCP sockets must
// still be eligible for the path this file proves. A nil seam would panic on the first spliced
// connection on a phone - a failure mode a developer machine never sees - and an eligibility
// regression would make every test above pass by never reaching the engine.
func TestActualLinuxSpliceSeamsAreInitialized(t *testing.T) {
	require.NotNil(t, splicePipe2)
	pair := spliceTestNewPair(t, 0)
	require.True(t, N.SyscallAvailableForRead(pair.server), "a TCP socket must stay eligible for the splice path")
	require.True(t, N.SyscallAvailableForWrite(pair.client), "a TCP socket must stay eligible as a splice destination")
}
