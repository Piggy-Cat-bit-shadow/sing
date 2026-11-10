package bufio

import (
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"

	"github.com/stretchr/testify/require"
)

// Tests for the cached first payload hand-over.
//
// # The ownership rule
//
// NewCachedConn and NewCachedReader take a reference on the buffer they are
// given, and must drop it exactly once: either by transferring it out of
// ReadCached (the caller then owns that reference and releases it), or by
// releasing it themselves when the cached bytes are consumed or Close runs.
// Everything below checks one of those two halves, because getting either wrong
// is either a leak of a pooled buffer or a read from a buffer that the pool has
// already handed to somebody else.
//
// # The Read/Close race this pins
//
// Read used to inspect and read c.buffer with no lock while Close cleared and
// released that same field. A Close that won the interleaving released the
// buffer while Read was still reading it, and a Close between Read's nil check
// and its dereference left Read reading through a nil pointer; the taken flag
// only arbitrated which caller got the hand-over, it never protected the field.
// Read, ReadCached, Close and ReaderReplaceable now share one mutex, so the
// buffer can only change at points where no reader holds it.
//
// TestCachedConnReadCloseRace is the detector-based guard for that: both
// goroutines are released by the same barrier so their accesses to the wrapper
// carry no ordering between them, which is exactly the shape -race reports on
// the unsynchronised field. Run this package with -race (see the merge report);
// the functional tests below also fail on the old code without the detector.

func TestCachedConnReadCloseRace(t *testing.T) {
	t.Parallel()
	// Several independent pairs: one pair is enough to establish the absence of
	// ordering, the repetitions make the window wide enough that a scheduler that
	// happens to serialise one pair cannot hide the bug.
	for i := 0; i < 200; i++ {
		cached := NewCachedConn(&cacheTestConn{}, cacheTestBuffer("payload"))
		start := make(chan struct{})
		var waitGroup sync.WaitGroup
		waitGroup.Add(2)
		go func() {
			defer waitGroup.Done()
			<-start
			_, _ = cached.Read(make([]byte, 1))
		}()
		go func() {
			defer waitGroup.Done()
			<-start
			_ = cached.Close()
		}()
		close(start)
		waitGroup.Wait()
	}
}

func TestCachedConnCachedPayloadDeliveredOnce(t *testing.T) {
	t.Parallel()
	cached := NewCachedConn(&cacheTestConn{}, cacheTestBuffer("payload"))
	var destination strings.Builder
	n, err := cached.WriteTo(&destination)
	require.NoError(t, err)
	require.EqualValues(t, len("payload"), n)
	// WriteTo owns the cached bytes once it has written them, so a second call
	// must not replay them onto the destination.
	n, err = cached.WriteTo(&destination)
	require.NoError(t, err)
	require.Zero(t, n)
	require.Equal(t, "payload", destination.String())
}

func TestCachedConnReaderReplaceableAfterDrain(t *testing.T) {
	t.Parallel()
	cached := NewCachedConn(&cacheTestConn{}, cacheTestBuffer("payload"))
	require.False(t, cached.ReaderReplaceable())
	payload := make([]byte, len("payload"))
	n, err := cached.Read(payload)
	require.NoError(t, err)
	require.Equal(t, len("payload"), n)
	require.Equal(t, "payload", string(payload))
	// Nothing is left to serve from the cache, so the copy loop may use the
	// upstream conn directly instead of keeping this wrapper in the chain.
	require.True(t, cached.ReaderReplaceable())
}

func TestCachedConnCloseKeepsHandedOverBuffer(t *testing.T) {
	t.Parallel()
	cached := NewCachedConn(&cacheTestConn{}, cacheTestBuffer("payload"))
	handed := cached.ReadCached()
	require.NotNil(t, handed)
	require.NoError(t, cached.Close())
	require.Equal(t, "payload", string(handed.Bytes()), "Close released a buffer that ReadCached had already handed over")
	handed.Release()
}

func TestCachedReaderCachedPayloadDeliveredOnce(t *testing.T) {
	t.Parallel()
	cached := NewCachedReader(strings.NewReader(""), cacheTestBuffer("payload"))
	var destination strings.Builder
	n, err := cached.WriteTo(&destination)
	require.NoError(t, err)
	require.EqualValues(t, len("payload"), n)
	// Same rule as CachedConn: the first WriteTo consumes the cached bytes.
	n, err = cached.WriteTo(&destination)
	require.NoError(t, err)
	require.Zero(t, n)
	require.Equal(t, "payload", destination.String())
}

func TestCachedReaderReaderReplaceableAfterDrain(t *testing.T) {
	t.Parallel()
	cached := NewCachedReader(strings.NewReader(""), cacheTestBuffer("payload"))
	require.False(t, cached.ReaderReplaceable())
	payload := make([]byte, len("payload"))
	n, err := cached.Read(payload)
	require.NoError(t, err)
	require.Equal(t, len("payload"), n)
	require.Equal(t, "payload", string(payload))
	require.True(t, cached.ReaderReplaceable())
}

func TestCachedReaderCloseKeepsHandedOverBuffer(t *testing.T) {
	t.Parallel()
	cached := NewCachedReader(strings.NewReader(""), cacheTestBuffer("payload"))
	handed := cached.ReadCached()
	require.NotNil(t, handed)
	require.NoError(t, cached.Close())
	require.Equal(t, "payload", string(handed.Bytes()), "Close released a buffer that ReadCached had already handed over")
	handed.Release()
}

func cacheTestBuffer(payload string) *buf.Buffer {
	buffer := buf.NewSize(len(payload))
	common.Must1(buffer.Write([]byte(payload)))
	return buffer
}

// cacheTestConn is already at EOF: any read that falls through the cache returns
// io.EOF immediately, so these tests never block on a socket.
type cacheTestConn struct{}

func (c *cacheTestConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *cacheTestConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *cacheTestConn) Close() error                     { return nil }
func (c *cacheTestConn) LocalAddr() net.Addr              { return cacheTestAddr{} }
func (c *cacheTestConn) RemoteAddr() net.Addr             { return cacheTestAddr{} }
func (c *cacheTestConn) SetDeadline(time.Time) error      { return nil }
func (c *cacheTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *cacheTestConn) SetWriteDeadline(time.Time) error { return nil }

type cacheTestAddr struct{}

func (cacheTestAddr) Network() string { return "test" }
func (cacheTestAddr) String() string  { return "cache-test" }
