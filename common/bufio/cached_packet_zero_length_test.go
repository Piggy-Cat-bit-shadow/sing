package bufio

// D02-ZERO: the session-facing meaning of "not the first packet" must survive an empty first packet.
//
// Handshake accounting asks one question: has this session already handed a packet to the
// destination? A cached packet may legitimately be empty, and while the flag was inferred from the
// byte count, an empty first packet left the flag false. The packet AFTER it was then classified as
// the session's first, so its write failure was reported through N.ReportHandshakeFailure - a
// handshake failure announced for a session whose handshake had already completed.

import (
	"errors"
	"io"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

// handshakeFailureRecorder is the origin source the engine consults when a first packet fails.
// It satisfies N.PacketReader only because the origin parameter is typed that way; the engine never
// reads from it.
type handshakeFailureRecorder struct {
	calls atomic.Int32
}

func (r *handshakeFailureRecorder) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, io.EOF
}

func (r *handshakeFailureRecorder) HandshakeFailure(err error) error {
	r.calls.Add(1)
	return err
}

// failingDestination writes the first packet, then fails every later one with a plain error.
type failingDestination struct {
	written  atomic.Bool
	failNow  bool
	writeErr error
}

func (d *failingDestination) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	defer buffer.Release()
	if d.failNow || d.written.Swap(true) {
		return d.writeErr
	}
	return nil
}

// cachedSource is a packet reader whose cache holds exactly one packet, empty or not.
//
// Upstream is a DIFFERENT object without ReaderReplaceable: returning itself would make
// N.UnwrapCountPacketReader follow it forever once the cache had been taken.
type cachedSource struct {
	cached  *buf.Buffer
	payload []byte
	plain   plainSource
}

type plainSource struct {
	payload []byte
	read    bool
}

func (c *plainSource) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if c.read {
		return M.Socksaddr{}, io.EOF
	}
	c.read = true
	_, err := buffer.Write(c.payload)
	return M.Socksaddr{}, err
}

func (c *cachedSource) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	return c.plain.ReadPacket(buffer)
}

func (c *cachedSource) ReadCachedPacket() *N.PacketBuffer {
	if c.cached == nil {
		return nil
	}
	cached := c.cached
	c.cached = nil
	return &N.PacketBuffer{Buffer: cached, Destination: M.Socksaddr{}}
}

func (c *cachedSource) Upstream() any { return &c.plain }

func (c *cachedSource) ReaderReplaceable() bool { return c.cached == nil }

// TestCachedEmptyPacketDoesNotMakeTheNextFailureAHandshakeFailure is the regression.
func TestCachedEmptyPacketDoesNotMakeTheNextFailureAHandshakeFailure(t *testing.T) {
	writeErr := errors.New("destination refused the datagram")

	origin := &handshakeFailureRecorder{}
	source := &cachedSource{cached: buf.NewPacket(), payload: []byte("second-packet")}
	destination := &failingDestination{writeErr: writeErr}

	_, err := CopyPacketWithCounters(destination, source, origin, nil, nil)

	require.ErrorIs(t, err, writeErr,
		"the destination's own error must reach the caller unchanged; got %v", err)
	require.Zero(t, origin.calls.Load(),
		"a failure after an already-delivered (empty) first packet was reported as a handshake "+
			"failure: %d call(s)", origin.calls.Load())
}

// TestCachedEmptyFirstFailureStillReportsOnce is the control in the other direction: a genuine
// first-packet failure must still be reported, or the fix would have silenced the path.
func TestCachedEmptyFirstFailureStillReportsOnce(t *testing.T) {
	writeErr := errors.New("destination refused the first datagram")

	origin := &handshakeFailureRecorder{}
	source := &cachedSource{payload: []byte("first-packet")} // no cache: the first read is the first packet
	destination := &failingDestination{writeErr: writeErr, failNow: true}

	_, err := CopyPacketWithCounters(destination, source, origin, nil, nil)

	require.ErrorIs(t, err, writeErr)
	require.EqualValues(t, 1, origin.calls.Load(),
		"a genuine first-packet failure stopped being reported, so the guard is over-broad")
}
