package bufio

// A cached first packet must not cost the session its batch path.
//
// route wraps the first packet (and any sniffed extra packets) in a CachedPacketConn before
// handing the flow to the packet copy engine, and the cache is deliberately NOT replaceable
// until it has been taken: letting a batch read through would skip the cached bytes and lose
// the first packet. CopyPacket and copyWithIncreateBuffer therefore drain N.CachedPacketReader
// BEFORE they probe for capabilities. CopyPacketWithCounters - the entry point
// route/conn.go's packetConnectionCopy calls - did not, so it probed while the cache was still
// held, found no batch reader, and fell into the per-packet loop for the WHOLE session: the
// probe runs once and the loop never returns to it.
//
// The two log lines below are the contract: both entry points must reach the batch path for
// the same input. The fake below is adapted from the round-06 capability harness (D line,
// .mem-r6/D-caps/harness), reduced to what this assertion needs.

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

// batchSession is a packet connection offering both batch capabilities and a fixed payload
// list that ends in io.EOF.
type batchSession struct {
	payloads [][]byte
	dest     M.Socksaddr

	readIndex atomic.Int32

	readPackets  atomic.Int32
	writePackets atomic.Int32
	batchReads   atomic.Int32
	batchWrites  atomic.Int32
}

func newBatchSession(count int, size int) *batchSession {
	session := &batchSession{dest: M.SocksaddrFrom(M.ParseAddr("127.0.0.1"), 5353)}
	for i := 0; i < count; i++ {
		payload := make([]byte, size)
		payload[0] = byte(i)
		session.payloads = append(session.payloads, payload)
	}
	return session
}

func (c *batchSession) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	index := int(c.readIndex.Add(1)) - 1
	if index >= len(c.payloads) {
		return M.Socksaddr{}, io.EOF
	}
	c.readPackets.Add(1)
	_, err := buffer.Write(c.payloads[index])
	return c.dest, err
}

func (c *batchSession) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	defer buffer.Release()
	c.writePackets.Add(1)
	return nil
}

func (c *batchSession) CreatePacketBatchReadWaiter() (N.PacketBatchReadWaiter, bool) {
	return &batchSessionReader{session: c}, true
}

func (c *batchSession) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	return &batchSessionWriter{session: c}, true
}

func (c *batchSession) Close() error                     { return nil }
func (c *batchSession) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *batchSession) SetDeadline(time.Time) error      { return nil }
func (c *batchSession) SetReadDeadline(time.Time) error  { return nil }
func (c *batchSession) SetWriteDeadline(time.Time) error { return nil }

type batchSessionReader struct {
	session *batchSession
	batch   int
}

func (r *batchSessionReader) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	r.batch = options.BatchSize
	if r.batch <= 0 {
		r.batch = 1
	}
	return false
}

func (r *batchSessionReader) WaitReadPackets() ([]*buf.Buffer, []M.Socksaddr, error) {
	buffers := make([]*buf.Buffer, 0, r.batch)
	destinations := make([]M.Socksaddr, 0, r.batch)
	for len(buffers) < r.batch {
		buffer := buf.NewPacket()
		destination, err := r.session.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			if len(buffers) == 0 {
				return nil, nil, err
			}
			break
		}
		buffers = append(buffers, buffer)
		destinations = append(destinations, destination)
	}
	r.session.batchReads.Add(1)
	return buffers, destinations, nil
}

type batchSessionWriter struct {
	session *batchSession
}

func (w *batchSessionWriter) WritePacketBatch(buffers []*buf.Buffer, _ []M.Socksaddr) error {
	w.session.batchWrites.Add(1)
	w.session.writePackets.Add(int32(len(buffers)))
	buf.ReleaseMulti(buffers)
	return nil
}

// TestNestedCachedFirstPacketsStillKeepTheBatchPath covers the shape route actually builds.
//
// route wraps EVERY extra packet sniffing read, in reverse, so a flow whose sniffer needed two
// packets arrives here as two nested CachedPacketConns, not one. The drain loop has to peel the
// outer cache, deliver it, then unwrap THROUGH the now-taken outer connection to reach the inner
// one. A fix that only drains one level would pass the single-cache test above and still leave the
// batch path unreachable in production, which is the failure this test exists to prevent.
func TestNestedCachedFirstPacketsStillKeepTheBatchPath(t *testing.T) {
	const datagrams = 4
	const datagramSize = 1200
	destination := M.SocksaddrFrom(M.ParseAddr("127.0.0.1"), 9999)

	newCachedPacket := func(payload string) *buf.Buffer {
		cached := buf.NewPacket()
		_, err := cached.Write([]byte(payload))
		require.NoError(t, err)
		return cached
	}

	for _, depth := range []int{1, 2, 3} {
		source := newBatchSession(datagrams, datagramSize)
		sink := newBatchSession(0, 0)
		var conn N.PacketConn = source
		for level := 0; level < depth; level++ {
			conn = NewCachedPacketConn(conn, newCachedPacket("first-packet"), destination)
		}
		_, err := CopyPacketWithCounters(sink, conn, conn, nil, nil)
		require.True(t, errors.Is(err, io.EOF), "depth=%d: ended with %v", depth, err)

		t.Logf("depth=%d: batchWrites=%d singleWrites=%d",
			depth, sink.batchWrites.Load(), sink.writePackets.Load())

		require.Equal(t, int32(depth+datagrams), sink.writePackets.Load(),
			"depth=%d: every cached packet and every datagram must arrive exactly once", depth)
		require.NotZero(t, sink.batchWrites.Load(),
			"depth=%d: nested caches left the batch path unreachable; the drain loop peeled only one level", depth)
	}
}

// TestCachedFirstPacketKeepsTheBatchPath is the regression this file exists for.
//
// It asserts equality between the two entry points rather than a number specific to one of
// them, so it stays meaningful if the copy engine's batch sizing changes.
func TestCachedFirstPacketKeepsTheBatchPath(t *testing.T) {
	const datagrams = 4
	const datagramSize = 1200

	newCached := func(source *batchSession) *CachedPacketConn {
		cached := buf.NewPacket()
		_, err := cached.Write([]byte("first-packet"))
		require.NoError(t, err)
		return NewCachedPacketConn(source, cached, M.SocksaddrFrom(M.ParseAddr("127.0.0.1"), 9999))
	}

	// Control: CopyPacket drains the cache before probing, so it must reach the batch path.
	controlSource := newBatchSession(datagrams, datagramSize)
	controlSink := newBatchSession(0, 0)
	_, err := CopyPacket(controlSink, newCached(controlSource))
	require.ErrorIs(t, err, io.EOF)
	require.NotZero(t, controlSink.batchWrites.Load(),
		"control: CopyPacket must reach the batch path after draining the cache")

	// The entry point route's packet copy calls.
	source := newBatchSession(datagrams, datagramSize)
	sink := newBatchSession(0, 0)
	cached := newCached(source)
	_, err = CopyPacketWithCounters(sink, cached, cached, nil, nil)
	require.True(t, errors.Is(err, io.EOF), "CopyPacketWithCounters ended with %v, want io.EOF", err)

	t.Logf("CopyPacket:              batchWrites=%d singleWrites=%d",
		controlSink.batchWrites.Load(), controlSink.writePackets.Load())
	t.Logf("CopyPacketWithCounters:  batchWrites=%d singleWrites=%d",
		sink.batchWrites.Load(), sink.writePackets.Load())

	require.Equal(t, int32(datagrams+1), sink.writePackets.Load(),
		"every datagram, including the cached one, must arrive exactly once")
	require.NotZero(t, sink.batchWrites.Load(),
		"the cached first packet must not cost the session its batch path: "+
			"CopyPacketWithCounters probed for capabilities while the cache was still held, "+
			"so the whole session fell back to one write per datagram")
}
