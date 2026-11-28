package canceler

// The idle-timeout wrappers sit in front of every UDP session that has a timeout, which is
// every UDP NAT session. They forwarded the CONNECTED batch capabilities (packet_batch.go),
// but not the unconnected ones - and the unconnected ones are what the NAT copy path asks for,
// because a NAT session writes each datagram to its own destination.
//
// The failure mode is the one packet_batch.go already describes for the connected half: the
// connection keeps working, so no functional test notices, and the batching is simply
// unreachable. These tests drive the production entry points
// (bufio.CreatePacketBatchWriter / CreatePacketBatchReadWaiter) rather than the wrapper's
// methods, because that is what the copy engine calls.

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

// fakeBatchConn is an UNCONNECTED packet connection offering both batch capabilities, with
// everything else under the test's control. deadlineErr selects the wrapper branch the same way
// the connected fake's does: os.ErrInvalid gives TimerPacketConn, nil gives TimeoutPacketConn.
type fakeBatchConn struct {
	deadlineErr error
	closed      chan struct{}
	closeOnce   sync.Once

	batchReads  int
	batchWrites int
	lastBatch   int
}

func newFakeBatchConn(deadlineErr error) *fakeBatchConn {
	return &fakeBatchConn{deadlineErr: deadlineErr, closed: make(chan struct{})}
}

func (c *fakeBatchConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, net.ErrClosed
}

func (c *fakeBatchConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (c *fakeBatchConn) LocalAddr() net.Addr                          { return &net.UDPAddr{} }
func (c *fakeBatchConn) ReadFrom(p []byte) (int, net.Addr, error)     { return 0, nil, net.ErrClosed }
func (c *fakeBatchConn) WriteTo(p []byte, addr net.Addr) (int, error) { return 0, net.ErrClosed }
func (c *fakeBatchConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (c *fakeBatchConn) SetReadDeadline(t time.Time) error  { return c.deadlineErr }
func (c *fakeBatchConn) SetWriteDeadline(t time.Time) error { return c.deadlineErr }
func (c *fakeBatchConn) SetDeadline(t time.Time) error      { return c.deadlineErr }

func (c *fakeBatchConn) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	return &fakePacketBatchWriter{conn: c}, true
}

func (c *fakeBatchConn) CreatePacketBatchReadWaiter() (N.PacketBatchReadWaiter, bool) {
	return &fakePacketBatchReadWaiter{conn: c}, true
}

type fakePacketBatchWriter struct {
	conn *fakeBatchConn
}

func (w *fakePacketBatchWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	w.conn.batchWrites++
	w.conn.lastBatch = len(buffers)
	buf.ReleaseMulti(buffers)
	return nil
}

type fakePacketBatchReadWaiter struct {
	conn *fakeBatchConn
}

func (w *fakePacketBatchReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	return false
}

// WaitReadPackets is never driven here: the capability is what is asserted. A test that reached
// it would fail loudly rather than pass silently.
func (w *fakePacketBatchReadWaiter) WaitReadPackets() ([]*buf.Buffer, []M.Socksaddr, error) {
	panic("WaitReadPackets must not be reached by a capability assertion")
}

// plainBatchlessConn offers neither capability; wrapping it must not invent one.
type plainBatchlessConn struct {
	closed chan struct{}
}

func newPlainBatchlessConn() *plainBatchlessConn {
	return &plainBatchlessConn{closed: make(chan struct{})}
}

func (c *plainBatchlessConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, net.ErrClosed
}
func (c *plainBatchlessConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}
func (c *plainBatchlessConn) LocalAddr() net.Addr                          { return &net.UDPAddr{} }
func (c *plainBatchlessConn) ReadFrom(p []byte) (int, net.Addr, error)     { return 0, nil, net.ErrClosed }
func (c *plainBatchlessConn) WriteTo(p []byte, addr net.Addr) (int, error) { return 0, net.ErrClosed }
func (c *plainBatchlessConn) Close() error                                 { return nil }
func (c *plainBatchlessConn) SetReadDeadline(t time.Time) error            { return nil }
func (c *plainBatchlessConn) SetWriteDeadline(t time.Time) error           { return nil }
func (c *plainBatchlessConn) SetDeadline(t time.Time) error                { return nil }

// TestTheTimeoutWrapperKeepsUnconnectedBatchWrites is the capability assertion, for BOTH
// wrapper branches (timer and deadline).
func TestTheTimeoutWrapperKeepsUnconnectedBatchWrites(t *testing.T) {
	for name, deadlineErr := range map[string]error{
		"TimerPacketConn":   os.ErrInvalid,
		"TimeoutPacketConn": nil,
	} {
		t.Run(name, func(t *testing.T) {
			inner := newFakeBatchConn(deadlineErr)
			_, wrapped := NewPacketConn(context.Background(), inner, time.Minute)
			batchWriter, created := bufio.CreatePacketBatchWriter(wrapped)
			require.True(t, created,
				"the idle-timeout wrapper dropped the unconnected batch write capability; "+
					"every datagram of this UDP session costs its own syscall")
			require.NoError(t, batchWriter.WritePacketBatch(
				[]*buf.Buffer{buf.NewSize(4), buf.NewSize(4)},
				[]M.Socksaddr{M.Socksaddr{}, M.Socksaddr{}},
			))
			require.Equal(t, 1, inner.batchWrites,
				"the batch must reach the inner connection exactly once, not be split per packet")
			require.Equal(t, 2, inner.lastBatch, "the wrapper must not split the batch")
		})
	}
}

// TestTheTimeoutWrapperKeepsUnconnectedBatchReads is the same assertion for the read side.
func TestTheTimeoutWrapperKeepsUnconnectedBatchReads(t *testing.T) {
	for name, deadlineErr := range map[string]error{
		"TimerPacketConn":   os.ErrInvalid,
		"TimeoutPacketConn": nil,
	} {
		t.Run(name, func(t *testing.T) {
			inner := newFakeBatchConn(deadlineErr)
			_, wrapped := NewPacketConn(context.Background(), inner, time.Minute)
			_, created := bufio.CreatePacketBatchReadWaiter(wrapped)
			require.True(t, created,
				"the idle-timeout wrapper dropped the unconnected batch read capability; "+
					"the upload direction reads one datagram per syscall")
		})
	}
}

// TestTheTimeoutWrapperDoesNotInventBatchCapability is the negative control: a connection that
// offers nothing must still offer nothing, or the copy engine would be handed a promise that
// fails at run time.
func TestTheTimeoutWrapperDoesNotInventBatchCapability(t *testing.T) {
	_, wrapped := NewPacketConn(context.Background(), newPlainBatchlessConn(), time.Minute)
	if _, created := bufio.CreatePacketBatchWriter(wrapped); created {
		t.Fatal("the wrapper invented a batch write capability the inner connection does not have")
	}
	if _, created := bufio.CreatePacketBatchReadWaiter(wrapped); created {
		t.Fatal("the wrapper invented a batch read capability the inner connection does not have")
	}
}
