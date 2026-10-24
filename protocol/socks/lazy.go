package socks

import (
	"net"
	"os"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks/socks4"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

// LazyConn defers the SOCKS reply until the outcome is known, so the reply can carry the
// bound address on success.
//
// # Why the reply state is synchronized
//
// The reply is written from whichever copy direction touches the connection first, and the
// two directions run on different goroutines: Read (the download loop) and Write (the upload
// loop) both call ConnHandshakeSuccess when the reply has not gone out yet, and
// ReaderReplaceable/WriterReplaceable are read by those same loops to decide whether the
// connection can be replaced. With a plain bool that is a data race, and it is not only a
// detector artifact: both goroutines can observe false and both write a reply frame, which
// puts two SOCKS replies on the wire for one connection and desynchronises the client's
// parser from that point on.
//
// responseAccess serializes the one-time decision and responseWritten publishes the outcome.
// Holding the lock across the write is deliberate: the section is a single small reply frame
// on a connection that is still being established, contention is at most the two copy loops
// of the SAME connection, the lock is a leaf (nothing else is taken under it and it is never
// taken while holding another lock), and releasing it mid-write is exactly what would let the
// second writer interleave its frame.
type LazyConn struct {
	net.Conn
	socksVersion    byte
	responseAccess  sync.Mutex
	responseWritten atomic.Bool
}

func NewLazyConn(conn net.Conn, socksVersion byte) *LazyConn {
	return &LazyConn{
		Conn:         conn,
		socksVersion: socksVersion,
	}
}

func (c *LazyConn) ConnHandshakeSuccess(conn net.Conn) error {
	c.responseAccess.Lock()
	defer c.responseAccess.Unlock()
	if c.responseWritten.Load() {
		return nil
	}
	var err error
	switch c.socksVersion {
	case socks4.Version:
		err = socks4.WriteResponse(c.Conn, socks4.Response{
			ReplyCode:   socks4.ReplyCodeGranted,
			Destination: M.SocksaddrFromNet(conn.LocalAddr()).Unwrap(),
		})
	case socks5.Version:
		err = socks5.WriteResponse(c.Conn, socks5.Response{
			ReplyCode: socks5.ReplyCodeSuccess,
			Bind:      M.SocksaddrFromNet(conn.LocalAddr()).Unwrap(),
		})
	default:
		panic("unknown socks version")
	}
	// Marked written even when the write failed, which is what the previous defer did: the
	// reply is a one-shot, and retrying it would append a second frame rather than fix a
	// half-written one.
	c.responseWritten.Store(true)
	return err
}

func (c *LazyConn) HandshakeFailure(reason error) error {
	c.responseAccess.Lock()
	defer c.responseAccess.Unlock()
	if c.responseWritten.Load() {
		return os.ErrInvalid
	}
	var err error
	switch c.socksVersion {
	case socks4.Version:
		err = socks4.WriteResponse(c.Conn, socks4.Response{
			ReplyCode: socks4.ReplyCodeRejectedOrFailed,
		})
	case socks5.Version:
		err = socks5.WriteResponse(c.Conn, socks5.Response{
			ReplyCode: socks5.ReplyCodeForError(reason),
		})
	default:
		panic("unknown socks version")
	}
	c.responseWritten.Store(true)
	return err
}

func (c *LazyConn) Read(p []byte) (n int, err error) {
	if !c.responseWritten.Load() {
		err = c.ConnHandshakeSuccess(c.Conn)
		if err != nil {
			return
		}
	}
	return c.Conn.Read(p)
}

func (c *LazyConn) Write(p []byte) (n int, err error) {
	if !c.responseWritten.Load() {
		err = c.ConnHandshakeSuccess(c.Conn)
		if err != nil {
			return
		}
	}
	return c.Conn.Write(p)
}

func (c *LazyConn) ReaderReplaceable() bool {
	return c.responseWritten.Load()
}

func (c *LazyConn) WriterReplaceable() bool {
	return c.responseWritten.Load()
}

func (c *LazyConn) Upstream() any {
	return c.Conn
}

// LazyAssociatePacketConn is the UDP ASSOCIATE counterpart of LazyConn and carries the same
// synchronization, for the same reason: the reply is written from whichever direction touches
// the association first - ReadFrom/ReadPacket on the receive side, WriteTo/WritePacket on the
// send side - and those run on different goroutines. See LazyConn for the full rationale.
type LazyAssociatePacketConn struct {
	AssociatePacketConn
	responseAccess  sync.Mutex
	responseWritten atomic.Bool
}

func NewLazyAssociatePacketConn(conn net.Conn, underlying net.Conn) *LazyAssociatePacketConn {
	return &LazyAssociatePacketConn{
		AssociatePacketConn: *NewAssociatePacketConn(conn, M.Socksaddr{}, underlying),
	}
}

func (c *LazyAssociatePacketConn) HandshakeSuccess() error {
	c.responseAccess.Lock()
	defer c.responseAccess.Unlock()
	if c.responseWritten.Load() {
		return nil
	}
	err := socks5.WriteResponse(c.underlying, socks5.Response{
		ReplyCode: socks5.ReplyCodeSuccess,
		Bind:      M.SocksaddrFromNet(c.conn.LocalAddr()).Unwrap(),
	})
	c.responseWritten.Store(true)
	return err
}

func (c *LazyAssociatePacketConn) HandshakeFailure(reason error) error {
	c.responseAccess.Lock()
	defer c.responseAccess.Unlock()
	if c.responseWritten.Load() {
		return os.ErrInvalid
	}
	err := socks5.WriteResponse(c.underlying, socks5.Response{
		ReplyCode: socks5.ReplyCodeForError(reason),
	})
	c.responseWritten.Store(true)
	// Closed even when the reply write failed, which is what the previous defer did: the
	// association is being refused, so both halves are torn down either way.
	c.conn.Close()
	c.underlying.Close()
	return err
}

func (c *LazyAssociatePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if !c.responseWritten.Load() {
		err = c.HandshakeSuccess()
		if err != nil {
			return
		}
	}
	return c.AssociatePacketConn.ReadFrom(p)
}

func (c *LazyAssociatePacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if !c.responseWritten.Load() {
		err = c.HandshakeSuccess()
		if err != nil {
			return
		}
	}
	return c.AssociatePacketConn.WriteTo(p, addr)
}

func (c *LazyAssociatePacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	if !c.responseWritten.Load() {
		err = c.HandshakeSuccess()
		if err != nil {
			return
		}
	}
	return c.AssociatePacketConn.ReadPacket(buffer)
}

func (c *LazyAssociatePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if !c.responseWritten.Load() {
		err := c.HandshakeSuccess()
		if err != nil {
			return err
		}
	}
	return c.AssociatePacketConn.WritePacket(buffer, destination)
}

func (c *LazyAssociatePacketConn) Read(p []byte) (n int, err error) {
	if !c.responseWritten.Load() {
		err = c.HandshakeSuccess()
		if err != nil {
			return
		}
	}
	return c.AssociatePacketConn.Read(p)
}

func (c *LazyAssociatePacketConn) Write(p []byte) (n int, err error) {
	if !c.responseWritten.Load() {
		err = c.HandshakeSuccess()
		if err != nil {
			return
		}
	}
	return c.AssociatePacketConn.Write(p)
}

func (c *LazyAssociatePacketConn) ReaderReplaceable() bool {
	return c.responseWritten.Load()
}

func (c *LazyAssociatePacketConn) WriterReplaceable() bool {
	return c.responseWritten.Load()
}

func (c *LazyAssociatePacketConn) Upstream() any {
	return &c.AssociatePacketConn
}
