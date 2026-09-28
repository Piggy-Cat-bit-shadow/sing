package socks

import (
	"context"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks/socks4"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

type Version uint8

const (
	Version4 Version = iota
	Version4A
	Version5
)

func (v Version) String() string {
	switch v {
	case Version4:
		return "4"
	case Version4A:
		return "4a"
	case Version5:
		return "5"
	default:
		return "unknown"
	}
}

func ParseVersion(version string) (Version, error) {
	switch version {
	case "4":
		return Version4, nil
	case "4a":
		return Version4A, nil
	case "5":
		return Version5, nil
	}
	return 0, E.New("unknown socks version: ", version)
}

var _ N.Dialer = (*Client)(nil)

type Client struct {
	version    Version
	dialer     N.Dialer
	serverAddr M.Socksaddr
	username   string
	password   string
	preconnect *preconnectPool
}

func NewClient(dialer N.Dialer, serverAddr M.Socksaddr, version Version, username string, password string) *Client {
	return &Client{
		version:    version,
		dialer:     dialer,
		serverAddr: serverAddr,
		username:   username,
		password:   password,
	}
}

// EnablePreconnect attaches an authenticated idle connection pool.
//
// It is only valid for SOCKS5 TCP CONNECT. The pool is opt-in: a caller that never
// invokes this keeps the previous behaviour exactly, including starting no
// goroutine and opening no extra socket.
//
// The pool must be closed by the owner, typically from the outbound's Close.
func (c *Client) EnablePreconnect(options PreconnectOptions) error {
	if err := options.Validate(); err != nil {
		return err
	}
	if c.version != Version5 {
		return E.New("socks: tcp_preconnect requires version 5, got ", c.version)
	}
	c.preconnect = newPreconnectPool(c, options)
	return nil
}

// Close stops the preconnect pool, if any.
func (c *Client) Close() error {
	if c.preconnect != nil {
		return c.preconnect.Close()
	}
	return nil
}

func NewClientFromURL(dialer N.Dialer, rawURL string) (*Client, error) {
	var client Client
	if !strings.Contains(rawURL, "://") {
		rawURL = "socks://" + rawURL
	}
	proxyURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	client.dialer = dialer
	client.serverAddr = M.ParseSocksaddr(proxyURL.Host)
	switch proxyURL.Scheme {
	case "socks4":
		client.version = Version4
	case "socks4a":
		client.version = Version4A
	case "socks", "socks5", "":
		client.version = Version5
	default:
		return nil, E.New("socks: unknown scheme: ", proxyURL.Scheme)
	}
	if proxyURL.User != nil {
		if client.version == Version5 {
			client.username = proxyURL.User.Username()
			client.password, _ = proxyURL.User.Password()
		} else {
			client.username = proxyURL.User.String()
		}
	}
	return &client, nil
}

func (c *Client) DialContext(ctx context.Context, network string, address M.Socksaddr) (result net.Conn, err error) {
	network = N.NetworkName(network)
	var command byte
	switch network {
	case N.NetworkTCP:
		command = socks4.CommandConnect
	case N.NetworkUDP:
		if c.version != Version5 {
			return nil, E.New("socks4: udp unsupported")
		}
		command = socks5.CommandUDPAssociate
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	// A warm, already-authenticated connection moves greeting and authentication off
	// this request's critical path. It is used ONLY for a TCP CONNECT: every other
	// command (UDP ASSOCIATE, BIND) keeps the cold path, because the pool is defined
	// for TCP CONNECT alone.
	//
	// A warm connection can be stale - the proxy's idle timeout, a NAT rebind, a
	// server reset - so a failure BEFORE the command is accepted falls back to
	// exactly one cold attempt. A warm failure must never become a user-visible
	// failure when a cold connection would have worked.
	if c.preconnect != nil && command == socks5.CommandConnect {
		if warm := c.preconnect.acquire(); warm != nil {
			warmResult, warmErr := c.preconnect.commandOnWarm(warm, command, address)
			if warmErr == nil {
				return warmResult, nil
			}
			// Exactly one cold retry follows; never a loop.
		}
	}
	tcpConn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.serverAddr)
	if err != nil {
		return nil, err
	}
	if ctx.Done() != nil {
		handshakeConn := tcpConn
		stopContext := context.AfterFunc(ctx, func() {
			_ = handshakeConn.Close()
		})
		defer func() {
			if !stopContext() {
				common.Close(result)
				result = nil
				err = ctx.Err()
			}
		}()
	}
	if c.version == Version4 && address.IsDomain() {
		var tcpAddr *net.TCPAddr
		tcpAddr, err = net.ResolveTCPAddr(network, address.String())
		if err != nil {
			tcpConn.Close()
			return nil, err
		}
		address = M.SocksaddrFromNet(tcpAddr)
	}
	switch c.version {
	case Version4, Version4A:
		_, err = ClientHandshake4(tcpConn, command, address, c.username)
		if err != nil {
			tcpConn.Close()
			return nil, err
		}
		return tcpConn, nil
	case Version5:
		var response socks5.Response
		response, err = ClientHandshake5(tcpConn, command, address, c.username, c.password)
		if err != nil {
			tcpConn.Close()
			return nil, err
		}
		if command == socks5.CommandConnect {
			return tcpConn, nil
		}
		var udpConn net.Conn
		udpConn, err = c.dialer.DialContext(ctx, N.NetworkUDP, response.Bind)
		if err != nil {
			tcpConn.Close()
			return nil, err
		}
		return NewAssociatePacketConn(udpConn, address, tcpConn), nil
	}
	_ = tcpConn.Close()
	return nil, os.ErrInvalid
}

func (c *Client) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := c.DialContext(ctx, N.NetworkUDP, destination)
	if err != nil {
		return nil, err
	}
	return conn.(*AssociatePacketConn), nil
}

func (c *Client) BindContext(ctx context.Context, address M.Socksaddr) (net.Conn, error) {
	tcpConn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.serverAddr)
	if err != nil {
		return nil, err
	}
	switch c.version {
	case Version4, Version4A:
		_, err = ClientHandshake4(tcpConn, socks4.CommandBind, address, c.username)
		if err != nil {
			tcpConn.Close()
			return nil, err
		}
		return tcpConn, nil
	case Version5:
		_, err = ClientHandshake5(tcpConn, socks5.CommandBind, address, c.username, c.password)
		if err != nil {
			tcpConn.Close()
			return nil, err
		}
		return tcpConn, nil
	}
	_ = tcpConn.Close()
	return nil, os.ErrInvalid
}
