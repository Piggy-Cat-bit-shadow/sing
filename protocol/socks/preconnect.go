package socks

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/varbin"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

// PreconnectOptions configures the authenticated idle connection pool.
//
// The pool exists to move SOCKS5 TCP setup and authentication off the critical path
// of a user request. With it enabled, connections are dialled and authenticated
// ahead of time and parked in the state "greeting done, credentials accepted,
// waiting for a command". A user flow then takes one and issues only its CONNECT.
//
// Zero value / nil means DISABLED. A disabled pool starts no goroutine, dials
// nothing, holds no socket and does not alter the handshake in any way.
type PreconnectOptions struct {
	// MinIdle is the number of authenticated connections the pool tries to keep
	// parked. The pool refills towards this value, never towards MaxIdle.
	MinIdle int
	// MaxIdle bounds the number of parked connections, including those still being
	// established. Without it a burst of refills could exceed the intended pool.
	MaxIdle int
	// IdleTimeout closes a parked connection that has waited this long. It is the
	// pool's only health mechanism: no ping is ever written and no read is issued,
	// because after authentication the next frame MUST be a command request.
	IdleTimeout time.Duration
}

func (o PreconnectOptions) enabled() bool {
	return o.MinIdle > 0 || o.MaxIdle > 0 || o.IdleTimeout > 0
}

// Validate reports configuration errors. It is exported so the config layer can
// reject a bad pool at `check` time instead of silently ignoring it.
func (o PreconnectOptions) Validate() error {
	if !o.enabled() {
		return nil
	}
	if o.MinIdle < 0 {
		return E.New("socks: tcp_preconnect min_idle must not be negative: ", o.MinIdle)
	}
	if o.MaxIdle <= 0 {
		return E.New("socks: tcp_preconnect max_idle must be positive: ", o.MaxIdle)
	}
	if o.MinIdle > o.MaxIdle {
		return E.New("socks: tcp_preconnect min_idle (", o.MinIdle,
			") must not exceed max_idle (", o.MaxIdle, ")")
	}
	if o.IdleTimeout <= 0 {
		return E.New("socks: tcp_preconnect idle_timeout must be positive: ", o.IdleTimeout)
	}
	return nil
}

// authenticatedConn is a SOCKS5 connection that has completed negotiation and
// authentication and is parked before its command.
//
// It is SINGLE-USE. Once handed to ClientCommand5 the connection has become a
// tunnel and must never be returned to the pool: a SOCKS5 connection carries
// exactly one command.
type authenticatedConn struct {
	conn   net.Conn
	reader *bufio.Reader
	idleAt time.Time
}

// preconnectPool maintains a small set of authenticated idle SOCKS5 connections.
//
// Lifecycle: created disabled or enabled, started lazily on first use, and stopped
// by Close. Close cancels the refill loop and closes every parked connection, so a
// sing-box reload cannot leave goroutines or sockets behind.
type preconnectPool struct {
	client  *Client
	options PreconnectOptions

	mu      sync.Mutex
	idle    []*authenticatedConn
	closed  bool
	pending int // connections being established, counted against MaxIdle

	startOnce sync.Once
	cancel    context.CancelFunc
	done      chan struct{}
	refill    chan struct{}

	// dial is separated for tests. It must go through the caller's dialer, so every
	// existing DialerOptions (bind_interface, routing_mark, netns, timeouts, detour,
	// socket control, interface selection) apply to pool connections exactly as they
	// do to a cold one.
	dial func(ctx context.Context) (*authenticatedConn, error)
}

const (
	// DefaultPreconnectMinIdle and friends are the conservative defaults used when
	// the operator enables the pool but omits parameters.
	DefaultPreconnectMinIdle     = 2
	DefaultPreconnectMaxIdle     = 4
	DefaultPreconnectIdleTimeout = 20 * time.Second

	// preconnectBackoffMin/Max bound the refill retry delay. Without a bound a
	// residential proxy that is down or rejecting credentials would be retried in a
	// tight loop: log storm, TCP flood, auth flood.
	preconnectBackoffMin = 500 * time.Millisecond
	preconnectBackoffMax = 30 * time.Second
)

func newPreconnectPool(client *Client, options PreconnectOptions) *preconnectPool {
	pool := &preconnectPool{
		client:  client,
		options: options,
		done:    make(chan struct{}),
		refill:  make(chan struct{}, 1),
	}
	pool.dial = pool.dialAndAuthenticate
	return pool
}

// dialAndAuthenticate opens a connection through the client's own dialer and takes
// it exactly as far as "authenticated", stopping before any command.
func (p *preconnectPool) dialAndAuthenticate(ctx context.Context) (*authenticatedConn, error) {
	tcpConn, err := p.client.dialer.DialContext(ctx, N.NetworkTCP, p.client.serverAddr)
	if err != nil {
		return nil, err
	}
	reader := bufio.NewReader(tcpConn)
	if err = ClientNegotiate5(tcpConn, varbin.StubReader(reader), p.client.username, p.client.password); err != nil {
		tcpConn.Close()
		return nil, err
	}
	// Any deadline the dialer or context imposed must not leak into the parked
	// state, or an idle connection would be killed by a timer set for a request
	// that has long since finished. The pool manages lifetime through IdleTimeout.
	if err = tcpConn.SetDeadline(time.Time{}); err != nil {
		tcpConn.Close()
		return nil, err
	}
	return &authenticatedConn{conn: tcpConn, reader: reader, idleAt: time.Now()}, nil
}

// take returns a parked connection, or nil when none is available.
//
// It NEVER blocks and never waits for a refill: a caller with no warm connection
// must fall back to the cold path immediately, so an empty pool can never become a
// latency source. It also discards connections whose idle lifetime has expired.
func (p *preconnectPool) take() *authenticatedConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	now := time.Now()
	for len(p.idle) > 0 {
		candidate := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		if now.Sub(candidate.idleAt) >= p.options.IdleTimeout {
			// Expired: close it rather than hand a stale socket to a caller.
			candidate.conn.Close()
			continue
		}
		p.requestRefillLocked()
		return candidate
	}
	return nil
}

// put returns a connection to the pool.
//
// It exists only for connections that did NOT reach a command, i.e. a refill that
// finished after the pool was closed. A connection that has carried a command must
// never be passed here.
func (p *preconnectPool) put(conn *authenticatedConn) {
	p.mu.Lock()
	if p.closed || len(p.idle) >= p.options.MaxIdle {
		p.mu.Unlock()
		conn.conn.Close()
		return
	}
	p.idle = append(p.idle, conn)
	p.mu.Unlock()
}

// discard closes a connection that must not be reused.
func (p *preconnectPool) discard(conn *authenticatedConn) {
	if conn != nil {
		conn.conn.Close()
	}
}

// start launches the refill loop once. Calling it more than once is safe.
func (p *preconnectPool) start() {
	p.startOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		p.cancel = cancel
		go p.loop(ctx)
	})
}

// Close stops the pool and closes every parked connection. It is idempotent.
func (p *preconnectPool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	parked := p.idle
	p.idle = nil
	cancel := p.cancel
	p.mu.Unlock()

	if cancel != nil {
		cancel()
		<-p.done
	}
	for _, conn := range parked {
		conn.conn.Close()
	}
	return nil
}

// requestRefillLocked nudges the loop. Must be called with the lock held.
func (p *preconnectPool) requestRefillLocked() {
	select {
	case p.refill <- struct{}{}:
	default:
	}
}

// loop maintains MinIdle authenticated connections until the context is cancelled.
func (p *preconnectPool) loop(ctx context.Context) {
	defer close(p.done)
	// Refill once immediately so the pool is warm without waiting for a consumer.
	p.requestRefillLocked()
	backoff := preconnectBackoffMin
	var timer *time.Timer
	var timerC <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-p.refill:
		case <-timerC:
			timerC = nil
		}
		established := false
		for p.needsRefill(ctx) {
			conn, err := p.dial(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				// Bounded backoff: a proxy that is down, refusing credentials or
				// unreachable must not be retried in a tight loop.
				p.releasePending()
				if timer == nil {
					timer = time.NewTimer(backoff)
				} else {
					timer.Reset(backoff)
				}
				timerC = timer.C
				backoff *= 2
				if backoff > preconnectBackoffMax {
					backoff = preconnectBackoffMax
				}
				break
			}
			backoff = preconnectBackoffMin
			established = true
			p.releasePending()
			p.put(conn)
		}
		if !established && timerC == nil {
			// Nothing to do; wait for the next nudge.
		}
	}
}

// needsRefill reports whether another connection should be established, reserving a
// slot against MaxIdle so concurrent refills cannot exceed it.
func (p *preconnectPool) needsRefill(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	if len(p.idle)+p.pending >= p.options.MaxIdle {
		return false
	}
	if len(p.idle)+p.pending >= p.options.MinIdle {
		return false
	}
	p.pending++
	return true
}

func (p *preconnectPool) releasePending() {
	p.mu.Lock()
	if p.pending > 0 {
		p.pending--
	}
	p.mu.Unlock()
}

// acquire returns an authenticated connection for a TCP CONNECT, or nil to signal
// that the caller must use the cold path.
func (p *preconnectPool) acquire() *authenticatedConn {
	if p == nil {
		return nil
	}
	p.start()
	return p.take()
}

// idleCount reports the number of parked connections. Test-only helper.
func (p *preconnectPool) idleCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.idle)
}

// commandOnWarm issues the command on an authenticated connection, reporting
// whether the caller should fall back to a cold connection.
//
// A warm connection can be stale for many reasons - the proxy's idle timeout, a NAT
// rebind, a server reset, a broken path - so a failure BEFORE the command is
// accepted closes the connection and asks for exactly one cold retry. A failure
// after acceptance is not retried, because the command has already had an effect
// and retrying could duplicate it.
func (p *preconnectPool) commandOnWarm(warm *authenticatedConn, command byte, destination M.Socksaddr) (net.Conn, error) {
	response, err := ClientCommand5(warm.conn, varbin.StubReader(warm.reader), command, destination)
	if err != nil {
		p.discard(warm)
		return nil, err
	}
	if response.ReplyCode != socks5.ReplyCodeSuccess {
		p.discard(warm)
		return nil, E.New("socks5: request rejected, code=", response.ReplyCode)
	}
	// The reader may already hold the first bytes the proxy sent after the reply;
	// they belong to the tunnel, so hand the caller the same reader.
	return &warmConn{Conn: warm.conn, reader: warm.reader}, nil
}

// warmConn carries the buffered reader alongside the connection so bytes already
// read past the SOCKS reply are not lost. This mirrors what the cold path does
// with the reader it creates during the handshake.
type warmConn struct {
	net.Conn
	reader io.Reader
}

func (c *warmConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
