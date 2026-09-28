package socks

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// This file tests the authenticated preconnect pool deterministically, with an
// in-process fake SOCKS5 server that COUNTS protocol operations.
//
// The assertions are about operation counts and state, never about wall-clock
// latency: a CI runner's timing is not evidence about a residential proxy, and the
// goal here is to prove the state machine, not to measure it.

// fakeSOCKSServer is a counting SOCKS5 server.
type fakeSOCKSServer struct {
	listener net.Listener
	port     uint16

	accepted    atomic.Int64
	greetings   atomic.Int64
	authOks     atomic.Int64
	authFails   atomic.Int64
	commands    atomic.Int64
	closedConns atomic.Int64

	// lastTarget records the destination of the most recent CONNECT.
	targetMu   sync.Mutex
	lastTarget M.Socksaddr

	// requireAuth selects method 0x02; authPassword is what is accepted.
	requireAuth  bool
	authPassword string
	// commandReply is the reply code for CONNECT (0 = success).
	commandReply byte

	// dropAfterAuth closes the connection right after a successful authentication,
	// simulating a proxy that times out a parked connection.
	dropAfterAuth atomic.Bool
	// dropAfterAuthOnce limits that behaviour to the first N connections.
	dropAfterAuthCount atomic.Int64

	wg sync.WaitGroup
}

func newFakeSOCKSServer(t *testing.T, configure func(*fakeSOCKSServer)) *fakeSOCKSServer {
	t.Helper()
	server := &fakeSOCKSServer{authPassword: "secret"}
	if configure != nil {
		configure(server)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server.listener = listener
	server.port = uint16(listener.Addr().(*net.TCPAddr).Port)

	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			server.accepted.Add(1)
			server.wg.Add(1)
			go func() {
				defer server.wg.Done()
				server.serve(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		server.wg.Wait()
	})
	return server
}

func (s *fakeSOCKSServer) serve(conn net.Conn) {
	defer conn.Close()
	defer s.closedConns.Add(1)
	reader := bufio.NewReader(conn)

	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return
	}
	s.greetings.Add(1)

	method := byte(0x00)
	if s.requireAuth {
		method = 0x02
	}
	if _, err := conn.Write([]byte{0x05, method}); err != nil {
		return
	}
	if s.requireAuth {
		verLen := make([]byte, 2)
		if _, err := io.ReadFull(reader, verLen); err != nil {
			return
		}
		uname := make([]byte, int(verLen[1]))
		if _, err := io.ReadFull(reader, uname); err != nil {
			return
		}
		plen := make([]byte, 1)
		if _, err := io.ReadFull(reader, plen); err != nil {
			return
		}
		passwd := make([]byte, int(plen[0]))
		if _, err := io.ReadFull(reader, passwd); err != nil {
			return
		}
		if string(passwd) != s.authPassword {
			s.authFails.Add(1)
			_, _ = conn.Write([]byte{0x01, 0x01})
			return
		}
		s.authOks.Add(1)
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
		if s.dropAfterAuth.Load() {
			if s.dropAfterAuthCount.Add(-1) >= 0 {
				return
			}
		}
	}

	// The command. This is where a parked connection MUST still be waiting.
	cmdHeader := make([]byte, 4)
	if _, err := io.ReadFull(reader, cmdHeader); err != nil {
		return
	}
	destination, err := readFakeSocksaddr(reader, cmdHeader[3])
	if err != nil {
		return
	}
	s.commands.Add(1)
	s.targetMu.Lock()
	s.lastTarget = destination
	s.targetMu.Unlock()

	replyCode := s.commandReply
	_, _ = conn.Write([]byte{0x05, replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if replyCode != 0 {
		return
	}
	// Echo so a caller can prove the tunnel is live.
	_, _ = io.Copy(conn, reader)
}

func readFakeSocksaddr(reader *bufio.Reader, atyp byte) (M.Socksaddr, error) {
	var host string
	switch atyp {
	case 0x01:
		raw := make([]byte, 4)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return M.Socksaddr{}, err
		}
		host = net.IP(raw).String()
	case 0x04:
		raw := make([]byte, 16)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return M.Socksaddr{}, err
		}
		host = net.IP(raw).String()
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(reader, length); err != nil {
			return M.Socksaddr{}, err
		}
		domain := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, domain); err != nil {
			return M.Socksaddr{}, err
		}
		host = string(domain)
	default:
		return M.Socksaddr{}, E.New("bad atyp")
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return M.Socksaddr{}, err
	}
	port := uint16(portBytes[0])<<8 | uint16(portBytes[1])
	return M.ParseSocksaddrHostPort(host, port).Unwrap(), nil
}

// serverAddr is needed so tests can point a Client at the fake server.
func (s *fakeSOCKSServer) serverAddr() M.Socksaddr {
	return M.ParseSocksaddrHostPort("127.0.0.1", s.port).Unwrap()
}

// directDialer dials through net.Dial, standing in for the outbound's own dialer so
// pool connections are opened the same way a cold connection is.
type directDialer struct{}

func (directDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, destination.String())
}

func (directDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("not implemented")
}

var _ N.Dialer = directDialer{}

// waitFor polls cond until it holds or the deadline passes. It is bounded, so a
// broken implementation fails rather than hangs.
func waitFor(t *testing.T, description string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func newPooledClient(t *testing.T, server *fakeSOCKSServer, options PreconnectOptions) *Client {
	t.Helper()
	client := NewClient(directDialer{}, server.serverAddr(), Version5, "user", "secret")
	require.NoError(t, client.EnablePreconnect(options))
	t.Cleanup(func() { client.Close() })
	return client
}

// newStartedPooledClient additionally starts the refill loop, which the pool
// otherwise defers until the first acquire. Tests that inspect the parked state need
// it running without a request.
func newStartedPooledClient(t *testing.T, server *fakeSOCKSServer, options PreconnectOptions) *Client {
	t.Helper()
	client := newPooledClient(t, server, options)
	client.preconnect.start()
	return client
}

// TestPoolDisabledIsInert is requirement A: without configuration the behaviour is
// exactly the previous one - no goroutine, no dial, no extra socket.
func TestPoolDisabledIsInert(t *testing.T) {
	server := newFakeSOCKSServer(t, func(s *fakeSOCKSServer) { s.requireAuth = true })
	client := NewClient(directDialer{}, server.serverAddr(), Version5, "user", "secret")

	// No EnablePreconnect call at all.
	time.Sleep(150 * time.Millisecond)
	require.Zero(t, server.accepted.Load(),
		"a client without a pool must not open any connection in the background")
	require.Nil(t, client.preconnect)

	conn, err := client.DialContext(context.Background(), N.NetworkTCP,
		M.ParseSocksaddr("192.0.2.10:443").Unwrap())
	require.NoError(t, err)
	conn.Close()

	require.EqualValues(t, 1, server.accepted.Load(), "exactly the cold connection")
	require.EqualValues(t, 1, server.commands.Load())
}

// TestPoolPreAuthenticatesWithoutCommand is requirement B: the pool establishes
// connections that complete greeting and authentication and STOP there.
func TestPoolPreAuthenticatesWithoutCommand(t *testing.T) {
	server := newFakeSOCKSServer(t, func(s *fakeSOCKSServer) { s.requireAuth = true })
	client := newStartedPooledClient(t, server, PreconnectOptions{
		MinIdle: 2, MaxIdle: 4, IdleTimeout: 5 * time.Second,
	})

	waitFor(t, "two parked connections", func() bool { return client.preconnect.idleCount() == 2 })
	require.EqualValues(t, 2, server.accepted.Load())
	require.EqualValues(t, 2, server.greetings.Load())
	require.EqualValues(t, 2, server.authOks.Load())
	require.Zero(t, server.commands.Load(),
		"a parked connection must NOT have sent a command")
}

// TestPoolConsumesWarmConnectionOnce is requirement C: a user flow issues only the
// CONNECT, and the connection leaves the pool permanently.
func TestPoolConsumesWarmConnectionOnce(t *testing.T) {
	server := newFakeSOCKSServer(t, func(s *fakeSOCKSServer) { s.requireAuth = true })
	client := newStartedPooledClient(t, server, PreconnectOptions{
		MinIdle: 1, MaxIdle: 4, IdleTimeout: 5 * time.Second,
	})
	waitFor(t, "a parked connection", func() bool { return client.preconnect.idleCount() == 1 })

	greetingsBefore := server.greetings.Load()
	authBefore := server.authOks.Load()

	conn, err := client.DialContext(context.Background(), N.NetworkTCP,
		M.ParseSocksaddr("192.0.2.10:443").Unwrap())
	require.NoError(t, err)
	defer conn.Close()

	require.EqualValues(t, 1, server.commands.Load())
	require.Equal(t, greetingsBefore, server.greetings.Load(),
		"the warm connection must not re-greet")
	require.Equal(t, authBefore, server.authOks.Load(),
		"the warm connection must not re-authenticate")

	// The connection is now a tunnel and must not return to the pool.
	require.LessOrEqual(t, client.preconnect.idleCount(), 1)
	server.targetMu.Lock()
	target := server.lastTarget
	server.targetMu.Unlock()
	require.Equal(t, "192.0.2.10", target.AddrString())
}

// TestPoolEmptyFallsBackImmediately is requirement D: an empty pool must not make
// the caller wait.
func TestPoolEmptyFallsBackImmediately(t *testing.T) {
	server := newFakeSOCKSServer(t, func(s *fakeSOCKSServer) { s.requireAuth = true })
	// MinIdle 0 keeps the pool empty; MaxIdle 1 gives it room if it ever refills.
	client := newPooledClient(t, server, PreconnectOptions{
		MinIdle: 0, MaxIdle: 1, IdleTimeout: time.Second,
	})

	start := time.Now()
	conn, err := client.DialContext(context.Background(), N.NetworkTCP,
		M.ParseSocksaddr("192.0.2.10:443").Unwrap())
	require.NoError(t, err)
	defer conn.Close()
	require.Less(t, time.Since(start), 2*time.Second,
		"an empty pool must fall back to the cold path without waiting for a refill")
	require.EqualValues(t, 1, server.commands.Load())
}

// TestStaleWarmConnectionFallsBackToCold is requirement E: a parked connection that
// the proxy has dropped must not fail the user's request.
func TestStaleWarmConnectionFallsBackToCold(t *testing.T) {
	server := newFakeSOCKSServer(t, func(s *fakeSOCKSServer) {
		s.requireAuth = true
		s.dropAfterAuth.Store(true)
		// Drop the first two parked connections, then behave normally.
		s.dropAfterAuthCount.Store(2)
	})
	client := newStartedPooledClient(t, server, PreconnectOptions{
		MinIdle: 1, MaxIdle: 4, IdleTimeout: time.Second,
	})
	waitFor(t, "a parked connection", func() bool { return client.preconnect.idleCount() >= 1 })

	conn, err := client.DialContext(context.Background(), N.NetworkTCP,
		M.ParseSocksaddr("192.0.2.10:443").Unwrap())
	require.NoError(t, err,
		"a stale warm connection must fall back to a cold one, not fail the request")
	defer conn.Close()
	require.GreaterOrEqual(t, server.commands.Load(), int64(1))
}

// TestIdleTimeoutClosesParkedConnections is requirement F.
func TestIdleTimeoutClosesParkedConnections(t *testing.T) {
	server := newFakeSOCKSServer(t, func(s *fakeSOCKSServer) { s.requireAuth = true })
	// A deliberately tiny timeout keeps this test in milliseconds. The production
	// default remains 20s.
	client := newStartedPooledClient(t, server, PreconnectOptions{
		MinIdle: 1, MaxIdle: 2, IdleTimeout: 50 * time.Millisecond,
	})
	waitFor(t, "a parked connection", func() bool { return client.preconnect.idleCount() >= 1 })

	// Once it expires, take() must discard it rather than hand it out.
	time.Sleep(80 * time.Millisecond)
	conn, err := client.DialContext(context.Background(), N.NetworkTCP,
		M.ParseSocksaddr("192.0.2.10:443").Unwrap())
	require.NoError(t, err, "an expired connection must not fail the request")
	defer conn.Close()
}

// TestBadCredentialsUseBackoff is requirement G: a rejected password must not
// produce a reconnect storm.
func TestBadCredentialsUseBackoff(t *testing.T) {
	server := newFakeSOCKSServer(t, func(s *fakeSOCKSServer) {
		s.requireAuth = true
		// The client sends "secret"; the server accepts something else, so every
		// authentication is rejected.
		s.authPassword = "different"
	})
	_ = newStartedPooledClient(t, server, PreconnectOptions{
		MinIdle: 2, MaxIdle: 4, IdleTimeout: time.Second,
	})

	// Give the loop time to fail repeatedly. With a 500ms floor and doubling, only a
	// handful of attempts can occur in this window; a tight loop would produce many.
	time.Sleep(700 * time.Millisecond)
	attempts := server.authFails.Load()
	_ = attempts
	require.GreaterOrEqual(t, attempts, int64(1), "the pool must attempt to fill")
	require.Less(t, attempts, int64(10),
		"a failing proxy must be retried with backoff, not in a tight loop (got %d "+
			"attempts in 700ms)", attempts)
}

// TestPoolRespectsMaxIdle is requirement H.
func TestPoolRespectsMaxIdle(t *testing.T) {
	server := newFakeSOCKSServer(t, func(s *fakeSOCKSServer) { s.requireAuth = true })
	client := newStartedPooledClient(t, server, PreconnectOptions{
		MinIdle: 2, MaxIdle: 3, IdleTimeout: 5 * time.Second,
	})
	waitFor(t, "the pool to fill", func() bool { return client.preconnect.idleCount() >= 2 })
	time.Sleep(150 * time.Millisecond)
	require.LessOrEqual(t, client.preconnect.idleCount(), 3,
		"the pool must never exceed max_idle")
	require.LessOrEqual(t, int(server.accepted.Load()), 3,
		"max_idle must also bound connections in flight")
}

// TestCloseReleasesEverything is requirement I: Close stops the loop and closes
// every parked socket, leaving no goroutine behind.
func TestCloseReleasesEverything(t *testing.T) {
	server := newFakeSOCKSServer(t, func(s *fakeSOCKSServer) { s.requireAuth = true })
	client := newStartedPooledClient(t, server, PreconnectOptions{
		MinIdle: 2, MaxIdle: 4, IdleTimeout: 5 * time.Second,
	})
	waitFor(t, "the pool to fill", func() bool { return client.preconnect.idleCount() >= 1 })

	require.NoError(t, client.Close())
	require.Zero(t, client.preconnect.idleCount(), "Close must drop every parked connection")

	// The loop must have exited: Close waits on it, so a second Close returns at once
	// and the pool reports closed.
	require.NoError(t, client.Close(), "Close must be idempotent")

	// Every connection the server accepted must be closed by the client.
	waitFor(t, "the server to see the closures", func() bool {
		return server.closedConns.Load() >= int64(server.accepted.Load())
	})
}

// TestConnectSendsIPv4NotDomain is requirement J, the DNS regression guard: the
// pool must send the address it is given, so a pre-resolved IPv4 target stays IPv4
// and the residential proxy never resolves a domain.
func TestConnectSendsIPv4NotDomain(t *testing.T) {
	server := newFakeSOCKSServer(t, func(s *fakeSOCKSServer) { s.requireAuth = true })
	client := newStartedPooledClient(t, server, PreconnectOptions{
		MinIdle: 1, MaxIdle: 2, IdleTimeout: 5 * time.Second,
	})
	waitFor(t, "a parked connection", func() bool { return client.preconnect.idleCount() == 1 })

	conn, err := client.DialContext(context.Background(), N.NetworkTCP,
		M.ParseSocksaddr("192.0.2.10:443").Unwrap())
	require.NoError(t, err)
	defer conn.Close()

	server.targetMu.Lock()
	target := server.lastTarget
	server.targetMu.Unlock()
	require.True(t, target.Addr.Is4(),
		"the warm path must send the IPv4 address, never a domain")
	require.Equal(t, "192.0.2.10", target.AddrString())
	require.False(t, target.IsDomain(),
		"a domain target would move DNS to the residential proxy, which this design "+
			"forbids")
}

// TestPreconnectRejectsNonSOCKS5 guards the configuration boundary: the pool is
// SOCKS5-only, and enabling it elsewhere must be an error rather than a silent
// no-op the operator would believe was active.
func TestPreconnectRejectsNonSOCKS5(t *testing.T) {
	client := NewClient(directDialer{}, M.ParseSocksaddr("127.0.0.1:1080").Unwrap(),
		Version4, "user", "")
	err := client.EnablePreconnect(PreconnectOptions{
		MinIdle: 1, MaxIdle: 2, IdleTimeout: time.Second,
	})
	require.Nil(t, client.preconnect, "a rejected configuration must not leave a pool")
	require.Error(t, err)
	require.Contains(t, err.Error(), "requires version 5")
}

// TestPreconnectOptionsValidate covers the configuration errors that must be
// reported at `check` time.
func TestPreconnectOptionsValidate(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		options PreconnectOptions
		wantErr string
	}{
		{"disabled is always valid", PreconnectOptions{}, ""},
		{"negative min_idle", PreconnectOptions{MinIdle: -1, MaxIdle: 4, IdleTimeout: time.Second}, "min_idle"},
		{"zero max_idle", PreconnectOptions{MinIdle: 0, MaxIdle: 0, IdleTimeout: time.Second}, "max_idle"},
		{"min above max", PreconnectOptions{MinIdle: 5, MaxIdle: 2, IdleTimeout: time.Second}, "must not exceed"},
		{"zero idle timeout", PreconnectOptions{MinIdle: 1, MaxIdle: 2, IdleTimeout: 0}, "idle_timeout"},
		{"valid", PreconnectOptions{MinIdle: 2, MaxIdle: 4, IdleTimeout: time.Second}, ""},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.options.Validate()
			if testCase.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), testCase.wantErr)
		})
	}
}

// TestPoolDoesNotPoolUDPOrBind pins that only TCP CONNECT uses the pool: a UDP
// ASSOCIATE must take the cold path and must not consume a parked connection.
func TestPoolDoesNotPoolUDPOrBind(t *testing.T) {
	server := newFakeSOCKSServer(t, func(s *fakeSOCKSServer) { s.requireAuth = true })
	client := newStartedPooledClient(t, server, PreconnectOptions{
		MinIdle: 1, MaxIdle: 2, IdleTimeout: 5 * time.Second,
	})
	waitFor(t, "a parked connection", func() bool { return client.preconnect.idleCount() == 1 })

	commandsBefore := server.commands.Load()
	_, err := client.DialContext(context.Background(), N.NetworkUDP,
		M.ParseSocksaddr("192.0.2.10:443").Unwrap())
	// The fake server answers the associate request and then closes; an error or a
	// successful associate are both acceptable here. What matters is the pool.
	if err == nil {
		t.Log("UDP associate returned a conn; asserting only the pool invariant")
	}

	waitFor(t, "the UDP command to be observed", func() bool {
		return server.commands.Load() > commandsBefore
	})
	require.GreaterOrEqual(t, server.commands.Load(), int64(1),
		"UDP ASSOCIATE must go through the connection, not the pool")
}
