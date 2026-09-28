package socks

import (
	"bufio"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/varbin"
	"github.com/sagernet/sing/protocol/socks/socks5"

	"github.com/stretchr/testify/require"
)

// These tests pin the split introduced for the authenticated preconnect pool:
// ClientHandshake5 must behave exactly as before, and the two halves must be
// usable separately with the SAME reader.
//
// The reader identity matters. A SOCKS5 server may answer the request in the same
// TCP segment as the greeting, so the reply can already sit in the buffered
// reader by the time negotiation returns. A pool that negotiated with one reader
// and issued the command with another would hang until the server's idle timeout.
// The pool therefore keeps one reader for the connection's lifetime, and
// TestNegotiateThenCommandSharesOneReader pins that requirement.

// SOCKS5 ATYP wire values. The socks5 package does not export them because it
// writes them internally through M.Socksaddr.
const (
	addressTypeIPv4   byte = 0x01
	addressTypeIPv6   byte = 0x04
	addressTypeDomain byte = 0x03

	// The username/password sub-negotiation carries its own version byte (RFC 1929),
	// which is 1 - NOT the SOCKS5 version 5.
	usernamePasswordVersion byte = 0x01
)

// scriptedServer accepts one connection and replies according to script, recording
// what it received. It never blocks on a reply the client is not expected to send.
type scriptedServer struct {
	listener net.Listener
	port     uint16

	// received, in order: greeting method list, optional userpass, command byte.
	greeting  []byte
	userpass  []byte
	command   []byte
	requestTo []byte

	// Phase signals. Each is closed once the server has RECORDED the corresponding
	// step, so the test never races the server goroutine and never needs a sleep.
	greetingDone chan struct{}
	authDone     chan struct{}
	commandDone  chan struct{}

	// auth selects the server's chosen method.
	requireAuth bool
	// rejectAuth makes the userpass reply report failure.
	rejectAuth bool
	// commandReply is the reply code sent for the command.
	commandReply byte
}

func newScriptedServer(t *testing.T, s *scriptedServer) *scriptedServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s.listener = listener
	s.port = uint16(listener.Addr().(*net.TCPAddr).Port)
	if s.commandReply == 0 {
		s.commandReply = socks5.ReplyCodeSuccess
	}
	done := make(chan struct{})
	s.greetingDone = make(chan struct{})
	s.authDone = make(chan struct{})
	s.commandDone = make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)

		// greeting: VER, NMETHODS, METHODS...
		header := make([]byte, 2)
		if _, err = io.ReadFull(reader, header); err != nil {
			return
		}
		methods := make([]byte, int(header[1]))
		if _, err = io.ReadFull(reader, methods); err != nil {
			return
		}
		s.greeting = append(append(make([]byte, 0, 2+len(methods)), header[0], header[1]), methods...)
		close(s.greetingDone)

		method := socks5.AuthTypeNotRequired
		if s.requireAuth {
			method = socks5.AuthTypeUsernamePassword
		}
		if _, err = conn.Write([]byte{socks5.Version, method}); err != nil {
			return
		}
		if s.requireAuth {
			// userpass: VER(1), ULEN(1), UNAME, PLEN(1), PASSWD
			// Read the whole exchange into ONE fresh slice so nothing aliases a
			// reused buffer.
			verLen := make([]byte, 2) // VER, ULEN
			if _, err = io.ReadFull(reader, verLen); err != nil {
				return
			}
			uname := make([]byte, int(verLen[1]))
			if _, err = io.ReadFull(reader, uname); err != nil {
				return
			}
			plen := make([]byte, 1)
			if _, err = io.ReadFull(reader, plen); err != nil {
				return
			}
			passwd := make([]byte, int(plen[0]))
			if _, err = io.ReadFull(reader, passwd); err != nil {
				return
			}
			recorded := make([]byte, 0, 4+len(uname)+len(passwd))
			recorded = append(recorded, verLen[0], verLen[1])
			recorded = append(recorded, uname...)
			recorded = append(recorded, plen[0])
			recorded = append(recorded, passwd...)
			s.userpass = recorded
			close(s.authDone)
			status := byte(socks5.UsernamePasswordStatusSuccess)
			if s.rejectAuth {
				status = socks5.UsernamePasswordStatusFailure
			}
			if _, err = conn.Write([]byte{usernamePasswordVersion, status}); err != nil {
				return
			}
			if s.rejectAuth {
				return
			}
		}

		// command: VER, CMD, RSV, ATYP, ADDR, PORT
		cmd := make([]byte, 4)
		if _, err = io.ReadFull(reader, cmd); err != nil {
			return
		}
		s.command = cmd
		var addrLen int
		switch cmd[3] {
		case addressTypeIPv4:
			addrLen = 4
		case addressTypeIPv6:
			addrLen = 16
		case addressTypeDomain:
			domainLen := make([]byte, 1)
			if _, err = io.ReadFull(reader, domainLen); err != nil {
				return
			}
			addrLen = int(domainLen[0])
		}
		rest := make([]byte, addrLen+2)
		if _, err = io.ReadFull(reader, rest); err != nil {
			return
		}
		s.requestTo = rest
		close(s.commandDone)

		reply := []byte{socks5.Version, s.commandReply, 0x00, addressTypeIPv4, 0, 0, 0, 0, 0, 0}
		_, _ = conn.Write(reply)

		// Hold the connection open until the test is finished with it.
		_, _ = io.Copy(io.Discard, reader)
	}()
	t.Cleanup(func() {
		listener.Close()
		<-done
	})
	return s
}

func (s *scriptedServer) address() (string, uint16) { return "127.0.0.1", s.port }

// awaitGreeting blocks until the server has recorded the greeting.
func (s *scriptedServer) awaitGreeting(t *testing.T) {
	t.Helper()
	select {
	case <-s.greetingDone:
	case <-time.After(2 * time.Second):
		t.Fatal("server never received the greeting")
	}
}

// awaitAuth blocks until the server has recorded the username/password exchange.
func (s *scriptedServer) awaitAuth(t *testing.T) {
	t.Helper()
	select {
	case <-s.authDone:
	case <-time.After(2 * time.Second):
		t.Fatal("server never received the credentials")
	}
}

// awaitCommand blocks until the server has recorded the command.
func (s *scriptedServer) awaitCommand(t *testing.T) {
	t.Helper()
	select {
	case <-s.commandDone:
	case <-time.After(2 * time.Second):
		t.Fatal("server never received the command")
	}
}

// authAttempted reports whether the auth phase finished, without blocking.
func (s *scriptedServer) authAttempted() bool {
	select {
	case <-s.authDone:
		return true
	default:
		return false
	}
}

// dialServer opens a connection to the scripted server.
func dialServer(t *testing.T, server *scriptedServer) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(server.port))))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

// TestHandshake5UnchangedBySplit asserts the public entry point still performs
// greeting + authentication + command in a single call, so every existing caller
// sees identical behaviour.
func TestHandshake5UnchangedBySplit(t *testing.T) {
	server := newScriptedServer(t, &scriptedServer{requireAuth: true})
	conn := dialServer(t, server)

	destination := M.ParseSocksaddr("192.0.2.10:443").Unwrap()
	response, err := ClientHandshake5(conn, socks5.CommandConnect, destination, "user", "pass")
	require.NoError(t, err)
	require.Equal(t, byte(socks5.ReplyCodeSuccess), response.ReplyCode)

	server.awaitCommand(t)
	require.Equal(t, []byte{socks5.Version, 1, socks5.AuthTypeUsernamePassword}, server.greeting,
		"a username must advertise exactly the username/password method")
	require.NotEmpty(t, server.userpass, "the credentials must have been sent")
	require.Equal(t, byte(socks5.CommandConnect), server.command[1])
	require.Equal(t, byte(addressTypeIPv4), server.command[3],
		"an IPv4 destination must be encoded as ATYP=IPv4")
}

// TestHandshake5WithoutAuthUnchanged pins the no-credentials path.
func TestHandshake5WithoutAuthUnchanged(t *testing.T) {
	server := newScriptedServer(t, &scriptedServer{requireAuth: false})
	conn := dialServer(t, server)

	_, err := ClientHandshake5(conn, socks5.CommandConnect, M.ParseSocksaddr("192.0.2.10:443").Unwrap(), "", "")
	require.NoError(t, err)

	server.awaitCommand(t)
	require.Equal(t, []byte{socks5.Version, 1, socks5.AuthTypeNotRequired}, server.greeting)
	require.Empty(t, server.userpass, "no credentials may be sent when none are configured")
}

// TestHandshake5RejectsBadCredentialsUnchanged pins the failure path: a rejected
// password is an error and no command is sent.
func TestHandshake5RejectsBadCredentialsUnchanged(t *testing.T) {
	server := newScriptedServer(t, &scriptedServer{requireAuth: true, rejectAuth: true})
	conn := dialServer(t, server)

	_, err := ClientHandshake5(conn, socks5.CommandConnect, M.ParseSocksaddr("192.0.2.10:443").Unwrap(), "user", "wrong")
	require.Error(t, err)
	require.Contains(t, err.Error(), "incorrect user name or password")
	require.Empty(t, server.command, "no command may follow a failed authentication")
}

// TestNegotiateThenCommandSharesOneReader is the pool's correctness requirement.
//
// Negotiation and the command must use the SAME buffered reader, because the
// server's command reply can arrive in the same segment as the authentication
// reply and would otherwise be stranded in the first reader's buffer.
func TestNegotiateThenCommandSharesOneReader(t *testing.T) {
	server := newScriptedServer(t, &scriptedServer{requireAuth: true})
	conn := dialServer(t, server)

	reader := bufio.NewReader(conn)
	require.NoError(t, ClientNegotiate5(conn, varbin.StubReader(reader), "user", "pass"))

	// The pool's whole premise: negotiation completed, and NO command has been sent.
	// Wait for the server to have observed the credentials, so this is an assertion
	// about ordering rather than about scheduling.
	server.awaitAuth(t)
	require.Empty(t, server.command,
		"negotiation must stop before the command is sent")

	response, err := ClientCommand5(conn, varbin.StubReader(reader), socks5.CommandConnect,
		M.ParseSocksaddr("192.0.2.10:443").Unwrap())
	require.NoError(t, err, "the command must succeed on the same reader")
	require.Equal(t, byte(socks5.ReplyCodeSuccess), response.ReplyCode)
	server.awaitCommand(t)
	require.Equal(t, byte(socks5.CommandConnect), server.command[1])
}

// TestSeparateReaderStrandsTheReply is why the pool keeps ONE reader per connection.
//
// A buffered reader may consume more bytes than the logical message it was asked
// for. Here the server writes the authentication reply and the command reply
// together, so the first reader swallows both; a second reader then sees nothing and
// the command would block until the server's idle timeout.
//
// The test asserts the stranding directly on the buffers rather than by waiting for
// a timeout, so it is fast, deterministic, and free of wall-clock dependence.
func TestSeparateReaderStrandsTheReply(t *testing.T) {
	// A buffered reader over a pipe, fed both replies in one write.
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()

	reader := bufio.NewReader(clientSide)
	go func() {
		// Auth reply (VER=1, STATUS=0) immediately followed by a command reply.
		_, _ = serverSide.Write([]byte{
			usernamePasswordVersion, socks5.UsernamePasswordStatusSuccess,
			socks5.Version, socks5.ReplyCodeSuccess, 0x00,
			addressTypeIPv4, 0, 0, 0, 0, 0, 0,
		})
	}()

	// Reading ONLY the two auth bytes leaves the command reply in the buffer.
	authReply := make([]byte, 2)
	_, err := io.ReadFull(reader, authReply)
	require.NoError(t, err)
	require.Equal(t, []byte{usernamePasswordVersion, socks5.UsernamePasswordStatusSuccess}, authReply)

	require.Greater(t, reader.Buffered(), 0,
		"the first reader must have buffered the command reply; if this is zero the "+
			"scenario did not reproduce and the test proves nothing")

	// A fresh reader over the same connection has an empty buffer and cannot see it.
	fresh := bufio.NewReader(clientSide)
	require.Equal(t, 0, fresh.Buffered(),
		"a second reader starts empty, which is exactly why negotiation and the "+
			"command must share one reader")
}

// TestCommandRejectedIsAnErrorWithoutRetry pins that a rejection surfaces to the
// caller; retry policy belongs to the pool, not to the protocol layer.
func TestCommandRejectedIsAnErrorWithoutRetry(t *testing.T) {
	server := newScriptedServer(t, &scriptedServer{commandReply: socks5.ReplyCodeNotAllowed})
	conn := dialServer(t, server)

	_, err := ClientHandshake5(conn, socks5.CommandConnect, M.ParseSocksaddr("192.0.2.10:443").Unwrap(), "", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "request rejected")
}

// TestUDPAssociateRewritingUnchanged guards the address rewriting that lives in the
// command half. It moved during the split, so it is pinned here to prove the move did
// not change it.
//
// The upstream rule is deliberately asymmetric and is reproduced EXACTLY rather than
// "fixed": a private destination becomes the LOOPBACK OF THE OTHER FAMILY, and a
// global-unicast destination becomes the UNSPECIFIED address of its own family. An
// IPv4 private destination therefore becomes ::1, which looks surprising but is the
// behaviour every existing caller already depends on.
func TestUDPAssociateRewritingUnchanged(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		destination string
		wantATYP    byte
		wantTail    []byte
	}{
		{
			name:        "global unicast IPv4 becomes 0.0.0.0:0",
			destination: "198.51.100.7:1234",
			wantATYP:    addressTypeIPv4,
			wantTail:    []byte{0, 0, 0, 0, 0, 0},
		},
		{
			name:        "private IPv4 becomes the IPv6 loopback",
			destination: "10.0.0.5:1234",
			wantATYP:    addressTypeIPv6,
			wantTail:    append(netip.IPv6Loopback().AsSlice(), 0, 0),
		},
		{
			name:        "global unicast IPv6 becomes ::",
			destination: "[2001:db8::1]:1234",
			wantATYP:    addressTypeIPv6,
			wantTail:    append(netip.IPv6Unspecified().AsSlice(), 0, 0),
		},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			server := newScriptedServer(t, &scriptedServer{})
			conn := dialServer(t, server)

			_, err := ClientHandshake5(conn, socks5.CommandUDPAssociate,
				M.ParseSocksaddr(testCase.destination).Unwrap(), "", "")
			require.NoError(t, err)
			server.awaitCommand(t)
			require.Equal(t, byte(socks5.CommandUDPAssociate), server.command[1])
			require.Equal(t, testCase.wantATYP, server.command[3])
			require.Equal(t, testCase.wantTail, server.requestTo,
				"the UDP ASSOCIATE rewrite must be unchanged by the split")
		})
	}
}
