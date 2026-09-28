package socks

import (
	std_bufio "bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/varbin"
	"github.com/sagernet/sing/protocol/socks/socks4"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

type HandlerEx interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

type PacketListener interface {
	ListenPacket(listenConfig net.ListenConfig, ctx context.Context, network string, address string) (net.PacketConn, error)
}

func ClientHandshake4(conn io.ReadWriter, command byte, destination M.Socksaddr, username string) (socks4.Response, error) {
	err := socks4.WriteRequest(conn, socks4.Request{
		Command:     command,
		Destination: destination,
		Username:    username,
	})
	if err != nil {
		return socks4.Response{}, err
	}
	response, err := socks4.ReadResponse(varbin.StubReader(conn))
	if err != nil {
		return socks4.Response{}, err
	}
	if response.ReplyCode != socks4.ReplyCodeGranted {
		err = E.New("socks4: request rejected, code= ", response.ReplyCode)
	}
	return response, err
}

// ClientNegotiate5 performs the SOCKS5 greeting and, when the server selects
// username/password authentication, the authentication exchange.
//
// It stops at the point where the connection is authenticated and ready to carry
// a command. Nothing is written after authentication, so the caller may hold the
// connection in that state and send the command later. This is what makes an
// authenticated connection poolable: the expensive part of the handshake can
// happen ahead of the request that needs it.
//
// A SOCKS5 connection carries exactly ONE command. A connection returned by this
// function is therefore single-use: after ClientCommand5 it has become a tunnel
// and must never be returned to a pool or reused for another destination.
//
// reader must be the buffered reader used for the whole connection. The caller
// must reuse the SAME reader for ClientCommand5, because the server's reply may
// already sit in its buffer.
func ClientNegotiate5(conn io.Writer, reader varbin.Reader, username string, password string) error {
	var method byte
	if username == "" {
		method = socks5.AuthTypeNotRequired
	} else {
		method = socks5.AuthTypeUsernamePassword
	}
	err := socks5.WriteAuthRequest(conn, socks5.AuthRequest{
		Methods: []byte{method},
	})
	if err != nil {
		return err
	}
	authResponse, err := socks5.ReadAuthResponse(reader)
	if err != nil {
		return err
	}
	if authResponse.Method == socks5.AuthTypeUsernamePassword {
		err = socks5.WriteUsernamePasswordAuthRequest(conn, socks5.UsernamePasswordAuthRequest{
			Username: username,
			Password: password,
		})
		if err != nil {
			return err
		}
		usernamePasswordResponse, err := socks5.ReadUsernamePasswordAuthResponse(reader)
		if err != nil {
			return err
		}
		if usernamePasswordResponse.Status != socks5.UsernamePasswordStatusSuccess {
			return E.New("socks5: incorrect user name or password")
		}
	} else if authResponse.Method != socks5.AuthTypeNotRequired {
		return E.New("socks5: unsupported auth method: ", authResponse.Method)
	}
	return nil
}

// ClientCommand5 sends a SOCKS5 request for command and reads the reply.
//
// It must be preceded by ClientNegotiate5 on the same connection and reader. See
// that function for the single-use rule.
func ClientCommand5(conn io.Writer, reader varbin.Reader, command byte, destination M.Socksaddr) (socks5.Response, error) {
	if command == socks5.CommandUDPAssociate {
		if destination.Addr.IsPrivate() {
			if destination.Addr.Is6() {
				destination.Addr = netip.AddrFrom4([4]byte{127, 0, 0, 1})
			} else {
				destination.Addr = netip.IPv6Loopback()
			}
		} else if destination.Addr.IsGlobalUnicast() {
			if destination.Addr.Is6() {
				destination.Addr = netip.IPv6Unspecified()
			} else {
				destination.Addr = netip.IPv4Unspecified()
			}
		} else {
			destination.Addr = netip.IPv6Unspecified()
		}
		destination.Port = 0
	}

	err := socks5.WriteRequest(conn, socks5.Request{
		Command:     command,
		Destination: destination,
	})
	if err != nil {
		return socks5.Response{}, err
	}
	response, err := socks5.ReadResponse(reader)
	if err != nil {
		return socks5.Response{}, err
	}
	if response.ReplyCode != socks5.ReplyCodeSuccess {
		err = E.New("socks5: request rejected, code=", response.ReplyCode)
	}
	return response, err
}

// ClientHandshake5 performs the complete SOCKS5 handshake: negotiation,
// authentication and one command.
//
// It is the composition of ClientNegotiate5 and ClientCommand5 and behaves
// exactly as before the split, including the UDP ASSOCIATE address rewriting
// performed by ClientCommand5.
func ClientHandshake5(conn io.ReadWriter, command byte, destination M.Socksaddr, username string, password string) (socks5.Response, error) {
	reader := varbin.StubReader(conn)
	err := ClientNegotiate5(conn, reader, username, password)
	if err != nil {
		return socks5.Response{}, err
	}
	return ClientCommand5(conn, reader, command, destination)
}

func HandleConnectionEx(
	ctx context.Context, conn net.Conn, reader *std_bufio.Reader,
	authenticator *auth.Authenticator,
	handler HandlerEx,
	packetListener PacketListener,
	udpTimeout time.Duration,
	// resolver TorResolver,
	source M.Socksaddr,
	onClose N.CloseHandlerFunc,
) error {
	version, err := reader.ReadByte()
	if err != nil {
		return err
	}
	switch version {
	case socks4.Version:
		var request socks4.Request
		request, err = socks4.ReadRequest0(reader)
		if err != nil {
			return err
		}
		switch request.Command {
		case socks4.CommandConnect:
			if authenticator != nil && !authenticator.Verify(request.Username, "") {
				err = socks4.WriteResponse(conn, socks4.Response{
					ReplyCode: socks4.ReplyCodeRejectedOrFailed,
				})
				if err != nil {
					return err
				}
				return E.New("socks4: authentication failed, username=", request.Username)
			}
			handler.NewConnectionEx(auth.ContextWithUser(ctx, request.Username), NewLazyConn(conn, version), source, request.Destination, onClose)
			return nil
		/*case CommandTorResolve, CommandTorResolvePTR:
		if resolver == nil {
			return E.New("socks4: torsocks: commands not implemented")
		}
		return handleTorSocks4(ctx, conn, request, resolver)*/
		default:
			err = socks4.WriteResponse(conn, socks4.Response{
				ReplyCode: socks4.ReplyCodeRejectedOrFailed,
			})
			if err != nil {
				return err
			}
			return E.New("socks4: unsupported command ", request.Command)
		}
	case socks5.Version:
		var authRequest socks5.AuthRequest
		authRequest, err = socks5.ReadAuthRequest0(reader)
		if err != nil {
			return err
		}
		var authMethod byte
		if authenticator != nil && !common.Contains(authRequest.Methods, socks5.AuthTypeUsernamePassword) {
			err = socks5.WriteAuthResponse(conn, socks5.AuthResponse{
				Method: socks5.AuthTypeNoAcceptedMethods,
			})
			if err != nil {
				return err
			}
		}
		if authenticator != nil {
			authMethod = socks5.AuthTypeUsernamePassword
		} else {
			authMethod = socks5.AuthTypeNotRequired
		}
		err = socks5.WriteAuthResponse(conn, socks5.AuthResponse{
			Method: authMethod,
		})
		if err != nil {
			return err
		}
		if authMethod == socks5.AuthTypeUsernamePassword {
			var usernamePasswordAuthRequest socks5.UsernamePasswordAuthRequest
			usernamePasswordAuthRequest, err = socks5.ReadUsernamePasswordAuthRequest(reader)
			if err != nil {
				return err
			}
			ctx = auth.ContextWithUser(ctx, usernamePasswordAuthRequest.Username)
			response := socks5.UsernamePasswordAuthResponse{}
			if authenticator.Verify(usernamePasswordAuthRequest.Username, usernamePasswordAuthRequest.Password) {
				response.Status = socks5.UsernamePasswordStatusSuccess
			} else {
				response.Status = socks5.UsernamePasswordStatusFailure
			}
			err = socks5.WriteUsernamePasswordAuthResponse(conn, response)
			if err != nil {
				return err
			}
			if response.Status != socks5.UsernamePasswordStatusSuccess {
				return E.New("socks5: authentication failed, username=", usernamePasswordAuthRequest.Username, ", password=", usernamePasswordAuthRequest.Password)
			}
		}
		var request socks5.Request
		request, err = socks5.ReadRequest(reader)
		if err != nil {
			return err
		}
		switch request.Command {
		case socks5.CommandConnect:
			handler.NewConnectionEx(ctx, NewLazyConn(conn, version), source, request.Destination, onClose)
			return nil
		case socks5.CommandUDPAssociate:
			var (
				listenConfig net.ListenConfig
				udpConn      net.PacketConn
			)
			if packetListener != nil {
				udpConn, err = packetListener.ListenPacket(listenConfig, ctx, M.NetworkFromNetAddr("udp", M.AddrFromNet(conn.LocalAddr())), M.SocksaddrFrom(M.AddrFromNet(conn.LocalAddr()), 0).String())
			} else {
				udpConn, err = listenConfig.ListenPacket(ctx, M.NetworkFromNetAddr("udp", M.AddrFromNet(conn.LocalAddr())), M.SocksaddrFrom(M.AddrFromNet(conn.LocalAddr()), 0).String())
			}
			if err != nil {
				return E.Cause(err, "socks5: listen udp")
			}
			err = socks5.WriteResponse(conn, socks5.Response{
				ReplyCode: socks5.ReplyCodeSuccess,
				Bind:      M.SocksaddrFromNet(udpConn.LocalAddr()).Unwrap(),
			})
			if err != nil {
				return E.Cause(err, "socks5: write response")
			}
			serverConn := bufio.NewServerPacketConn(udpConn)
			associateConn := NewAssociatePacketConn(serverConn, M.Socksaddr{}, conn)
			go func() {
				var buffer [1]byte
				_, _ = conn.Read(buffer[:])
				_ = associateConn.Close()
			}()
			var socksPacketConn N.PacketConn = associateConn
			if udpTimeout > 0 {
				udpConn.SetReadDeadline(time.Now().Add(udpTimeout))
			}
			var firstPacket *buf.Buffer
			var destination M.Socksaddr
			readWaiter, hasReadWaiter := bufio.CreatePacketReadWaiter(socksPacketConn)
			if hasReadWaiter {
				readWaiter.InitializeReadWaiter(N.ReadWaitOptions{})
				firstPacket, destination, err = readWaiter.WaitReadPacket()
			} else {
				firstPacket = buf.NewPacket()
				destination, err = socksPacketConn.ReadPacket(firstPacket)
			}
			if err != nil {
				firstPacket.Release()
				_ = socksPacketConn.Close()
				return E.Cause(err, "socks5: read first packet")
			}
			if udpTimeout > 0 {
				udpConn.SetReadDeadline(time.Time{})
			}
			if udpTimeout > 0 {
				ctx, socksPacketConn = canceler.NewPacketConn(ctx, socksPacketConn, udpTimeout)
			}
			socksPacketConn = bufio.NewCachedPacketConn(socksPacketConn, firstPacket, destination)
			handler.NewPacketConnectionEx(ctx, socksPacketConn, M.SocksaddrFromNet(serverConn.RemoteAddr()).Unwrap(), destination, onClose)
			return nil
		/*case CommandTorResolve, CommandTorResolvePTR:
		if resolver == nil {
			return E.New("socks4: torsocks: commands not implemented")
		}
		return handleTorSocks5(ctx, conn, request, resolver)*/
		default:
			err = socks5.WriteResponse(conn, socks5.Response{
				ReplyCode: socks5.ReplyCodeUnsupported,
			})
			if err != nil {
				return err
			}
			return E.New("socks5: unsupported command ", request.Command)
		}
	}
	return os.ErrInvalid
}
