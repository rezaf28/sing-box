package trojan

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/sagernet/sing-box/common/usermanagement"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/rw"
)

type Handler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

type Service[K comparable] struct {
	users           *usermanagement.UserManager
	protocol        string
	tag             string
	handler         Handler
	fallbackHandler N.TCPConnectionHandlerEx
	logger          logger.ContextLogger
}

func NewService[K comparable](handler Handler, fallbackHandler N.TCPConnectionHandlerEx, logger logger.ContextLogger) *Service[K] {
	return &Service[K]{
		handler:         handler,
		fallbackHandler: fallbackHandler,
		logger:          logger,
	}
}

func (s *Service[K]) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc, protocol, tag string) error {
	var key [KeyLength]byte
	n, err := conn.Read(key[:])
	if err != nil {
		return err
	} else if n != KeyLength {
		return s.fallback(ctx, conn, source, key[:n], E.New("bad request size"), onClose)
	}

	um := usermanagement.GetUserManagerSafe()
	if um.AddIP(protocol, tag, string(key[:]), source.IPAddr().IP.String()) {
		userid, err := um.GetUserId("trojan", string(key[:]))
		if err == nil {
			ctx = auth.ContextWithUser(ctx, userid)
		} else {
			return s.fallback(ctx, conn, source, key[:], E.New("bad request"), onClose)
		}
	}

	err = rw.SkipN(conn, 2)
	if err != nil {
		return E.Cause(err, "skip crlf")
	}

	var command byte
	err = binary.Read(conn, binary.BigEndian, &command)
	if err != nil {
		return E.Cause(err, "read command")
	}

	switch command {
	case CommandTCP, CommandUDP, CommandMux:
	default:
		return E.New("unknown command ", command)
	}

	// var destination M.Socksaddr
	destination, err := M.SocksaddrSerializer.ReadAddrPort(conn)
	if err != nil {
		return E.Cause(err, "read destination")
	}

	err = rw.SkipN(conn, 2)
	if err != nil {
		return E.Cause(err, "skip crlf")
	}

	switch command {
	case CommandTCP:
		s.handler.NewConnectionEx(ctx, conn, source, destination, onClose)
	case CommandUDP:
		s.handler.NewPacketConnectionEx(ctx, &PacketConn{Conn: conn}, source, destination, onClose)
	// case CommandMux:
	default:
		return HandleMuxConnection(ctx, conn, source, s.handler, s.logger, onClose)
	}
	return nil
}

func (s *Service[K]) fallback(ctx context.Context, conn net.Conn, source M.Socksaddr, header []byte, err error, onClose N.CloseHandlerFunc) error {
	if s.fallbackHandler == nil {
		return E.Extend(err, "fallback disabled")
	}
	conn = bufio.NewCachedConn(conn, buf.As(header).ToOwned())
	s.fallbackHandler.NewConnectionEx(ctx, conn, source, M.Socksaddr{}, onClose)
	return nil
}

type PacketConn struct {
	net.Conn
	readWaitOptions N.ReadWaitOptions
}

func (c *PacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	return ReadPacket(c.Conn, buffer)
}

func (c *PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return WritePacket(c.Conn, buffer, destination)
}

func (c *PacketConn) FrontHeadroom() int {
	return M.MaxSocksaddrLength + 4
}

func (c *PacketConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *PacketConn) Upstream() any {
	return c.Conn
}
