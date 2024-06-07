package trojan

import (
	"context"
	"github.com/sagernet/sing-box/common/usermanagement"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"net"

	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/rw"
)

type Handler interface {
	N.TCPConnectionHandler
	N.UDPConnectionHandler
	E.Handler
}

type Service[K comparable] struct {
	users           *usermanagement.UserManager
	protocol        string
	tag             string
	handler         Handler
	fallbackHandler N.TCPConnectionHandler
}

func NewService[K comparable](handler Handler, fallbackHandler N.TCPConnectionHandler) *Service[K] {
	return &Service[K]{
		handler:         handler,
		fallbackHandler: fallbackHandler,
	}
}

func (s *Service[K]) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata, protocol, tag string) error {
	var key [KeyLength]byte
	n, err := conn.Read(key[:])
	if err != nil {
		return err
	} else if n != KeyLength {
		return s.fallback(ctx, conn, metadata, key[:n], E.New("bad request size"))
	}

	um := ctx.Value("userManager").(*usermanagement.UserManager)

	if um.AddIP(protocol, tag, string(key[:]), metadata.Source.IPAddr().IP.String()) {
		userid, err := um.GetUserId("trojan", string(key[:]))
		if err == nil {
			ctx = auth.ContextWithUser(ctx, userid)
		} else {
			return s.fallback(ctx, conn, metadata, key[:], E.New("bad request"))
		}
	}

	err = rw.SkipN(conn, 2)
	if err != nil {
		return E.Cause(err, "skip crlf")
	}

	command, err := rw.ReadByte(conn)
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

	metadata.Protocol = "trojan"
	metadata.Destination = destination

	switch command {
	case CommandTCP:
		return s.handler.NewConnection(ctx, conn, metadata)
	case CommandUDP:
		return s.handler.NewPacketConnection(ctx, &PacketConn{Conn: conn}, metadata)
	// case CommandMux:
	default:
		return HandleMuxConnection(ctx, conn, metadata, s.handler)
	}
}

func (s *Service[K]) fallback(ctx context.Context, conn net.Conn, metadata M.Metadata, header []byte, err error) error {
	if s.fallbackHandler == nil {
		return E.Extend(err, "fallback disabled")
	}
	conn = bufio.NewCachedConn(conn, buf.As(header).ToOwned())
	return s.fallbackHandler.NewConnection(ctx, conn, metadata)
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
