package direct

import (
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/qimaoww/quic-go"
	"github.com/qimaoww/outbound/netproxy"
	"github.com/qimaoww/outbound/protocol/juicity"
	"github.com/stretchr/testify/require"
)

type stubPacketConn struct{}

func (stubPacketConn) Read([]byte) (int, error)                     { return 0, nil }
func (stubPacketConn) Write([]byte) (int, error)                    { return 0, nil }
func (stubPacketConn) ReadFrom([]byte) (int, netip.AddrPort, error) { return 0, netip.AddrPort{}, nil }
func (stubPacketConn) WriteTo([]byte, string) (int, error)          { return 0, nil }
func (stubPacketConn) Close() error                                 { return nil }
func (stubPacketConn) SetDeadline(time.Time) error                  { return nil }
func (stubPacketConn) SetReadDeadline(time.Time) error              { return nil }
func (stubPacketConn) SetWriteDeadline(time.Time) error             { return nil }
func (stubPacketConn) SyscallConn() (syscall.RawConn, error)        { return nil, nil }

func TestFakeNetPacketConn(t *testing.T) {
	t.Run("positive", func(t *testing.T) {
		fc := netproxy.NewFakeNetPacketConn(stubPacketConn{}, nil, nil)
		_, ok := fc.(quic.OOBCapablePacketConn)
		require.True(t, ok)
		_, ok = fc.(net.PacketConn)
		require.True(t, ok)
	})
	t.Run("negative", func(t *testing.T) {
		c := (interface{})(&juicity.PacketConn{})
		fc := netproxy.NewFakeNetPacketConn(c.(netproxy.PacketConn), nil, nil)
		_, ok := fc.(quic.OOBCapablePacketConn)
		require.False(t, ok)
		_, ok = fc.(net.PacketConn)
		require.True(t, ok)
	})
}
