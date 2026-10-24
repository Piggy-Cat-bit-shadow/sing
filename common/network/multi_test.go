package network

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// blockingDialer ignores its per-attempt context deliberately. DialParallel must still honor the
// parent context instead of waiting for the fallback timer or for a dialer that never returns.
type blockingDialer struct {
	release chan struct{}
}

func (d *blockingDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	<-d.release
	return nil, net.ErrClosed
}

func (d *blockingDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func TestDialParallelReturnsOnContextCancellation(t *testing.T) {
	t.Parallel()
	dialer := &blockingDialer{release: make(chan struct{})}
	t.Cleanup(func() { close(dialer.release) })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := DialParallel(ctx, dialer, "tcp", M.SocksaddrFrom(netip.MustParseAddr("192.0.2.1"), 443), []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	}, false, time.Hour)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 5*time.Second, "cancellation must not wait for the one-hour fallback")
}
