package proxy

import (
	"context"
	"net"
	"net/url"
	"sync/atomic"

	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
)

// GetEndpointDialer returns a ProxyDialer which, when Dial() is called
// returns a net.Conn which reaches the provided endpoint.
var GetEndpointDialer = directDialer

// directDialer returns a ProxyDialer which tcp dials directly to the provided
// endpoint.
func directDialer(ctx context.Context, endpoint *url.URL, _ *pbs.AuthorizeConnectionResponse) (*ProxyDialer, error) {
	const op = "proxy.directDialer"
	if endpoint == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "endpoint is nil")
	}
	d, err := NewProxyDialer(ctx, func(...Option) (net.Conn, error) {
		remoteConn, err := net.Dial("tcp", endpoint.Host)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		return remoteConn, nil
	})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return d, nil
}

// proxyAddr is a net.Addr with IP and port information for the endpoint being
// proxied to.
// TODO: Support returning the IP and port information that gets sent back up through grpc.
type proxyAddr struct {
	wrapped *net.TCPAddr
}

// Ip returns the ip address of the dialed endpoint
func (p *proxyAddr) Ip() string {
	return p.wrapped.IP.String()
}

// Port returns the tcp port of the endpoint connected to
func (p *proxyAddr) Port() uint32 {
	return uint32(p.wrapped.Port)
}

// ProxyDialer dials downstream to eventually get to the target host.
type ProxyDialer struct {
	dialFn     func(...Option) (net.Conn, error)
	latestAddr atomic.Pointer[proxyAddr]
}

// Returns a new proxy dialer using the provided function to get the net.Conn.
func NewProxyDialer(ctx context.Context, df func(...Option) (net.Conn, error)) (*ProxyDialer, error) {
	const op = "proxy.NewProxyDialer"
	if df == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "dialing function is nil")
	}
	return &ProxyDialer{
		dialFn: df,
	}, nil
}

// LastConnectionAddr returns the net.Addr of the last non nil net.Conn
// returned from the Dial() call.  Nil is returned if a non nil net.Conn has
// never been returned from Dial().
func (d *ProxyDialer) LastConnectionAddr() *proxyAddr {
	return d.latestAddr.Load()
}

// Dial uses the provided dial function to get a net.Conn and record its
// net.Addr information.  The returned net.Addr should contain the information
// for the endpoint that is being proxied to.
func (d *ProxyDialer) Dial(ctx context.Context, opt ...Option) (net.Conn, error) {
	const op = "proxy.(*ProxyDialer).Dial"
	c, err := d.dialFn(opt...)
	if err != nil {
		return nil, err
	}
	switch v := c.RemoteAddr().(type) {
	case *net.TCPAddr:
		d.latestAddr.Store(&proxyAddr{v})
	default:
		c.Close()
		return nil, errors.New(ctx, errors.Internal, op, "connection type unexpected")
	}
	return c, nil
}
