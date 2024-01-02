// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package proxy

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/proto"
)

// GetEndpointDialer returns a ProxyDialer which, when Dial() is called
// returns a net.Conn which reaches the provided endpoint.
var GetEndpointDialer = directDialer

// directDialer returns a ProxyDialer which tcp dials directly to the provided
// endpoint.
func directDialer(ctx context.Context, endpoint string, _ string, _ proto.Message, _ interface{}) (*ProxyDialer, error) {
	const op = "proxy.directDialer"
	if len(endpoint) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "endpoint is empty")
	}
	d, err := NewProxyDialer(ctx, func(opt ...Option) (net.Conn, error) {
		remoteConn, err := net.Dial("tcp", endpoint)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		opts := GetOpts(opt...)
		if opts.WithPostConnectionHook != nil {
			opts.WithPostConnectionHook(remoteConn)
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
type proxyAddr struct {
	ip   string
	port uint32
}

// Ip returns the ip address of the dialed endpoint
func (p *proxyAddr) Ip() string {
	return p.ip
}

// Port returns the tcp port of the endpoint connected to
func (p *proxyAddr) Port() uint32 {
	return p.port
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

// portAndIpGetter allows a dialing function to return a connection that can
// provide it's ip address and port through the GetIp and GetPort methods
// instead of providing directly a *net.TCPConn.  This might be helpful if the
// net.Conn embeds a protobuf message with Ip and Port fields for example.
type portAndIpGetter interface {
	GetIp() string
	GetPort() uint32
}

// Dial uses the provided dial function to get a net.Conn and record its
// net.Addr information.  The returned net.Addr should contain the information
// for the endpoint that is being proxied to.
// All provided options (for example WithPostConnectionHook) are passed into the
// dial function associated with this ProxyDialer.
func (d *ProxyDialer) Dial(ctx context.Context, opt ...Option) (net.Conn, error) {
	const op = "proxy.(*ProxyDialer).Dial"
	c, err := d.dialFn(opt...)
	if err != nil {
		return nil, err
	}
	switch v := c.(type) {
	case *net.TCPConn:
		addr := v.RemoteAddr().(*net.TCPAddr)
		ip := addr.IP.String()
		port := uint32(addr.Port)
		d.latestAddr.Store(&proxyAddr{ip: ip, port: port})
	case portAndIpGetter:
		d.latestAddr.Store(&proxyAddr{ip: v.GetIp(), port: v.GetPort()})
	default:
		c.Close()
		return nil, errors.New(ctx, errors.Internal, op, fmt.Sprintf("connection type unexpected %T", v))
	}
	return c, nil
}
