package common

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/hashicorp/boundary/internal/errors"
)

const (
	RealIpHeader        = "X-Real-Ip"
	XForwardedForHeader = "X-Forwarded-For"
)

var privateNets atomic.Value

// ClientIpFromRequest will determine if the client IP of the http request using
// the provide set of private networks. See InitPrivateNetworks(...) and
// PrivateNetworks(...) for building the list of private networks.
func ClientIpFromRequest(ctx context.Context, privateNetworks []*net.IPNet, r *http.Request) (string, error) {
	const op = "common.ClientIpFromRequest"
	if privateNetworks == nil {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing list of private networks")
	}
	if r == nil {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing http request")
	}

	forwardedFor := r.Header.Get(XForwardedForHeader)
	realIp := r.Header.Get(RealIpHeader)

	// no headers, so we'll use the remote addr
	if forwardedFor == "" && realIp == "" {
		ip, err := ipFromRequestRemoteAddr(ctx, r)
		if err != nil {
			return "", errors.Wrap(ctx, err, op)
		}
		return ip, nil
	}

	// next up, we'll see if there's any public addrs in the X-Forwarded-For
	// header
	for _, a := range strings.Split(forwardedFor, ",") {
		a = strings.TrimSpace(a)
		isPrivate, err := isPrivateAddr(ctx, privateNetworks, a)
		if !isPrivate && err == nil {
			return a, nil
		}
	}

	// no private x-forwarded-for was found and real-ip is empty, so use remote
	// addr
	if realIp == "" {
		ip, err := ipFromRequestRemoteAddr(ctx, r)
		if err != nil {
			return "", errors.Wrap(ctx, err, op)
		}
		return ip, nil
	}

	// finally, just fallback to the contexts of the X-Real-Ip header
	return realIp, nil
}

func ipFromRequestRemoteAddr(ctx context.Context, r *http.Request) (string, error) {
	const op = "common.ipFromRequestRemoteAddr"
	if strings.ContainsRune(r.RemoteAddr, ':') {
		if ip, _, err := net.SplitHostPort(r.RemoteAddr); err != nil {
			return "", errors.Wrap(ctx, err, op)
		} else {
			return ip, nil
		}
	}
	return r.RemoteAddr, nil
}

func isPrivateAddr(ctx context.Context, privateNetworks []*net.IPNet, addr string) (bool, error) {
	const op = "common.isPrivateAddr"
	if privateNetworks == nil {
		return false, errors.New(ctx, errors.InvalidParameter, op, "missing list of private networks")
	}
	if addr == "" {
		return false, errors.New(ctx, errors.InvalidParameter, op, "missing address")
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return false, errors.New(ctx, errors.InvalidParameter, op, "address is not valid")
	}

	// This iterates forward (left to right) from the client, through the IPs
	// for the first public addr...
	//
	// we may want to actually iterate backward (right to left) from boundary
	// until we find the first public addr from what ever proxy/lb is in front
	// of boundary. BTW, Apache processes right to left (backwards):
	// https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html
	for _, net := range privateNetworks {
		if net.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}

// InitPrivateNetworks will use the list of cidr blocks to initialize the list
// of networks returned by PrivateNetworks(...)
func InitPrivateNetworks(ctx context.Context, cidrBlocks []string) error {
	const op = "common.initPrivateNetworks"
	if len(cidrBlocks) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "missing list of cidr blocks")
	}
	nets := make([]*net.IPNet, len(cidrBlocks))
	for i, b := range cidrBlocks {
		_, cidr, err := net.ParseCIDR(b)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("invalid cidr block"))
		}
		nets[i] = cidr
	}
	privateNets.Store(nets)
	return nil
}

// PrivateNetworks is the list of private networks built by
// InitPrivateNetworks(...)
func PrivateNetworks(ctx context.Context) []*net.IPNet {
	if nets, ok := privateNets.Load().([]*net.IPNet); ok {
		return nets
	} else {
		return nil
	}
}

// PrivateCidrBlocks is a list of cidr blocks that defines possible private
// networks. It uses info defined in:
// 	https://en.wikipedia.org/wiki/Private_network
// 	https://en.wikipedia.org/wiki/Link-local_address
func PrivateCidrBlocks() []string {
	return []string{
		"127.0.0.1/8",    // local
		"::1/128",        // local IPv6
		"fe80::/10",      // link local address IPv6
		"fc00::/7",       // unique local address IPv6
		"169.254.0.0/16", // link local addresses
		"192.168.0.0/16", // 16-bit
		"172.16.0.0/12",  // 20-bit
		"10.0.0.0/8",     // 24-bit
	}
}
