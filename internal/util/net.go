// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package util

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
)

const (
	// MinAddressLength is the minimum length for an address.
	MinAddressLength = 3
	// MaxAddressLength is the maximum length for an address.
	MaxAddressLength = 255
)

var (
	// ErrMissingPort is returned from SplitHostPort when the underlying
	// net.SplitHostPort call detects the input did not contain a port. This is
	// the case for an input like "127.0.0.1" (but not "127.0.0.1:").
	ErrMissingPort = errors.New("missing port in address")
	// ErrTooManyColons is returned from SplitHostPort when the underlying
	// net.SplitHostPort call detects the input has more colons than it is
	// expected to have. This is the case for an input like
	// "127.0.0.1:1010:1010".
	ErrTooManyColons = errors.New("too many colons in address")
	// ErrMissingRBracket is returned from SplitHostPort when the underlying
	// net.SplitHostPort call detects an input that starts with '[' but has no
	// corresponding ']' closing bracket. This is the case for an input like
	// "[::1:9090".
	ErrMissingRBracket = errors.New("missing ']' in address")
	// ErrUnexpectedLBracket is returned from SplitHostPort when the underlying
	// net.SplitHostPort call detects an input that has an unexpected '['
	// character where it is not supposed to be. This is the case for an input
	// like "127.0.[0.1:9090" or "[[127.0.0.1]:9090" (but not
	// "[127.0.0.1]:9090").
	ErrUnexpectedLBracket = errors.New("unexpected '[' in address")
	// ErrUnexpectedRBracket is returned from SplitHostPort when the underlying
	// net.SplitHostPort call detects an input that has an unexpected ']'
	// character where it is not supposed to be. This is the case for an input
	// like "127.0.]0.1:9090" or "127.0.0.1]:9090" (but not "[127.0.0.1]:9090").
	ErrUnexpectedRBracket = errors.New("unexpected ']' in address")

	// ErrInvalidAddressLength is returned when an address input is not within
	// defined lengths (see MinAddressLength and MaxAddressLength).
	ErrInvalidAddressLength = errors.New("invalid address length")
	// ErrInvalidAddressContainsPort is returned when an address input contains
	// a port.
	ErrInvalidAddressContainsPort = errors.New("address contains a port")
)

// This regular expression is used to find all instances of square brackets within a string.
// This regular expression is used to remove the square brackets from an IPv6 address.
var squareBrackets = regexp.MustCompile("\\[|\\]")

// JoinHostPort combines host and port into a network address of the form "host:port".
// If host contains a colon, as found in literal IPv6 addresses, then JoinHostPort returns "[host]:port".
func JoinHostPort(host, port string) string {
	host = squareBrackets.ReplaceAllString(host, "")
	return net.JoinHostPort(host, port)
}

// SplitHostPort splits a network address of the form "host:port",
// "host%zone:port", "[host]:port" or "[host%zone]:port" into separate "host" or
// "host%zone" and "port". It differs from its standard library counterpart in
// the following ways:
//   - If the input is an IP address (with no port), this function will return
//     that IP as the `host`, empty `port`, and ErrMissingPort.
//   - If the input is just a host (with no port), this function will return
//     that host as the `host`, empty `port`, and ErrMissingPort.
//
// These changes enable inputs like "ip_address" or "host" and allows callers to
// detect whether any given `hostport` contains a port or is just a host/IP.
func SplitHostPort(hostport string) (host string, port string, err error) {
	// In case `hostport` is just an ip, we can grab that early.
	if ip := net.ParseIP(hostport); ip != nil {
		// If ParseIP successfully parsed it, it means `hostport` does not have
		// a port (or is a malformed IPv6 address like "::1:1234").
		host = ip.String()
		err = ErrMissingPort
		return host, port, err
	}

	// At this time, we don't necessarily know that `hostport` is a string
	// composed of a host and a port, however net.SplitHostPort will error if
	// that is not the case.
	host, port, err = net.SplitHostPort(hostport)
	if err != nil {
		addrErr := new(net.AddrError)
		isAddrErr := errors.As(err, &addrErr)
		if !isAddrErr {
			return host, port, err
		}

		// Since net.SplitHostPort does not type the error reason, we'll handle
		// that here to simplify logic in callers of this function. Note that
		// while this list covers every error state in net.SplitHostPort up to
		// Go 1.24.1, error reasons might expand over time.
		// See: https://cs.opensource.google/go/go/+/refs/tags/go1.24.1:src/net/ipsock.go;l=165-218
		const (
			stdlibErrReasonMissingPort        = "missing port in address"
			stdlibErrReasonTooManyColons      = "too many colons in address"
			stdlibErrReasonMissingRBracket    = "missing ']' in address"
			stdlibErrReasonUnexpectedLBracket = "unexpected '[' in address"
			stdlibErrReasonUnexpectedRBracket = "unexpected ']' in address"
		)
		switch {
		case strings.Contains(addrErr.Err, stdlibErrReasonMissingPort):
			// In case the `hostport` value is an IPv6 address, we must remove
			// the brackets (if they exist) to retain the same behavior as
			// net.SplitHostPort. This case wouldn't be caught by net.ParseIP
			// because "[ipv6_address]" is not a valid input to that function.
			host = squareBrackets.ReplaceAllString(hostport, "")
			err = ErrMissingPort
		case strings.Contains(addrErr.Err, stdlibErrReasonTooManyColons):
			err = ErrTooManyColons
		case strings.Contains(addrErr.Err, stdlibErrReasonMissingRBracket):
			err = ErrMissingRBracket
		case strings.Contains(addrErr.Err, stdlibErrReasonUnexpectedLBracket):
			err = ErrUnexpectedLBracket
		case strings.Contains(addrErr.Err, stdlibErrReasonUnexpectedRBracket):
			err = ErrUnexpectedRBracket
		}
	}

	return host, port, err
}

// ParseAddress trims and validates the input address string.  It checks whether
// the address is within the allowed length and attempts to split it into a host and
// port. If the address contains a port, it returns an error. The function supports
// both valid IP addresses (IPv4 or IPv6) and DNS names. If the address is valid
// and does not include a port, it returns the host (either an IP or a DNS name).
func ParseAddress(ctx context.Context, address string) (string, error) {
	const op = "util.ParseAddress"
	address = strings.TrimSpace(address)
	if len(address) < MinAddressLength || len(address) > MaxAddressLength {
		return "", ErrInvalidAddressLength
	}
	_, port, _ := SplitHostPort(address)
	if port != "" {
		return "", ErrInvalidAddressContainsPort
	}
	return parseutil.NormalizeAddr(address)
}
