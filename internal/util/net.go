// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package util

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
)

const (
	// MinAddressLength
	MinAddressLength = 3
	// MaxAddressLength
	MaxAddressLength = 255
	// address is not within the lengths defined above
	InvalidAddressLength = "invalid address length"
	// address contains a port
	InvalidAddressContainsPort = "address contains a port"
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

// SplitHostPort splits a network address of the form "host:port", "host%zone:port", "[host]:port" or "[host%zone]:port" into host or host%zone and port.
func SplitHostPort(hostport string) (host string, port string, err error) {
	// in case hostport is just an ip, we can grab that early
	if ip := net.ParseIP(hostport); ip != nil {
		host = ip.String()
		return
	}
	host, port, err = net.SplitHostPort(hostport)
	// use the hostport value as a backup when we have a missing port error
	if err != nil && strings.Contains(err.Error(), globals.MissingPortErrStr) {
		// incase the hostport value is an ipv6, we must remove the enclosed square
		// brackets to retain the same behavior as the net.SplitHostPort() method
		host = squareBrackets.ReplaceAllString(hostport, "")
		err = nil
	}
	return
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
		return "", errors.New(InvalidAddressLength)
	}
	_, port, err := SplitHostPort(address)
	if err == nil && port != "" {
		return "", errors.New(InvalidAddressContainsPort)
	}
	return parseutil.NormalizeAddr(address)
}
