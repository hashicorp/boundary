// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package endpoint

import (
	"net"

	"github.com/ryanuber/go-glob"
)

// matcher is a function that given an input returns whether there is a match
type matcher interface {
	Match(string) bool
}

var (
	_ matcher = (*dnsMatcher)(nil)
	_ matcher = (*cidrMatcher)(nil)
	_ matcher = (*addrTypeMatcher)(nil)
)

// DnsMatcher is a function that given an input returns true if there is a
// globbed DNS match
type dnsMatcher struct {
	pattern string
}

// Match satisfies the matcher interface
func (m dnsMatcher) Match(in string) bool {
	return glob.Glob(m.pattern, in)
}

// cidrMatcher is a function that given an input returns true if the input is
// contained within the given net
type cidrMatcher struct {
	ipNet *net.IPNet
}

// Match satisfies the matcher interface
func (m cidrMatcher) Match(in string) bool {
	// Can't be created directly since this is unexported so this should never
	// actually trigger, but for safety
	if m.ipNet == nil {
		return false
	}
	ip := net.ParseIP(in)
	if ip == nil {
		return false
	}
	return m.ipNet.Contains(ip)
}

// addressType represents the desired IP address classification (public or private).
type addressType int

const (
	addrTypePublic addressType = iota
	addrTypePrivate
)

// addrTypeMatcher is a matcher that returns true if the input IP address
// matches the desired classification (public or private).
type addrTypeMatcher struct {
	addrType addressType
}

// Match satisfies the matcher interface. It returns true if the IP's
// public/private classification matches the desired address type.
func (m addrTypeMatcher) Match(in string) bool {
	ip := net.ParseIP(in)
	if ip == nil {
		return false
	}
	switch m.addrType {
	case addrTypePrivate:
		return ip.IsPrivate()
	case addrTypePublic:
		return ip.IsGlobalUnicast() && !ip.IsPrivate()
	default:
		return false
	}
}
