// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package endpoint

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchers(t *testing.T) {
	t.Parallel()
	t.Run("dnsMatcherEmptyPattern", func(t *testing.T) {
		d := dnsMatcher{pattern: ""}
		assert.False(t, d.Match("foo"))
	})
	t.Run("dnsMatcherBasic", func(t *testing.T) {
		d := dnsMatcher{pattern: "foo"}
		assert.True(t, d.Match("foo"))
	})
	t.Run("dnsMatcherMatchingGlob", func(t *testing.T) {
		d := dnsMatcher{pattern: "fo*o*"}
		assert.True(t, d.Match("foweroasgdf"))
	})
	t.Run("dnsMatcherNonMatchingGlob", func(t *testing.T) {
		d := dnsMatcher{pattern: "fo*o*"}
		assert.False(t, d.Match("bfoweroasgdf"))
	})
	t.Run("cidrMatcherNilMatcher", func(t *testing.T) {
		d := cidrMatcher{}
		assert.False(t, d.Match("1.2.3.4"))
	})
	t.Run("cidrMatcherIpv4Matcher", func(t *testing.T) {
		_, net, err := net.ParseCIDR("1.2.3.4/24")
		require.NoError(t, err)
		d := cidrMatcher{ipNet: net}
		assert.True(t, d.Match("1.2.3.4"))
		assert.False(t, d.Match("1.2.4.4"))
		assert.False(t, d.Match("260.234.19.3"))
	})
	t.Run("cidrMatcherIpv6Matcher", func(t *testing.T) {
		_, net, err := net.ParseCIDR("2001:1234::/32")
		require.NoError(t, err)
		d := cidrMatcher{ipNet: net}
		assert.True(t, d.Match("2001:1234:3092::abcd:dead:beef:2423"))
		assert.False(t, d.Match("2001:1244:3092::abcd:dead:beef:2423"))
	})
	t.Run("addrTypeMatcherPublicIPv4", func(t *testing.T) {
		m := addrTypeMatcher{addrType: addrTypePublic}
		assert.True(t, m.Match("54.23.1.100"))
	})
	t.Run("addrTypeMatcherPublicIPv6", func(t *testing.T) {
		m := addrTypeMatcher{addrType: addrTypePublic}
		assert.True(t, m.Match("2001:db8::1"))
	})
	t.Run("addrTypeMatcherPublicRejectsPrivateIPv4", func(t *testing.T) {
		m := addrTypeMatcher{addrType: addrTypePublic}
		assert.False(t, m.Match("10.0.0.1"))
		assert.False(t, m.Match("172.16.0.1"))
		assert.False(t, m.Match("192.168.1.1"))
	})
	t.Run("addrTypeMatcherPublicRejectsPrivateIPv6", func(t *testing.T) {
		m := addrTypeMatcher{addrType: addrTypePublic}
		assert.False(t, m.Match("fc00::1"))
	})
	t.Run("addrTypeMatcherPublicRejectsLoopback", func(t *testing.T) {
		m := addrTypeMatcher{addrType: addrTypePublic}
		assert.False(t, m.Match("127.0.0.1"))
		assert.False(t, m.Match("::1"))
	})
	t.Run("addrTypeMatcherPublicRejectsLinkLocal", func(t *testing.T) {
		m := addrTypeMatcher{addrType: addrTypePublic}
		assert.False(t, m.Match("169.254.1.1"))
		assert.False(t, m.Match("fe80::1"))
	})
	t.Run("addrTypeMatcherPrivateIPv4", func(t *testing.T) {
		m := addrTypeMatcher{addrType: addrTypePrivate}
		assert.True(t, m.Match("10.0.0.1"))
		assert.True(t, m.Match("172.16.0.1"))
		assert.True(t, m.Match("192.168.1.1"))
	})
	t.Run("addrTypeMatcherPrivateIPv6", func(t *testing.T) {
		m := addrTypeMatcher{addrType: addrTypePrivate}
		assert.True(t, m.Match("fc00::1"))
	})
	t.Run("addrTypeMatcherPrivateRejectsPublic", func(t *testing.T) {
		m := addrTypeMatcher{addrType: addrTypePrivate}
		assert.False(t, m.Match("54.23.1.100"))
		assert.False(t, m.Match("2001:db8::1"))
	})
	t.Run("addrTypeMatcherPrivateRejectsLoopback", func(t *testing.T) {
		m := addrTypeMatcher{addrType: addrTypePrivate}
		assert.False(t, m.Match("127.0.0.1"))
		assert.False(t, m.Match("::1"))
	})
	t.Run("addrTypeMatcherInvalidInput", func(t *testing.T) {
		m := addrTypeMatcher{addrType: addrTypePublic}
		assert.False(t, m.Match("not-an-ip"))
		assert.False(t, m.Match(""))
	})
	t.Run("addrTypeMatcherInvalidInputPrivate", func(t *testing.T) {
		m := addrTypeMatcher{addrType: addrTypePrivate}
		assert.False(t, m.Match("not-an-ip"))
		assert.False(t, m.Match(""))
	})
	t.Run("addrTypeMatcherUnknownType", func(t *testing.T) {
		m := addrTypeMatcher{addrType: addressType(99)}
		assert.False(t, m.Match("54.23.1.100"))
	})
}
