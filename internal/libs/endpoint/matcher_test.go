// Copyright IBM Corp. 2020, 2025
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
}
