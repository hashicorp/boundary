// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package endpoint

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithNil", func(t *testing.T) {
		_, err := getOpts(Option(nil))
		require.NoError(t, err)
	})
	t.Run("WithDnsNames", func(t *testing.T) {
		opts, err := getOpts(WithDnsNames([]string{"foo.bar", "fluebar"}))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withDnsNames = []string{"foo.bar", "fluebar"}
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithIpAddrsBadIp", func(t *testing.T) {
		_, err := getOpts(WithIpAddrs([]string{"foo.bar", "1.2.3.4"}))
		require.Error(t, err)
	})
	t.Run("WithIpAddrs", func(t *testing.T) {
		opts, err := getOpts(WithIpAddrs([]string{"1.2.3.4", "5.6.7.8"}))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withIpAddrs = []string{"1.2.3.4", "5.6.7.8"}
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithPreferenceOrderBadCidr", func(t *testing.T) {
		_, err := getOpts(WithPreferenceOrder([]string{"cidr:15.3.25.6/33", "1.2.3.4"}))
		require.Error(t, err)
	})
	t.Run("WithPreferenceOrderBadDns", func(t *testing.T) {
		_, err := getOpts(WithPreferenceOrder([]string{"dns:"}))
		require.Error(t, err)
	})
	t.Run("WithPreferenceOrderBadPref", func(t *testing.T) {
		_, err := getOpts(WithPreferenceOrder([]string{"abc:15.3.25.6/33", "1.2.3.4"}))
		require.Error(t, err)
	})
	t.Run("WithPreferenceOrder", func(t *testing.T) {
		require := require.New(t)
		cidr1Str := "15.3.25.6/8"
		_, net1, err := net.ParseCIDR(cidr1Str)
		require.NoError(err)
		dns1Str := "foo.bar"
		cidr2Str := "2001::44"
		_, net2, err := net.ParseCIDR(cidr2Str + "/128")
		require.NoError(err)
		cidr3Str := "1.2.3.4"
		_, net3, err := net.ParseCIDR(cidr3Str + "/32")
		require.NoError(err)
		opts, err := getOpts(WithPreferenceOrder([]string{"cidr:" + cidr1Str, "dns:" + dns1Str, "cidr:" + cidr2Str, "cidr:" + cidr3Str}))
		require.NoError(err)
		testOpts := getDefaultOptions()

		testOpts.withMatchers = []matcher{
			cidrMatcher{
				ipNet: net1,
			},
			dnsMatcher{
				pattern: dns1Str,
			},
			cidrMatcher{
				ipNet: net2,
			},
			cidrMatcher{
				ipNet: net3,
			},
		}
		assert.Equal(t, opts, testOpts)
	})
}
