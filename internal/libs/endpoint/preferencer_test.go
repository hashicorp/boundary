// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package endpoint

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreferencer(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("badOption", func(t *testing.T) {
		_, err := NewPreferencer(ctx, WithPreferenceOrder([]string{"bad:1.2.3.4"}))
		assert.Error(t, err)
	})
	t.Run("goodOption", func(t *testing.T) {
		_, err := NewPreferencer(ctx, WithPreferenceOrder([]string{"cidr:1.2.3.4"}))
		assert.NoError(t, err)
	})
	t.Run("chooseBadOption", func(t *testing.T) {
		p, err := NewPreferencer(ctx)
		require.NoError(t, err)
		_, err = p.Choose(ctx, WithIpAddrs([]string{"266.1.2.3"}))
		assert.Error(t, err)
	})
	t.Run("noAddresses", func(t *testing.T) {
		p, err := NewPreferencer(ctx)
		require.NoError(t, err)
		_, err = p.Choose(ctx)
		assert.Error(t, err)
	})
	t.Run("preferenceOrder", func(t *testing.T) {
		p, err := NewPreferencer(ctx,
			WithPreferenceOrder([]string{
				"cidr:1.2.3.4/24",
				"dns:*.example.com",
				"cidr:5.6.7.8/8",
				"dns:*.company.com",
			}))
		require.NoError(t, err)

		cases := []struct {
			name                  string
			withIpAddrs           []string
			withDnsNames          []string
			expectedEndpoint      string
			expectedErrorContains string
		}{
			{
				name:             "first cidr",
				withIpAddrs:      []string{"5.6.7.8", "1.2.3.56"},
				withDnsNames:     []string{"foo.bar", "bar.baz"},
				expectedEndpoint: "1.2.3.56",
			},
			{
				name:             "first dns",
				withIpAddrs:      []string{"48.134.5.1", "1.2.7.56"},
				withDnsNames:     []string{"bar.baz", "foo.example.com"},
				expectedEndpoint: "foo.example.com",
			},
			{
				name:             "second cidr",
				withIpAddrs:      []string{"5.6.7.8", "1.2.7.56"},
				withDnsNames:     []string{"foo.bar", "bar.baz"},
				expectedEndpoint: "5.6.7.8",
			},
			{
				name:             "second dns",
				withIpAddrs:      []string{"48.134.5.1", "1.2.7.56"},
				withDnsNames:     []string{"foo.bar.com", "bar.company.com"},
				expectedEndpoint: "bar.company.com",
			},
			{
				name:         "no match",
				withIpAddrs:  []string{"48.134.5.1", "1.2.7.56"},
				withDnsNames: []string{"foo.bar.com", "bar.baz.com"},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				out, err := p.Choose(ctx, WithIpAddrs(tc.withIpAddrs), WithDnsNames(tc.withDnsNames))
				if tc.expectedErrorContains != "" {
					require.Error(t, err)
					assert.Contains(t, tc.expectedErrorContains, err.Error())
				}
				assert.Equal(t, tc.expectedEndpoint, out)
			})
		}
	})
	t.Run("noPrefReturnsPrivate", func(t *testing.T) {
		const privAddr = "192.168.4.3"
		p, err := NewPreferencer(ctx)
		require.NoError(t, err)
		out, err := p.Choose(
			ctx,
			WithIpAddrs([]string{"48.134.5.1", "2001::1", privAddr}),
			WithDnsNames([]string{"foo.bar.com", "bar.baz.com"}),
		)
		require.NoError(t, err)
		assert.Equal(t, privAddr, out)
	})
	t.Run("noPrefNoPrivateReturnsIp4", func(t *testing.T) {
		const exp = "48.134.5.1"
		p, err := NewPreferencer(ctx)
		require.NoError(t, err)
		out, err := p.Choose(
			ctx,
			WithIpAddrs([]string{"2001::1", exp}),
			WithDnsNames([]string{"foo.bar.com", "bar.baz.com"}),
		)
		require.NoError(t, err)
		assert.Equal(t, exp, out)
	})
	t.Run("noPrefNoIp4ReturnsDns", func(t *testing.T) {
		const exp = "foo.bar.com"
		p, err := NewPreferencer(ctx)
		require.NoError(t, err)
		out, err := p.Choose(
			ctx,
			WithIpAddrs([]string{"2001::1"}),
			WithDnsNames([]string{exp}),
		)
		require.NoError(t, err)
		assert.Equal(t, exp, out)
	})
	t.Run("ip6OnlyReturnsPrivate", func(t *testing.T) {
		const exp = "fc00::1"
		p, err := NewPreferencer(ctx)
		require.NoError(t, err)
		out, err := p.Choose(
			ctx,
			WithIpAddrs([]string{"2001::1", exp}),
		)
		require.NoError(t, err)
		assert.Equal(t, exp, out)
	})
	t.Run("ip6OnlyPublic", func(t *testing.T) {
		const exp = "2001::1"
		p, err := NewPreferencer(ctx)
		require.NoError(t, err)
		out, err := p.Choose(
			ctx,
			WithIpAddrs([]string{exp}),
		)
		require.NoError(t, err)
		assert.Equal(t, exp, out)
	})
	t.Run("netPublicSelectsPublicIPv4", func(t *testing.T) {
		p, err := NewPreferencer(ctx, WithPreferenceOrder([]string{"address_type:public"}))
		require.NoError(t, err)
		out, err := p.Choose(ctx,
			WithIpAddrs([]string{"10.0.0.5", "192.168.1.1", "54.23.1.100"}),
		)
		require.NoError(t, err)
		assert.Equal(t, "54.23.1.100", out)
	})
	t.Run("netPublicSelectsPublicIPv6", func(t *testing.T) {
		p, err := NewPreferencer(ctx, WithPreferenceOrder([]string{"address_type:public"}))
		require.NoError(t, err)
		out, err := p.Choose(ctx,
			WithIpAddrs([]string{"fc00::1", "2001:db8::1"}),
		)
		require.NoError(t, err)
		assert.Equal(t, "2001:db8::1", out)
	})
	t.Run("netPublicNoMatch", func(t *testing.T) {
		p, err := NewPreferencer(ctx, WithPreferenceOrder([]string{"address_type:public"}))
		require.NoError(t, err)
		out, err := p.Choose(ctx,
			WithIpAddrs([]string{"10.0.0.5", "192.168.1.1", "172.16.0.1"}),
		)
		require.NoError(t, err)
		assert.Equal(t, "", out)
	})
	t.Run("netPrivateSelectsPrivateIPv4", func(t *testing.T) {
		p, err := NewPreferencer(ctx, WithPreferenceOrder([]string{"address_type:private"}))
		require.NoError(t, err)
		out, err := p.Choose(ctx,
			WithIpAddrs([]string{"54.23.1.100", "10.0.0.5", "3.128.0.1"}),
		)
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.5", out)
	})
	t.Run("netPrivateSelectsPrivateIPv6", func(t *testing.T) {
		p, err := NewPreferencer(ctx, WithPreferenceOrder([]string{"address_type:private"}))
		require.NoError(t, err)
		out, err := p.Choose(ctx,
			WithIpAddrs([]string{"2001:db8::1", "fc00::1"}),
		)
		require.NoError(t, err)
		assert.Equal(t, "fc00::1", out)
	})
	t.Run("netPrivateNoMatch", func(t *testing.T) {
		p, err := NewPreferencer(ctx, WithPreferenceOrder([]string{"address_type:private"}))
		require.NoError(t, err)
		out, err := p.Choose(ctx,
			WithIpAddrs([]string{"54.23.1.100", "3.128.0.1"}),
		)
		require.NoError(t, err)
		assert.Equal(t, "", out)
	})
	t.Run("netPublicWithDnsFallback", func(t *testing.T) {
		// address_type:public only matches IPs, not DNS names. DNS matcher should be used separately.
		p, err := NewPreferencer(ctx, WithPreferenceOrder([]string{"address_type:public", "dns:*.amazonaws.com"}))
		require.NoError(t, err)
		out, err := p.Choose(ctx,
			WithIpAddrs([]string{"10.0.0.5"}),
			WithDnsNames([]string{"ec2-54-1-2-3.compute-1.amazonaws.com"}),
		)
		require.NoError(t, err)
		// No public IPs, so address_type:public doesn't match, falls through to dns matcher
		assert.Equal(t, "ec2-54-1-2-3.compute-1.amazonaws.com", out)
	})
	t.Run("netPublicPrecedenceOverDns", func(t *testing.T) {
		p, err := NewPreferencer(ctx, WithPreferenceOrder([]string{"address_type:public", "dns:*.amazonaws.com"}))
		require.NoError(t, err)
		out, err := p.Choose(ctx,
			WithIpAddrs([]string{"10.0.0.5", "54.23.1.100"}),
			WithDnsNames([]string{"ec2-54-1-2-3.compute-1.amazonaws.com"}),
		)
		require.NoError(t, err)
		// Public IP found first since address_type:public is higher priority
		assert.Equal(t, "54.23.1.100", out)
	})
	t.Run("netPublicExcludesLoopback", func(t *testing.T) {
		p, err := NewPreferencer(ctx, WithPreferenceOrder([]string{"address_type:public"}))
		require.NoError(t, err)
		out, err := p.Choose(ctx,
			WithIpAddrs([]string{"127.0.0.1", "54.23.1.100"}),
		)
		require.NoError(t, err)
		assert.Equal(t, "54.23.1.100", out)
	})
	t.Run("netPublicExcludesLinkLocal", func(t *testing.T) {
		p, err := NewPreferencer(ctx, WithPreferenceOrder([]string{"address_type:public"}))
		require.NoError(t, err)
		out, err := p.Choose(ctx,
			WithIpAddrs([]string{"169.254.1.1", "52.10.0.1"}),
		)
		require.NoError(t, err)
		assert.Equal(t, "52.10.0.1", out)
	})
	t.Run("netBadValue", func(t *testing.T) {
		_, err := NewPreferencer(ctx, WithPreferenceOrder([]string{"address_type:happy"}))
		assert.Error(t, err)
	})
	t.Run("netEmpty", func(t *testing.T) {
		_, err := NewPreferencer(ctx, WithPreferenceOrder([]string{"address_type:"}))
		assert.Error(t, err)
	})
	t.Run("netPublicMixedWithCidr", func(t *testing.T) {
		// cidr:10.0.0.0/8 is first priority, address_type:public is fallback
		p, err := NewPreferencer(ctx, WithPreferenceOrder([]string{"cidr:10.0.0.0/8", "address_type:public"}))
		require.NoError(t, err)
		// Has a 10.x address, should prefer that
		out, err := p.Choose(ctx,
			WithIpAddrs([]string{"54.23.1.100", "10.0.0.5"}),
		)
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.5", out)

		// No 10.x address, falls through to address_type:public
		out, err = p.Choose(ctx,
			WithIpAddrs([]string{"192.168.1.1", "54.23.1.100"}),
		)
		require.NoError(t, err)
		assert.Equal(t, "54.23.1.100", out)
	})
}
