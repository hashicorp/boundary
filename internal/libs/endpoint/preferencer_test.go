// Copyright IBM Corp. 2020, 2025
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
}
