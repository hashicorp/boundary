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
	t.Run("noPrefRandom", func(t *testing.T) {
		p, err := NewPreferencer(ctx)
		require.NoError(t, err)
		checkMap := map[string]int{}
		for i := 0; i < 200; i++ {
			out, err := p.Choose(
				ctx,
				WithIpAddrs([]string{"48.134.5.1", "1.2.7.56"}),
				WithDnsNames([]string{"foo.bar.com", "bar.baz.com"}),
			)
			require.NoError(t, err)
			checkMap[out] = checkMap[out] + 1
		}
		// Ensure that we've inserted all four keys
		assert.Len(t, checkMap, 4)
	})
}
