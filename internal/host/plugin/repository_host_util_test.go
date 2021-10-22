package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/host"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestCreateNewHostMap(t *testing.T) {
	ctx := context.Background()
	const externalId = "ext_1234567890"
	const pluginId = "plg_1234567890"

	catalog, err := NewHostCatalog(ctx, "p_1234567890", pluginId)
	require.NoError(t, err)
	require.NotNil(t, catalog)
	catalog.PublicId = "hc_1234567890"
	baseHostId, err := newHostId(ctx, catalog.GetPublicId(), externalId)
	require.NoError(t, err)

	baseResponseHost := &plgpb.ListHostsResponseHost{
		ExternalId:  externalId,
		Name:        "base-name",
		Description: "base-description",
		IpAddresses: []string{"1.2.3.4", "5.6.7.8"},
		DnsNames:    []string{"a.b.c", "x.y.z"},
		SetIds:      []string{"hs_1234567890", "hs_0987654321"},
	}
	var baseIpsIfaces []interface{}
	for _, v := range baseResponseHost.IpAddresses {
		ip, err := host.NewIpAddress(ctx, baseHostId, v)
		require.NoError(t, err)
		baseIpsIfaces = append(baseIpsIfaces, ip)
	}
	var baseDnsNamesIfaces []interface{}
	for _, v := range baseResponseHost.DnsNames {
		name, err := host.NewDnsName(ctx, baseHostId, v)
		require.NoError(t, err)
		baseDnsNamesIfaces = append(baseDnsNamesIfaces, name)
	}
	baseHost := NewHost(ctx, catalog.PublicId, externalId)
	baseHost.Name = baseResponseHost.Name
	baseHost.Description = baseResponseHost.Description
	baseHost.IpAddresses = baseResponseHost.IpAddresses
	baseHost.DnsNames = baseResponseHost.DnsNames
	baseHost.PluginId = pluginId

	tests := []struct {
		name string

		// This function should take in a base host (which will be provided as a
		// clone) and transform however needed for the particular test
		in func(*plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo)

		currentHostMap map[string]*Host
	}{
		{
			name: "base",
			in: func(in *plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo) {
				hi := &hostInfo{
					dirtyHost:     true,
					ipsToAdd:      baseIpsIfaces,
					dnsNamesToAdd: baseDnsNamesIfaces,
				}
				return in, hi
			},
		},
		{
			name: "no-change",
			in: func(in *plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo) {
				hi := &hostInfo{}
				return in, hi
			},
			currentHostMap: map[string]*Host{baseHostId: baseHost},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			h := proto.Clone(baseResponseHost).(*plgpb.ListHostsResponseHost)
			var hi *hostInfo
			h, hi = tt.in(h)
			out, err := createNewHostMap(ctx, catalog, []*plgpb.ListHostsResponseHost{h}, tt.currentHostMap)
			require.NoError(err)
			require.NotNil(out)
			require.NotNil(out[baseHostId])
			got := out[baseHostId]

			// Check the various host bits
			assert.Equal(h.ExternalId, got.h.ExternalId)
			assert.Equal(h.Name, got.h.Name)
			assert.Equal(h.Description, got.h.Description)
			assert.ElementsMatch(h.IpAddresses, got.h.IpAddresses)
			assert.ElementsMatch(h.DnsNames, got.h.DnsNames)
			assert.ElementsMatch(h.SetIds, got.h.SetIds)

			// Check the various hostInfo bits
			assert.Equal(hi.dirtyHost, got.dirtyHost)
			assert.ElementsMatch(hi.ipsToAdd, got.ipsToAdd)
			assert.ElementsMatch(hi.ipsToRemove, got.ipsToRemove)
			assert.ElementsMatch(hi.dnsNamesToAdd, got.dnsNamesToAdd)
			assert.ElementsMatch(hi.dnsNamesToRemove, got.dnsNamesToRemove)
		})
	}
}
