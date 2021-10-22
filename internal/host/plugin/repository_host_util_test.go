package plugin

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/host"
	hoststore "github.com/hashicorp/boundary/internal/host/store"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestUtilFunctions(t *testing.T) {
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

	defaultHostFunc := func(in *Host) *Host {
		return in
	}

	tests := []struct {
		name string
		host func(*Host) *Host
		// This function should take in a base host (which will be provided as a
		// clone) and transform however needed for the particular test
		in func(*plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo)
	}{
		{
			name: "base",
			host: func(in *Host) *Host {
				return nil
			},
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
			host: defaultHostFunc,
			in: func(in *plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo) {
				hi := &hostInfo{}
				return in, hi
			},
		},
		{
			name: "new-name",
			host: defaultHostFunc,
			in: func(in *plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo) {
				in.Name = "newname"
				hi := &hostInfo{
					dirtyHost: true,
				}
				return in, hi
			},
		},
		{
			name: "new-description",
			host: defaultHostFunc,
			in: func(in *plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo) {
				in.Description = "newdescription"
				hi := &hostInfo{
					dirtyHost: true,
				}
				return in, hi
			},
		},
		{
			name: "extra-ip",
			host: defaultHostFunc,
			in: func(in *plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo) {
				const newIp = "11.22.33.44"
				in.IpAddresses = append(in.IpAddresses, newIp)
				ip, err := host.NewIpAddress(ctx, baseHostId, newIp)
				require.NoError(t, err)
				hi := &hostInfo{
					ipsToAdd:    append(baseIpsIfaces, ip),
					ipsToRemove: baseIpsIfaces,
				}
				return in, hi
			},
		},
		{
			name: "remove-ip",
			host: defaultHostFunc,
			in: func(in *plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo) {
				in.IpAddresses = in.IpAddresses[0:1]
				hi := &hostInfo{
					ipsToAdd:    baseIpsIfaces[0:1],
					ipsToRemove: baseIpsIfaces,
				}
				return in, hi
			},
		},
		{
			name: "extra-dns-name",
			host: defaultHostFunc,
			in: func(in *plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo) {
				const newName = "this.is.a.test"
				in.DnsNames = append(in.DnsNames, newName)
				name, err := host.NewDnsName(ctx, baseHostId, newName)
				require.NoError(t, err)
				hi := &hostInfo{
					dnsNamesToAdd:    append(baseDnsNamesIfaces, name),
					dnsNamesToRemove: baseDnsNamesIfaces,
				}
				return in, hi
			},
		},
		{
			name: "remove-dns-name",
			host: defaultHostFunc,
			in: func(in *plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo) {
				in.DnsNames = in.DnsNames[0:1]
				hi := &hostInfo{
					dnsNamesToAdd:    baseDnsNamesIfaces[0:1],
					dnsNamesToRemove: baseDnsNamesIfaces,
				}
				return in, hi
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			var hi *hostInfo
			currentHostMap := map[string]*Host{baseHostId: tt.host(baseHost.clone())}
			h := proto.Clone(baseResponseHost).(*plgpb.ListHostsResponseHost)
			h, hi = tt.in(h)

			out, err := createNewHostMap(ctx, catalog, []*plgpb.ListHostsResponseHost{h}, currentHostMap)
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
			assert.Empty(
				cmp.Diff(
					hi.ipsToAdd,
					got.ipsToAdd,
					cmpopts.IgnoreUnexported(host.IpAddress{}, hoststore.IpAddress{}),
					cmpopts.SortSlices(func(x, y interface{}) bool {
						return x.(*host.IpAddress).Address < y.(*host.IpAddress).Address
					}),
				),
			)
			assert.Empty(
				cmp.Diff(
					hi.ipsToRemove,
					got.ipsToRemove,
					cmpopts.IgnoreUnexported(host.IpAddress{}, hoststore.IpAddress{}),
					cmpopts.SortSlices(func(x, y interface{}) bool {
						return x.(*host.IpAddress).Address < y.(*host.IpAddress).Address
					}),
				),
			)
			assert.Empty(
				cmp.Diff(
					hi.dnsNamesToAdd,
					got.dnsNamesToAdd,
					cmpopts.IgnoreUnexported(host.DnsName{}, hoststore.DnsName{}),
					cmpopts.SortSlices(func(x, y interface{}) bool {
						return x.(*host.DnsName).Name < y.(*host.DnsName).Name
					}),
				),
			)
			assert.Empty(
				cmp.Diff(
					hi.dnsNamesToRemove,
					got.dnsNamesToRemove,
					cmpopts.IgnoreUnexported(host.DnsName{}, hoststore.DnsName{}),
					cmpopts.SortSlices(func(x, y interface{}) bool {
						return x.(*host.DnsName).Name < y.(*host.DnsName).Name
					}),
				),
			)
		})
	}
}
