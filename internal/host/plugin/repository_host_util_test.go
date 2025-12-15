// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
		ExternalId:   externalId,
		ExternalName: "base-external-name",
		Name:         "base-name",
		Description:  "base-description",
		IpAddresses:  []string{"1.2.3.4", "5.6.7.8"},
		DnsNames:     []string{"a.b.c", "x.y.z"},
		SetIds:       []string{"set1", "set2"},
	}
	baseIpsIfaces := valueToInterfaceMap{}
	for _, v := range baseResponseHost.IpAddresses {
		ip, err := host.NewIpAddress(ctx, baseHostId, v)
		require.NoError(t, err)
		baseIpsIfaces[v] = ip
	}
	baseDnsNamesIfaces := valueToInterfaceMap{}
	for _, v := range baseResponseHost.DnsNames {
		name, err := host.NewDnsName(ctx, baseHostId, v)
		require.NoError(t, err)
		baseDnsNamesIfaces[v] = name
	}
	baseHost := NewHost(ctx, catalog.PublicId, externalId)
	baseHost.ExternalName = baseResponseHost.ExternalName
	baseHost.Name = baseResponseHost.Name
	baseHost.Description = baseResponseHost.Description
	baseHost.IpAddresses = baseResponseHost.IpAddresses
	baseHost.DnsNames = baseResponseHost.DnsNames
	baseHost.PluginId = pluginId
	baseHost.SetIds = baseResponseHost.SetIds

	defaultHostFunc := func(in *Host) *Host {
		return in
	}
	defaultSetsFunc := func() []string {
		return baseHost.SetIds
	}

	tests := []struct {
		name string
		host func(*Host) *Host
		// This function should take in a base host (which will be provided as a
		// clone) and transform however needed for the particular test
		in           func(*plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo)
		sets         func() []string
		setsToAdd    map[string][]string
		setsToRemove map[string][]string
	}{
		{
			name: "base",
			host: func(in *Host) *Host {
				return nil
			},
			sets: func() []string {
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
			sets: defaultSetsFunc,
			in: func(in *plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo) {
				hi := &hostInfo{}
				return in, hi
			},
		},
		{
			name: "new-name",
			host: defaultHostFunc,
			sets: defaultSetsFunc,
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
			sets: defaultSetsFunc,
			in: func(in *plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo) {
				in.Description = "newdescription"
				hi := &hostInfo{
					dirtyHost: true,
				}
				return in, hi
			},
		},
		{
			name: "new-external-name",
			host: defaultHostFunc,
			sets: defaultSetsFunc,
			in: func(in *plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo) {
				in.ExternalName = "newextname"
				hi := &hostInfo{
					dirtyHost: true,
				}
				return in, hi
			},
		},
		{
			name: "extra-ip",
			host: defaultHostFunc,
			sets: defaultSetsFunc,
			in: func(in *plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo) {
				const newIp = "11.22.33.44"
				in.IpAddresses = append(in.IpAddresses, newIp)
				ip, err := host.NewIpAddress(ctx, baseHostId, newIp)
				require.NoError(t, err)
				hi := &hostInfo{
					ipsToAdd: valueToInterfaceMap{newIp: ip},
				}
				return in, hi
			},
		},
		{
			name: "remove-ip",
			host: defaultHostFunc,
			sets: defaultSetsFunc,
			in: func(in *plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo) {
				hi := &hostInfo{
					ipsToRemove: valueToInterfaceMap{},
				}
				for _, ip := range in.IpAddresses[1:] {
					hi.ipsToRemove[ip] = baseIpsIfaces[ip]
				}
				in.IpAddresses = in.IpAddresses[0:1]
				return in, hi
			},
		},
		{
			name: "extra-dns-name",
			host: defaultHostFunc,
			sets: defaultSetsFunc,
			in: func(in *plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo) {
				const newName = "this.is.a.test"
				in.DnsNames = append(in.DnsNames, newName)
				name, err := host.NewDnsName(ctx, baseHostId, newName)
				require.NoError(t, err)
				hi := &hostInfo{
					dnsNamesToAdd: valueToInterfaceMap{newName: name},
				}
				return in, hi
			},
		},
		{
			name: "remove-dns-name",
			host: defaultHostFunc,
			sets: defaultSetsFunc,
			in: func(in *plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo) {
				hi := &hostInfo{
					dnsNamesToRemove: valueToInterfaceMap{},
				}
				for _, name := range in.DnsNames[1:] {
					hi.dnsNamesToRemove[name] = baseDnsNamesIfaces[name]
				}
				in.DnsNames = in.DnsNames[0:1]
				return in, hi
			},
		},
		{
			name: "add-sets",
			host: defaultHostFunc,
			sets: func() []string {
				return append(defaultSetsFunc(), "extra-set", "extra-set-2")
			},
			in: func(in *plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo) {
				hi := &hostInfo{}
				return in, hi
			},
			setsToAdd: map[string][]string{
				"extra-set":   {baseHostId},
				"extra-set-2": {baseHostId},
			},
		},
		{
			name: "remove-sets",
			host: defaultHostFunc,
			sets: func() []string {
				return defaultSetsFunc()[0:1]
			},
			in: func(in *plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo) {
				hi := &hostInfo{}
				return in, hi
			},
			setsToRemove: map[string][]string{
				"set2": {baseHostId},
			},
		},
		{
			name: "add-and-remove-sets",
			host: defaultHostFunc,
			sets: func() []string {
				return append(defaultSetsFunc()[0:1], "extra-set")
			},
			in: func(in *plgpb.ListHostsResponseHost) (*plgpb.ListHostsResponseHost, *hostInfo) {
				hi := &hostInfo{}
				return in, hi
			},
			setsToAdd: map[string][]string{
				"extra-set": {baseHostId},
			},
			setsToRemove: map[string][]string{
				"set2": {baseHostId},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			var hi *hostInfo
			currHost := tt.host(baseHost.clone())
			currentHostMap := map[string]*Host{}
			if currHost != nil {
				currentHostMap[baseHostId] = currHost
			}
			h := proto.Clone(baseResponseHost).(*plgpb.ListHostsResponseHost)
			h, hi = tt.in(h)

			newHostMap, err := createNewHostMap(ctx, catalog, []*plgpb.ListHostsResponseHost{h}, currentHostMap)
			require.NoError(err)
			require.NotNil(newHostMap)
			require.NotNil(newHostMap[baseHostId])
			got := newHostMap[baseHostId]

			// Check the various host/hostinfo bits
			{
				assert.Equal(h.ExternalId, got.h.ExternalId)
				assert.Equal(h.Name, got.h.Name)
				assert.Equal(h.Description, got.h.Description)
				assert.ElementsMatch(h.IpAddresses, got.h.IpAddresses)
				assert.ElementsMatch(h.DnsNames, got.h.DnsNames)
				assert.ElementsMatch(h.SetIds, got.h.SetIds)

				assert.Equal(hi.dirtyHost, got.dirtyHost)
				assert.Empty(
					cmp.Diff(
						hi.ipsToAdd,
						got.ipsToAdd,
						cmpopts.IgnoreUnexported(host.IpAddress{}, hoststore.IpAddress{}),
						cmpopts.SortSlices(func(x, y any) bool {
							return x.(*host.IpAddress).Address < y.(*host.IpAddress).Address
						}),
					),
				)
				assert.Empty(
					cmp.Diff(
						hi.ipsToRemove,
						got.ipsToRemove,
						cmpopts.IgnoreUnexported(host.IpAddress{}, hoststore.IpAddress{}),
						cmpopts.SortSlices(func(x, y any) bool {
							return x.(*host.IpAddress).Address < y.(*host.IpAddress).Address
						}),
					),
				)
				assert.Empty(
					cmp.Diff(
						hi.dnsNamesToAdd,
						got.dnsNamesToAdd,
						cmpopts.IgnoreUnexported(host.DnsName{}, hoststore.DnsName{}),
						cmpopts.SortSlices(func(x, y any) bool {
							return x.(*host.DnsName).Name < y.(*host.DnsName).Name
						}),
					),
				)
				assert.Empty(
					cmp.Diff(
						hi.dnsNamesToRemove,
						got.dnsNamesToRemove,
						cmpopts.IgnoreUnexported(host.DnsName{}, hoststore.DnsName{}),
						cmpopts.SortSlices(func(x, y any) bool {
							return x.(*host.DnsName).Name < y.(*host.DnsName).Name
						}),
					),
				)
			}

			// Run through the sets function
			{
				newHostMap[baseHostId].h.SetIds = tt.sets()
				toAdd, toRemove := getSetChanges(currentHostMap, newHostMap)
				assert.Equal(tt.setsToAdd, toAdd)
				assert.Equal(tt.setsToRemove, toRemove)
			}
		})
	}
}
