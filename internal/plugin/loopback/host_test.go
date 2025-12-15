// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package loopback

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	ta "github.com/stretchr/testify/assert"
	tr "github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

// TestLoopbackHostPlugin is a quick test of basic host service functionality.
func TestLoopbackHostPlugin(t *testing.T) {
	require, assert := tr.New(t), ta.New(t)
	ctx := context.Background()

	plg, err := NewLoopbackPlugin()
	require.NoError(err)
	secretsMap := map[string]any{
		"key1": "key2",
		"baz":  true,
	}
	secrets, err := structpb.NewStruct(secretsMap)
	require.NoError(err)

	// First, test that if we give it secrets, those secrets come back as
	// persisted data
	catResp, err := plg.OnCreateCatalog(ctx, &plgpb.OnCreateCatalogRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Secrets: secrets,
		},
	})
	require.NoError(err)
	require.NotNil(catResp)
	require.NotNil(catResp.GetPersisted())
	require.NotNil(catResp.GetPersisted().GetSecrets())
	assert.EqualValues(secretsMap, catResp.GetPersisted().GetSecrets().AsMap())

	newSecretsMap := map[string]any{
		"key1": "key2",
		"baz":  true,
	}
	newSecrets, err := structpb.NewStruct(newSecretsMap)
	require.NoError(err)

	// First, test that if we give it secrets, those secrets come back as
	// persisted data
	upResp, err := plg.OnUpdateCatalog(ctx, &plgpb.OnUpdateCatalogRequest{
		CurrentCatalog: &hostcatalogs.HostCatalog{},
		NewCatalog: &hostcatalogs.HostCatalog{
			Secrets: newSecrets,
		},
		Persisted: &plgpb.HostCatalogPersisted{
			Secrets: secrets,
		},
	})
	require.NoError(err)
	require.NotNil(upResp)
	require.NotNil(upResp.GetPersisted())
	require.NotNil(upResp.GetPersisted().GetSecrets())
	assert.EqualValues(newSecretsMap, upResp.GetPersisted().GetSecrets().AsMap())

	// Add data to some sets
	hostInfo1 := map[string]any{
		loopbackPluginHostInfoAttrField: map[string]any{
			"set_ids":      []any{"set1"},
			"external_id":  "host1",
			"ip_addresses": []any{"1.2.3.4", "2.3.4.5"},
			"dns_names":    []any{"foo.com"},
		},
	}
	attrs, err := structpb.NewStruct(hostInfo1)
	require.NoError(err)
	_, err = plg.OnCreateSet(ctx, &plgpb.OnCreateSetRequest{
		Set: &hostsets.HostSet{
			Id: "set1",
			Attrs: &hostsets.HostSet_Attributes{
				Attributes: attrs,
			},
		},
	})
	require.NoError(err)
	hostInfo2 := map[string]any{
		loopbackPluginHostInfoAttrField: map[string]any{
			"set_ids":      []any{"set2"},
			"external_id":  "host2",
			"ip_addresses": []any{"5.6.7.8", "6.7.8.9"},
			"dns_names":    []any{"bar.com"},
		},
	}
	attrs, err = structpb.NewStruct(hostInfo2)
	require.NoError(err)
	_, err = plg.OnCreateSet(ctx, &plgpb.OnCreateSetRequest{
		Set: &hostsets.HostSet{
			Id: "set2",
			Attrs: &hostsets.HostSet_Attributes{
				Attributes: attrs,
			},
		},
	})
	require.NoError(err)

	// Define test struct and validation function
	type testInfo struct {
		name  string
		sets  []string
		found []map[string]any
	}
	validateSets := func(t *testing.T, tt testInfo) {
		require, assert := tr.New(t), ta.New(t)
		var hostSets []*hostsets.HostSet
		for _, set := range tt.sets {
			hostSets = append(hostSets, &hostsets.HostSet{Id: set})
		}
		resp, err := plg.ListHosts(ctx, &plgpb.ListHostsRequest{
			Sets: hostSets,
		})
		require.NoError(err)
		if len(tt.found) == 0 {
			assert.Len(resp.GetHosts(), 0)
			return
		}

		require.Greater(len(resp.GetHosts()), 0)

		var found []map[string]any
		for _, host := range resp.GetHosts() {
			hostMap := map[string]any{
				"external_id": host.GetExternalId(),
			}
			var sets []any
			for _, set := range host.SetIds {
				sets = append(sets, set)
			}
			var ips []any
			for _, ip := range host.GetIpAddresses() {
				ips = append(ips, ip)
			}
			var names []any
			for _, name := range host.GetDnsNames() {
				names = append(names, name)
			}
			if len(sets) > 0 {
				hostMap["set_ids"] = sets
			}
			if len(ips) > 0 {
				hostMap["ip_addresses"] = ips
			}
			if len(names) > 0 {
				hostMap["dns_names"] = names
			}
			found = append(found, hostMap)
		}
		assert.ElementsMatch(tt.found, found)
	}

	// First set of tests: check that we can look up sets individually and
	// together
	setTests := []testInfo{
		{
			name: "set 1",
			sets: []string{"set1"},
			found: []map[string]any{
				hostInfo1[loopbackPluginHostInfoAttrField].(map[string]any),
			},
		},
		{
			name: "set 2",
			sets: []string{"set2"},
			found: []map[string]any{
				hostInfo2[loopbackPluginHostInfoAttrField].(map[string]any),
			},
		},
		{
			name: "sets 1 and 2",
			sets: []string{"set1", "set2"},
			found: []map[string]any{
				hostInfo1[loopbackPluginHostInfoAttrField].(map[string]any),
				hostInfo2[loopbackPluginHostInfoAttrField].(map[string]any),
			},
		},
	}
	for _, tt := range setTests {
		t.Run(tt.name, func(t *testing.T) {
			validateSets(t, tt)
		})
	}

	// Remove a set
	_, err = plg.OnDeleteSet(ctx, &plgpb.OnDeleteSetRequest{
		Set: &hostsets.HostSet{
			Id: "set1",
		},
	})
	require.NoError(err)

	// Run tests again, making sure we no longer find that host either
	// individually or together
	setTests = []testInfo{
		{
			name:  "set 1 deleted",
			sets:  []string{"set1"},
			found: []map[string]any{},
		},
		{
			name: "set 2 not deleted",
			sets: []string{"set2"},
			found: []map[string]any{
				hostInfo2[loopbackPluginHostInfoAttrField].(map[string]any),
			},
		},
		{
			name: "sets 1 and 2 set 1 deleted",
			sets: []string{"set1", "set2"},
			found: []map[string]any{
				hostInfo2[loopbackPluginHostInfoAttrField].(map[string]any),
			},
		},
	}
	for _, tt := range setTests {
		t.Run(tt.name, func(t *testing.T) {
			validateSets(t, tt)
		})
	}
}

func TestLoopbackHostPluginArrays(t *testing.T) {
	require := tr.New(t)
	ctx := context.Background()

	plg, err := NewLoopbackPlugin()
	require.NoError(err)

	// Add data to some sets
	hostInfo1 := map[string]any{
		loopbackPluginHostInfoAttrField: []any{
			map[string]any{
				"set_ids":      []any{"set1"},
				"external_id":  "host1a",
				"ip_addresses": []any{"1.2.3.4", "2.3.4.5"},
				"dns_names":    []any{"foo.com"},
			},
			map[string]any{
				"set_ids":      []any{"set1"},
				"external_id":  "host1b",
				"ip_addresses": []any{"3.4.5.6", "4.5.6.7"},
				"dns_names":    []any{"bar.com"},
			},
		},
	}
	attrs, err := structpb.NewStruct(hostInfo1)
	require.NoError(err)
	_, err = plg.OnCreateSet(ctx, &plgpb.OnCreateSetRequest{
		Set: &hostsets.HostSet{
			Id: "set1",
			Attrs: &hostsets.HostSet_Attributes{
				Attributes: attrs,
			},
		},
	})
	require.NoError(err)
	hostInfo2 := map[string]any{
		loopbackPluginHostInfoAttrField: []any{
			map[string]any{
				"set_ids":      []any{"set2"},
				"external_id":  "host2a",
				"ip_addresses": []any{"10.20.30.40", "20.30.40.50"},
				"dns_names":    []any{"foz.com"},
			},
			map[string]any{
				"set_ids":      []any{"set2"},
				"external_id":  "host2b",
				"ip_addresses": []any{"30.40.50.60", "40.50.60.70"},
				"dns_names":    []any{"baz.com"},
			},
		},
	}
	attrs, err = structpb.NewStruct(hostInfo2)
	require.NoError(err)
	_, err = plg.OnCreateSet(ctx, &plgpb.OnCreateSetRequest{
		Set: &hostsets.HostSet{
			Id: "set2",
			Attrs: &hostsets.HostSet_Attributes{
				Attributes: attrs,
			},
		},
	})
	require.NoError(err)

	// Define test struct and validation function
	type testInfo struct {
		name  string
		sets  []string
		found []any
	}
	validateSets := func(t *testing.T, tt testInfo) {
		require, assert := tr.New(t), ta.New(t)
		var hostSets []*hostsets.HostSet
		for _, set := range tt.sets {
			hostSets = append(hostSets, &hostsets.HostSet{Id: set})
		}
		resp, err := plg.ListHosts(ctx, &plgpb.ListHostsRequest{
			Sets: hostSets,
		})
		require.NoError(err)
		if len(tt.found) == 0 {
			assert.Len(resp.GetHosts(), 0)
			return
		}

		require.Greater(len(resp.GetHosts()), 0)

		var found []any
		for _, host := range resp.GetHosts() {
			hostMap := map[string]any{
				"external_id": host.GetExternalId(),
			}
			var sets []any
			for _, set := range host.SetIds {
				sets = append(sets, set)
			}
			var ips []any
			for _, ip := range host.GetIpAddresses() {
				ips = append(ips, ip)
			}
			var names []any
			for _, name := range host.GetDnsNames() {
				names = append(names, name)
			}
			if len(sets) > 0 {
				hostMap["set_ids"] = sets
			}
			if len(ips) > 0 {
				hostMap["ip_addresses"] = ips
			}
			if len(names) > 0 {
				hostMap["dns_names"] = names
			}
			found = append(found, hostMap)
		}
		assert.ElementsMatch(tt.found, found)
	}

	// First set of tests: check that we can look up sets individually and
	// together
	setTests := []testInfo{
		{
			name:  "set 1",
			sets:  []string{"set1"},
			found: hostInfo1[loopbackPluginHostInfoAttrField].([]any),
		},
		{
			name:  "set 2",
			sets:  []string{"set2"},
			found: hostInfo2[loopbackPluginHostInfoAttrField].([]any),
		},
		{
			name: "sets 1 and 2",
			sets: []string{"set1", "set2"},
			found: append(hostInfo1[loopbackPluginHostInfoAttrField].([]any),
				hostInfo2[loopbackPluginHostInfoAttrField].([]any)...),
		},
	}
	for _, tt := range setTests {
		t.Run(tt.name, func(t *testing.T) {
			validateSets(t, tt)
		})
	}
}
