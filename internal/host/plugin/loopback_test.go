package plugin

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

// TestLoopbackPlugin is a quick test of basic functionality.
func TestLoopbackPlugin(t *testing.T) {
	require, assert := tr.New(t), ta.New(t)
	ctx := context.Background()

	plg := NewLoopbackPlugin()
	secretsMap := map[string]interface{}{
		"foo": "bar",
		"baz": true,
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

	// Add data to some sets
	hostInfo1 := map[string]interface{}{
		loopbackPluginHostInfoAttrField: map[string]interface{}{
			"set_ids":      []interface{}{"set1"},
			"external_id":  "host1",
			"ip_addresses": []interface{}{"1.2.3.4", "2.3.4.5"},
			"dns_names":    []interface{}{"foo.com"},
		},
	}
	attrs, err := structpb.NewStruct(hostInfo1)
	require.NoError(err)
	_, err = plg.OnCreateSet(ctx, &plgpb.OnCreateSetRequest{
		Set: &hostsets.HostSet{
			Id:         "set1",
			Attributes: attrs,
		},
	})
	require.NoError(err)
	hostInfo2 := map[string]interface{}{
		loopbackPluginHostInfoAttrField: map[string]interface{}{
			"set_ids":      []interface{}{"set2"},
			"external_id":  "host2",
			"ip_addresses": []interface{}{"5.6.7.8", "6.7.8.9"},
			"dns_names":    []interface{}{"bar.com"},
		},
	}
	attrs, err = structpb.NewStruct(hostInfo2)
	require.NoError(err)
	_, err = plg.OnCreateSet(ctx, &plgpb.OnCreateSetRequest{
		Set: &hostsets.HostSet{
			Id:         "set2",
			Attributes: attrs,
		},
	})
	require.NoError(err)

	// Define test struct and validation function
	type testInfo struct {
		name  string
		sets  []string
		found []map[string]interface{}
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

		var found []map[string]interface{}
		for _, host := range resp.GetHosts() {
			hostMap := map[string]interface{}{
				"external_id": host.GetExternalId(),
			}
			var sets []interface{}
			for _, set := range host.SetIds {
				sets = append(sets, set)
			}
			var ips []interface{}
			for _, ip := range host.GetIpAddresses() {
				ips = append(ips, ip)
			}
			var names []interface{}
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
			found: []map[string]interface{}{
				hostInfo1[loopbackPluginHostInfoAttrField].(map[string]interface{}),
			},
		},
		{
			name: "set 2",
			sets: []string{"set2"},
			found: []map[string]interface{}{
				hostInfo2[loopbackPluginHostInfoAttrField].(map[string]interface{}),
			},
		},
		{
			name: "sets 1 and 2",
			sets: []string{"set1", "set2"},
			found: []map[string]interface{}{
				hostInfo1[loopbackPluginHostInfoAttrField].(map[string]interface{}),
				hostInfo2[loopbackPluginHostInfoAttrField].(map[string]interface{}),
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
			found: []map[string]interface{}{},
		},
		{
			name: "set 2 not deleted",
			sets: []string{"set2"},
			found: []map[string]interface{}{
				hostInfo2[loopbackPluginHostInfoAttrField].(map[string]interface{}),
			},
		},
		{
			name: "sets 1 and 2 set 1 deleted",
			sets: []string{"set1", "set2"},
			found: []map[string]interface{}{
				hostInfo2[loopbackPluginHostInfoAttrField].(map[string]interface{}),
			},
		},
	}
	for _, tt := range setTests {
		t.Run(tt.name, func(t *testing.T) {
			validateSets(t, tt)
		})
	}
}
