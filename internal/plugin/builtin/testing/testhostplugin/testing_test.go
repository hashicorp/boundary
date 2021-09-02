package testhostplugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	"github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/require"
)

// Implementation test.
var _ = plugin.HostPluginServiceClient((*TestHostPlugin)(nil))

// TestTestHostPlugin is an E2E test meant to simulate a "workflow"
// for using the test plugin.
func TestTestHostPlugin(t *testing.T) {
	require := require.New(t)
	// Create the initial client.
	client := NewClient()
	require.NotNil(client)

	ctx := context.Background()

	// All we're doing is validating responses, so just declare it as
	// interface{}.
	var resp interface{}

	// We're "creating" the catalog by running it through
	// OnCreateCatalog. Validate the response.
	resp, err := client.OnCreateCatalog(ctx, &plugin.OnCreateCatalogRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attributes: mapAsStruct(testExpectedCatalogAttributes),
		},
	})
	require.NoError(err)
	require.Equal(&plugin.OnCreateCatalogResponse{
		Persisted: &plugin.HostCatalogPersisted{
			Data: mapAsStruct(testExpectedPersisted),
		},
	}, resp)

	// Now we "update" it with the new data.
	resp, err = client.OnUpdateCatalog(ctx, &plugin.OnUpdateCatalogRequest{
		CurrentCatalog: &hostcatalogs.HostCatalog{
			Attributes: mapAsStruct(testExpectedCatalogAttributes),
		},
		NewCatalog: &hostcatalogs.HostCatalog{
			Attributes: mapAsStruct(testExpectedCatalogAttributesNew),
		},
		Persisted: &plugin.HostCatalogPersisted{
			Data: mapAsStruct(testExpectedPersisted),
		},
	})
	require.NoError(err)
	require.Equal(&plugin.OnUpdateCatalogResponse{
		Persisted: &plugin.HostCatalogPersisted{
			Data: mapAsStruct(testExpectedPersistedNew),
		},
	}, resp)

	// Now we "delete" it.
	resp, err = client.OnDeleteCatalog(ctx, &plugin.OnDeleteCatalogRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attributes: mapAsStruct(testExpectedCatalogAttributesNew),
		},
		Persisted: &plugin.HostCatalogPersisted{
			Data: mapAsStruct(testExpectedPersistedNew),
		},
	})
	require.NoError(err)
	require.Equal(&plugin.OnDeleteCatalogResponse{}, resp)

	// Let's imagine that the update/delete never happened, and let's
	// just create a set with the catalog.
	resp, err = client.OnCreateSet(ctx, &plugin.OnCreateSetRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attributes: mapAsStruct(testExpectedCatalogAttributes),
		},
		Set: &hostsets.HostSet{
			Attributes: mapAsStruct(testExpectedSetAttributes),
		},
		Persisted: &plugin.HostCatalogPersisted{
			Data: mapAsStruct(testExpectedPersisted),
		},
	})
	require.NoError(err)
	require.Equal(&plugin.OnCreateSetResponse{}, resp)

	// "Update" the set.
	resp, err = client.OnUpdateSet(ctx, &plugin.OnUpdateSetRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attributes: mapAsStruct(testExpectedCatalogAttributes),
		},
		CurrentSet: &hostsets.HostSet{
			Attributes: mapAsStruct(testExpectedSetAttributes),
		},
		NewSet: &hostsets.HostSet{
			Attributes: mapAsStruct(testExpectedSetAttributesNew),
		},
		Persisted: &plugin.HostCatalogPersisted{
			Data: mapAsStruct(testExpectedPersisted),
		},
	})
	require.NoError(err)
	require.Equal(&plugin.OnUpdateSetResponse{}, resp)

	// Now "delete" the set.
	resp, err = client.OnDeleteSet(ctx, &plugin.OnDeleteSetRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attributes: mapAsStruct(testExpectedCatalogAttributes),
		},
		Set: &hostsets.HostSet{
			Attributes: mapAsStruct(testExpectedSetAttributesNew),
		},
		Persisted: &plugin.HostCatalogPersisted{
			Data: mapAsStruct(testExpectedPersisted),
		},
	})
	require.NoError(err)
	require.Equal(&plugin.OnDeleteSetResponse{}, resp)

	// Now similar to the host catalog steps, let's just imagine the
	// update/delete didn't happen and list the hosts in the set.
	resp, err = client.ListHosts(ctx, &plugin.ListHostsRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attributes: mapAsStruct(testExpectedCatalogAttributes),
		},
		Sets: []*hostsets.HostSet{
			{
				Attributes: mapAsStruct(testExpectedSetAttributes),
			},
		},
		Persisted: &plugin.HostCatalogPersisted{
			Data: mapAsStruct(testExpectedPersisted),
		},
	})
	require.NoError(err)
	require.Equal(&plugin.ListHostsResponse{
		Hosts: []*plugin.ListHostsResponseHost{
			{
				ExternalId:  "host-foo",
				IpAddresses: []string{"10.0.0.100", "10.0.0.101"},
				Attributes: mapAsStruct(map[string]interface{}{
					"id": "foo",
				}),
			},
			{
				ExternalId:  "host-bar",
				IpAddresses: []string{"10.0.0.200", "10.0.0.201"},
				Attributes: mapAsStruct(map[string]interface{}{
					"id": "bar",
				}),
			},
		},
	}, resp)
}
