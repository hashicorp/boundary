package testhostplugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/plugin/proto"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	"github.com/stretchr/testify/require"
)

// Implementation test.
var _ = proto.HostPluginServiceClient((*TestHostPlugin)(nil))

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
	resp, err := client.OnCreateCatalog(ctx, &proto.OnCreateCatalogRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attributes: mapAsStruct(testExpectedCatalogAttributes),
		},
	})
	require.NoError(err)
	require.Equal(&proto.OnCreateCatalogResponse{
		Persisted: &proto.HostCatalogPersisted{
			Data: mapAsStruct(testExpectedPersisted),
		},
	}, resp)

	// Now we "update" it with the new data.
	resp, err = client.OnUpdateCatalog(ctx, &proto.OnUpdateCatalogRequest{
		CurrentCatalog: &hostcatalogs.HostCatalog{
			Attributes: mapAsStruct(testExpectedCatalogAttributes),
		},
		NewCatalog: &hostcatalogs.HostCatalog{
			Attributes: mapAsStruct(testExpectedCatalogAttributesNew),
		},
		Persisted: &proto.HostCatalogPersisted{
			Data: mapAsStruct(testExpectedPersisted),
		},
	})
	require.NoError(err)
	require.Equal(&proto.OnUpdateCatalogResponse{
		Persisted: &proto.HostCatalogPersisted{
			Data: mapAsStruct(testExpectedPersistedNew),
		},
	}, resp)

	// Now we "delete" it.
	resp, err = client.OnDeleteCatalog(ctx, &proto.OnDeleteCatalogRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attributes: mapAsStruct(testExpectedCatalogAttributesNew),
		},
		Persisted: &proto.HostCatalogPersisted{
			Data: mapAsStruct(testExpectedPersistedNew),
		},
	})
	require.NoError(err)
	require.Equal(&proto.OnDeleteCatalogResponse{}, resp)

	// Let's imagine that the update/delete never happened, and let's
	// just create a set with the catalog.
	resp, err = client.OnCreateSet(ctx, &proto.OnCreateSetRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attributes: mapAsStruct(testExpectedCatalogAttributes),
		},
		Set: &hostsets.HostSet{
			Attributes: mapAsStruct(testExpectedSetAttributes),
		},
		Persisted: &proto.HostCatalogPersisted{
			Data: mapAsStruct(testExpectedPersisted),
		},
	})
	require.NoError(err)
	require.Equal(&proto.OnCreateSetResponse{}, resp)

	// "Update" the set.
	resp, err = client.OnUpdateSet(ctx, &proto.OnUpdateSetRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attributes: mapAsStruct(testExpectedCatalogAttributes),
		},
		CurrentSet: &hostsets.HostSet{
			Attributes: mapAsStruct(testExpectedSetAttributes),
		},
		NewSet: &hostsets.HostSet{
			Attributes: mapAsStruct(testExpectedSetAttributesNew),
		},
		Persisted: &proto.HostCatalogPersisted{
			Data: mapAsStruct(testExpectedPersisted),
		},
	})
	require.NoError(err)
	require.Equal(&proto.OnUpdateSetResponse{}, resp)

	// Now "delete" the set.
	resp, err = client.OnDeleteSet(ctx, &proto.OnDeleteSetRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attributes: mapAsStruct(testExpectedCatalogAttributes),
		},
		Set: &hostsets.HostSet{
			Attributes: mapAsStruct(testExpectedSetAttributesNew),
		},
		Persisted: &proto.HostCatalogPersisted{
			Data: mapAsStruct(testExpectedPersisted),
		},
	})
	require.NoError(err)
	require.Equal(&proto.OnDeleteSetResponse{}, resp)

	// Now similar to the host catalog steps, let's just imagine the
	// update/delete didn't happen and list the hosts in the set.
	resp, err = client.ListHosts(ctx, &proto.ListHostsRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attributes: mapAsStruct(testExpectedCatalogAttributes),
		},
		Sets: []*hostsets.HostSet{
			&hostsets.HostSet{
				Attributes: mapAsStruct(testExpectedSetAttributes),
			},
		},
		Persisted: &proto.HostCatalogPersisted{
			Data: mapAsStruct(testExpectedPersisted),
		},
	})
	require.NoError(err)
	require.Equal(&proto.ListHostsResponse{
		Hosts: []*proto.ListHostsResponseHost{
			&proto.ListHostsResponseHost{
				ExternalId: "host-foo",
				Address:    "10.0.0.100",
				Attributes: mapAsStruct(map[string]interface{}{
					"id": "foo",
				}),
			},
			&proto.ListHostsResponseHost{
				ExternalId: "host-bar",
				Address:    "10.0.0.101",
				Attributes: mapAsStruct(map[string]interface{}{
					"id": "bar",
				}),
			},
		},
	}, resp)
}
