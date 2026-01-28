// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/plugin/loopback"
	"github.com/hashicorp/boundary/internal/scheduler"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestCatalogs(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(proj)
	assert.NotEmpty(proj.GetPublicId())

	plg := plugin.TestPlugin(t, conn, "test")
	require.NotNil(plg)
	assert.NotEmpty(plg.GetPublicId())

	cs := TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId(), WithName("foo"), WithDescription("bar"))
	assert.NotEmpty(cs.GetPublicId())
	db.AssertPublicId(t, globals.PluginHostCatalogPrefix, cs.GetPublicId())
	assert.Equal("foo", cs.GetName())
	assert.Equal("bar", cs.GetDescription())
}

func Test_TestSet(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	kmsCache := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	plg := plugin.TestPlugin(t, conn, "test")
	require.NotNil(plg)
	assert.NotEmpty(plg.GetPublicId())

	c := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())
	set := TestSet(t, conn, kmsCache, sched, c, map[string]plgpb.HostPluginServiceClient{plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&loopback.TestPluginServer{})}, WithName("foo"), WithDescription("bar"))
	assert.NotEmpty(set.GetPublicId())
	db.AssertPublicId(t, globals.PluginHostSetPrefix, set.GetPublicId())
	assert.Equal("foo", set.GetName())
	assert.Equal("bar", set.GetDescription())
}

func Test_TestHosts(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	plg := plugin.TestPlugin(t, conn, "test")
	require.NotNil(plg)
	assert.NotEmpty(plg.GetPublicId())

	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	c := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())

	h := TestHost(t, conn, c.GetPublicId(), plg.GetPublicId())
	assert.NotEmpty(h.GetPublicId())
}

func Test_TestSetMembers(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	kmsCache := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	plg := plugin.TestPlugin(t, conn, "test")
	require.NotNil(plg)
	assert.NotEmpty(plg.GetPublicId())

	c := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())
	s := TestSet(t, conn, kmsCache, sched, c, map[string]plgpb.HostPluginServiceClient{plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&loopback.TestPluginServer{})})

	h := TestHost(t, conn, c.GetPublicId(), plg.GetPublicId())
	members := TestSetMembers(t, conn, s.PublicId, []*Host{h})
	assert.Len(members, 1)
	assert.Equal(h.GetPublicId(), members[0].GetHostId())
	assert.Equal(s.GetPublicId(), members[0].GetSetId())
}

func Test_TestRunSetSync(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	kmsCache := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	plg := plugin.TestPlugin(t, conn, "test")
	require.NotNil(plg)
	assert.NotEmpty(plg.GetPublicId())
	pluginServer := &loopback.TestPluginServer{}
	plgm := map[string]plgpb.HostPluginServiceClient{plg.GetPublicId(): loopback.NewWrappingPluginHostClient(pluginServer)}

	c := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())
	s1 := TestSet(t, conn, kmsCache, sched, c, plgm)
	s2 := TestSet(t, conn, kmsCache, sched, c, plgm)

	pluginServer.ListHostsFn = func(ctx context.Context, req *plgpb.ListHostsRequest) (*plgpb.ListHostsResponse, error) {
		var setIds []string
		for _, s := range req.GetSets() {
			setIds = append(setIds, s.GetId())
		}
		resp := &plgpb.ListHostsResponse{Hosts: []*plgpb.ListHostsResponseHost{
			{
				ExternalId:  "test",
				SetIds:      setIds,
				IpAddresses: []string{"10.0.0.1"},
			},
		}}
		return resp, nil
	}

	TestRunSetSync(t, conn, kmsCache, plgm)
	rw := db.New(conn)
	var ha []*hostAgg
	require.NoError(rw.SearchWhere(context.Background(), &ha, "true", nil))
	require.Len(ha, 1)
	assert.ElementsMatch(ha[0].toHost().SetIds, []string{s1.GetPublicId(), s2.GetPublicId()})
}
