package plugin

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin/host"
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

	plg := host.TestPlugin(t, conn, "test")
	require.NotNil(plg)
	assert.NotEmpty(plg.GetPublicId())

	cs := TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId(), WithName("foo"), WithDescription("bar"))
	assert.NotEmpty(cs.GetPublicId())
	db.AssertPublicId(t, HostCatalogPrefix, cs.GetPublicId())
	assert.Equal("foo", cs.GetName())
	assert.Equal("bar", cs.GetDescription())
}

func Test_TestSet(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	plg := host.TestPlugin(t, conn, "test")
	require.NotNil(plg)
	assert.NotEmpty(plg.GetPublicId())

	c := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())
	set := TestSet(t, conn, kmsCache, c, map[string]plgpb.HostPluginServiceClient{plg.GetPublicId(): NewWrappingPluginClient(&TestPluginServer{})}, WithName("foo"), WithDescription("bar"))
	assert.NotEmpty(set.GetPublicId())
	db.AssertPublicId(t, HostSetPrefix, set.GetPublicId())
	assert.Equal("foo", set.GetName())
	assert.Equal("bar", set.GetDescription())
}

func Test_TestHosts(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	plg := host.TestPlugin(t, conn, "test")
	require.NotNil(plg)
	assert.NotEmpty(plg.GetPublicId())

	require.NotNil(org)
	assert.NotEmpty(org.GetPublicId())

	c := TestCatalog(t, conn, org.GetPublicId(), plg.GetPublicId())

	h := TestHost(t, conn, c.GetPublicId(), plg.GetPublicId())
	assert.NotEmpty(h.GetPublicId())
}

func Test_TestSetMembers(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	plg := host.TestPlugin(t, conn, "test")
	require.NotNil(plg)
	assert.NotEmpty(plg.GetPublicId())

	c := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())
	s := TestSet(t, conn, kmsCache, c, map[string]plgpb.HostPluginServiceClient{plg.GetPublicId(): NewWrappingPluginClient(&TestPluginServer{})})

	h := TestHost(t, conn, c.GetPublicId(), plg.GetPublicId())
	members := TestSetMembers(t, conn, s.PublicId, []*Host{h})
	assert.Len(members, 1)
	assert.Equal(h.GetPublicId(), members[0].GetHostId())
	assert.Equal(s.GetPublicId(), members[0].GetSetId())
}
