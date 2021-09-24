package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin/host"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCatalog creates count number of plugin host catalogs to the provided DB
// with the provided scope id.  If any errors are encountered during the creation of
// the host catalog, the test will fail.
func TestCatalog(t *testing.T, conn *gorm.DB, scopeId, pluginId string, opt ...Option) *HostCatalog {
	t.Helper()
	ctx := context.Background()
	w := db.New(conn)

	cat, err := NewHostCatalog(ctx, scopeId, pluginId, opt...)
	require.NoError(t, err)
	assert.NotNil(t, cat)

	plg := host.NewPlugin()
	plg.PublicId = pluginId
	require.NoError(t, w.LookupByPublicId(ctx, plg))

	id, err := newHostCatalogId(ctx)
	assert.NoError(t, err)
	assert.NotEmpty(t, id)
	cat.PublicId = id

	require.NoError(t, w.Create(ctx, cat))
	return cat
}

// TestSet creates a plugin host sets in the provided DB
// with the provided catalog id. The catalog must have been created
// previously. The test will fail if any errors are encountered.
func TestSet(t *testing.T, conn *gorm.DB, kmsCache *kms.Kms, hc *HostCatalog, plgm map[string]plgpb.HostPluginServiceServer, opt ...Option) *HostSet {
	t.Helper()
	require := require.New(t)
	ctx := context.Background()
	rw := db.New(conn)

	repo, err := NewRepository(rw, rw, kmsCache, plgm)
	require.NoError(err)

	set, err := NewHostSet(ctx, hc.PublicId, opt...)
	require.NoError(err)
	require.NotNil(set)

	plg := host.NewPlugin()
	plg.PublicId = hc.GetPluginId()
	require.NoError(rw.LookupByPublicId(ctx, plg))

	id, err := newHostSetId(ctx)
	require.NoError(err)
	require.NotEmpty(id)

	set, _, err = repo.CreateSet(ctx, hc.ScopeId, set, opt...)
	require.NoError(err)

	return set
}

var _ plgpb.HostPluginServiceServer = (*TestPluginServer)(nil)

// TestPluginServer provides a host plugin service server where each method can be overwritten for tests.
type TestPluginServer struct {
	OnCreateCatalogFn func(context.Context, *plgpb.OnCreateCatalogRequest) (*plgpb.OnCreateCatalogResponse, error)
	OnUpdateCatalogFn func(context.Context, *plgpb.OnUpdateCatalogRequest) (*plgpb.OnUpdateCatalogResponse, error)
	OnDeleteCatalogFn func(context.Context, *plgpb.OnDeleteCatalogRequest) (*plgpb.OnDeleteCatalogResponse, error)
	OnCreateSetFn     func(context.Context, *plgpb.OnCreateSetRequest) (*plgpb.OnCreateSetResponse, error)
	OnUpdateSetFn     func(context.Context, *plgpb.OnUpdateSetRequest) (*plgpb.OnUpdateSetResponse, error)
	OnDeleteSetFn     func(context.Context, *plgpb.OnDeleteSetRequest) (*plgpb.OnDeleteSetResponse, error)
	ListHostsFn       func(context.Context, *plgpb.ListHostsRequest) (*plgpb.ListHostsResponse, error)
	plgpb.UnimplementedHostPluginServiceServer
}

func (t TestPluginServer) OnCreateCatalog(ctx context.Context, req *plgpb.OnCreateCatalogRequest) (*plgpb.OnCreateCatalogResponse, error) {
	if t.OnCreateCatalogFn == nil {
		return t.UnimplementedHostPluginServiceServer.OnCreateCatalog(ctx, req)
	}
	return t.OnCreateCatalogFn(ctx, req)
}

func (t TestPluginServer) OnUpdateCatalog(ctx context.Context, req *plgpb.OnUpdateCatalogRequest) (*plgpb.OnUpdateCatalogResponse, error) {
	if t.OnUpdateCatalogFn == nil {
		return t.UnimplementedHostPluginServiceServer.OnUpdateCatalog(ctx, req)
	}
	return t.OnUpdateCatalogFn(ctx, req)
}

func (t TestPluginServer) OnDeleteCatalog(ctx context.Context, req *plgpb.OnDeleteCatalogRequest) (*plgpb.OnDeleteCatalogResponse, error) {
	if t.OnDeleteCatalogFn == nil {
		return t.UnimplementedHostPluginServiceServer.OnDeleteCatalog(ctx, req)
	}
	return t.OnDeleteCatalogFn(ctx, req)
}

func (t TestPluginServer) OnCreateSet(ctx context.Context, req *plgpb.OnCreateSetRequest) (*plgpb.OnCreateSetResponse, error) {
	if t.OnCreateSetFn == nil {
		return t.UnimplementedHostPluginServiceServer.OnCreateSet(ctx, req)
	}
	return t.OnCreateSetFn(ctx, req)
}

func (t TestPluginServer) OnUpdateSet(ctx context.Context, req *plgpb.OnUpdateSetRequest) (*plgpb.OnUpdateSetResponse, error) {
	if t.OnUpdateSetFn == nil {
		return t.UnimplementedHostPluginServiceServer.OnUpdateSet(ctx, req)
	}
	return t.OnUpdateSetFn(ctx, req)
}

func (t TestPluginServer) OnDeleteSet(ctx context.Context, req *plgpb.OnDeleteSetRequest) (*plgpb.OnDeleteSetResponse, error) {
	if t.OnDeleteSetFn == nil {
		return t.UnimplementedHostPluginServiceServer.OnDeleteSet(ctx, req)
	}
	return t.OnDeleteSetFn(ctx, req)
}

func (t TestPluginServer) ListHosts(ctx context.Context, req *plgpb.ListHostsRequest) (*plgpb.ListHostsResponse, error) {
	if t.ListHostsFn == nil {
		return t.UnimplementedHostPluginServiceServer.ListHosts(ctx, req)
	}
	return t.ListHostsFn(ctx, req)
}
