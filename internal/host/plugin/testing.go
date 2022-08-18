package plugin

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sort"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/kms"
	hostplugin "github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/hashicorp/boundary/internal/scheduler"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCatalogs creates count number of static host catalogs to the provided DB
// with the provided scope id.  If any errors are encountered during the creation of
// the host catalog, the test will fail.
func TestCatalogs(t testing.TB, conn *db.DB, scopeId, pluginId string, count int) []*HostCatalog {
	t.Helper()
	var cats []*HostCatalog
	for i := 0; i < count; i++ {
		cats = append(cats, TestCatalog(t, conn, scopeId, pluginId))
	}
	return cats
}

// TestCatalog creates a plugin host catalogs to the provided DB
// with the provided scope id.  If any errors are encountered during the creation of
// the host catalog, the test will fail.
func TestCatalog(t testing.TB, conn *db.DB, scopeId, pluginId string, opt ...Option) *HostCatalog {
	t.Helper()
	ctx := context.Background()
	w := db.New(conn)

	cat, err := NewHostCatalog(ctx, scopeId, pluginId, opt...)
	require.NoError(t, err)
	assert.NotNil(t, cat)

	plg := hostplugin.NewPlugin()
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
func TestSet(t testing.TB, conn *db.DB, kmsCache *kms.Kms, sched *scheduler.Scheduler, hc *HostCatalog, plgm map[string]plgpb.HostPluginServiceClient, opt ...Option) *HostSet {
	t.Helper()
	require := require.New(t)
	ctx := context.Background()
	rw := db.New(conn)

	repo, err := NewRepository(rw, rw, kmsCache, sched, plgm)
	require.NoError(err)

	set, err := NewHostSet(ctx, hc.PublicId, opt...)
	require.NoError(err)
	require.NotNil(set)

	plg := hostplugin.NewPlugin()
	plg.PublicId = hc.GetPluginId()
	require.NoError(rw.LookupByPublicId(ctx, plg))

	id, err := newHostSetId(ctx)
	require.NoError(err)
	require.NotEmpty(id)

	set, _, err = repo.CreateSet(ctx, hc.ScopeId, set, opt...)
	require.NoError(err)

	return set
}

// TestSetMembers adds hosts to the specified setId in the provided DB.
// The set and hosts must have been created previously and belong to the
// same catalog. The test will fail if any errors are encountered.
func TestSetMembers(t testing.TB, conn *db.DB, setId string, hosts []*Host) []*HostSetMember {
	t.Helper()
	assert := assert.New(t)

	var members []*HostSetMember
	for _, host := range hosts {
		member, err := NewHostSetMember(context.Background(), setId, host.PublicId)
		assert.NoError(err)
		assert.NotNil(member)

		w := db.New(conn)
		err2 := w.Create(context.Background(), member)
		assert.NoError(err2)
		members = append(members, member)
	}
	return members
}

// TestHost creates a plugin host in the provided DB in the catalog with the
// provided catalog id. The catalog must have been created previously.
// The test will fail if any errors are encountered.
func TestHost(t testing.TB, conn *db.DB, catId, externId string, opt ...Option) *Host {
	t.Helper()
	w := db.New(conn)
	ctx := context.Background()
	host1 := NewHost(ctx, catId, externId, opt...)
	var err error
	host1.PublicId, err = newHostId(ctx, catId, externId)
	require.NoError(t, err)
	require.NoError(t, w.Create(ctx, host1))

	var ipAddresses []interface{}
	if len(host1.GetIpAddresses()) > 0 {
		sort.Strings(host1.IpAddresses)
		ipAddresses = make([]interface{}, 0, len(host1.GetIpAddresses()))
		for _, a := range host1.GetIpAddresses() {
			obj, err := host.NewIpAddress(ctx, host1.PublicId, a)
			require.NoError(t, err)
			ipAddresses = append(ipAddresses, obj)
		}
		require.NoError(t, w.CreateItems(ctx, ipAddresses))
	}

	var dnsNames []interface{}
	if len(host1.GetDnsNames()) > 0 {
		sort.Strings(host1.DnsNames)
		dnsNames = make([]interface{}, 0, len(host1.GetDnsNames()))
		for _, n := range host1.GetDnsNames() {
			obj, err := host.NewDnsName(ctx, host1.PublicId, n)
			require.NoError(t, err)
			dnsNames = append(dnsNames, obj)
		}
		require.NoError(t, w.CreateItems(ctx, dnsNames))
	}
	return host1
}

func TestExternalHosts(t testing.TB, catalog *HostCatalog, setIds []string, count int) ([]*plgpb.ListHostsResponseHost, []*Host) {
	t.Helper()
	require := require.New(t)
	retRH := make([]*plgpb.ListHostsResponseHost, 0, count)
	retH := make([]*Host, 0, count)
	if setIds == nil {
		// Prevent panics
		setIds = make([]string, 0)
	}

	for i := 0; i < count; i++ {
		externalId, err := base62.Random(10)
		require.NoError(err)

		ipStr := testGetIpAddress(t)
		dnsName := testGetDnsName(t)

		rh := &plgpb.ListHostsResponseHost{
			ExternalId:  externalId,
			Name:        base62.MustRandom(10),
			Description: base62.MustRandom(10),
			SetIds:      setIds[0 : i+1],
			IpAddresses: []string{ipStr},
			DnsNames:    []string{dnsName},
		}
		retRH = append(retRH, rh)

		publicId, err := newHostId(context.Background(), catalog.PublicId, externalId)
		require.NoError(err)

		retH = append(retH, &Host{
			PluginId: catalog.PluginId,
			SetIds:   setIds[0 : i+1],
			Host: &store.Host{
				Name:        rh.Name,
				Description: rh.Description,
				CatalogId:   catalog.PublicId,
				PublicId:    publicId,
				ExternalId:  externalId,
				IpAddresses: []string{ipStr},
				DnsNames:    []string{dnsName},
				Version:     1,
			},
		})
	}

	return retRH, retH
}

// TestRunSetSync runs the set sync job a single time.
func TestRunSetSync(t testing.TB, conn *db.DB, kmsCache *kms.Kms, plgm map[string]plgpb.HostPluginServiceClient) {
	t.Helper()
	rw := db.New(conn)
	ctx := context.Background()

	j, err := newSetSyncJob(ctx, rw, rw, kmsCache, plgm)
	require.NoError(t, err)
	require.NoError(t, j.Run(ctx))
}

func testGetDnsName(t testing.TB) string {
	dnsName, err := base62.Random(10)
	require.NoError(t, err)
	return fmt.Sprintf("%s.example.com", dnsName)
}

func testGetIpAddress(t testing.TB) string {
	ipBytes := make([]byte, 4)
	for {
		lr := io.LimitReader(rand.Reader, 4)
		n, err := lr.Read(ipBytes)
		require.NoError(t, err)
		require.Equal(t, n, 4)
		ip := net.IP(ipBytes)
		v4 := ip.To4()
		if v4 != nil {
			return v4.String()
		}
	}
}

var _ plgpb.HostPluginServiceServer = (*TestPluginServer)(nil)

// TestPluginServer provides a host plugin service server where each method can be overwritten for tests.
type TestPluginServer struct {
	NormalizeCatalogDataFn func(context.Context, *plgpb.NormalizeCatalogDataRequest) (*plgpb.NormalizeCatalogDataResponse, error)
	OnCreateCatalogFn      func(context.Context, *plgpb.OnCreateCatalogRequest) (*plgpb.OnCreateCatalogResponse, error)
	OnUpdateCatalogFn      func(context.Context, *plgpb.OnUpdateCatalogRequest) (*plgpb.OnUpdateCatalogResponse, error)
	OnDeleteCatalogFn      func(context.Context, *plgpb.OnDeleteCatalogRequest) (*plgpb.OnDeleteCatalogResponse, error)
	NormalizeSetDataFn     func(context.Context, *plgpb.NormalizeSetDataRequest) (*plgpb.NormalizeSetDataResponse, error)
	OnCreateSetFn          func(context.Context, *plgpb.OnCreateSetRequest) (*plgpb.OnCreateSetResponse, error)
	OnUpdateSetFn          func(context.Context, *plgpb.OnUpdateSetRequest) (*plgpb.OnUpdateSetResponse, error)
	OnDeleteSetFn          func(context.Context, *plgpb.OnDeleteSetRequest) (*plgpb.OnDeleteSetResponse, error)
	ListHostsFn            func(context.Context, *plgpb.ListHostsRequest) (*plgpb.ListHostsResponse, error)
	plgpb.UnimplementedHostPluginServiceServer
}

func (t TestPluginServer) NormalizeCatalogData(ctx context.Context, req *plgpb.NormalizeCatalogDataRequest) (*plgpb.NormalizeCatalogDataResponse, error) {
	if t.NormalizeCatalogDataFn == nil {
		return t.UnimplementedHostPluginServiceServer.NormalizeCatalogData(ctx, req)
	}
	return t.NormalizeCatalogDataFn(ctx, req)
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

func (t TestPluginServer) NormalizeSetData(ctx context.Context, req *plgpb.NormalizeSetDataRequest) (*plgpb.NormalizeSetDataResponse, error) {
	if t.NormalizeSetDataFn == nil {
		return t.UnimplementedHostPluginServiceServer.NormalizeSetData(ctx, req)
	}
	return t.NormalizeSetDataFn(ctx, req)
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
