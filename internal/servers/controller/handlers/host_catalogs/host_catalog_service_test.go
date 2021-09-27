package host_catalogs_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/hashicorp/boundary/internal/servers/controller/auth"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/host_catalogs"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/plugins"
	scopepb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var authorizedCollectionActions = map[string]*structpb.ListValue{
	"host-sets": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"hosts": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
}

var testAuthorizedActions = []string{"no-op", "read", "update", "delete"}

func TestGet_Static(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	rw := db.New(conn)
	repo := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	pluginHostRepo := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, new(host.PluginMap))
	}
	pluginRepo := func() (*host.Repository, error) {
		return host.NewRepository(rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]

	toMerge := &pbs.GetHostCatalogRequest{
		Id: hc.GetPublicId(),
	}

	pHostCatalog := &pb.HostCatalog{
		Id:                          hc.GetPublicId(),
		ScopeId:                     hc.GetScopeId(),
		Scope:                       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
		CreatedTime:                 hc.CreateTime.GetTimestamp(),
		UpdatedTime:                 hc.UpdateTime.GetTimestamp(),
		Type:                        "static",
		AuthorizedActions:           testAuthorizedActions,
		AuthorizedCollectionActions: authorizedCollectionActions,
	}

	cases := []struct {
		name string
		req  *pbs.GetHostCatalogRequest
		res  *pbs.GetHostCatalogResponse
		err  error
	}{
		{
			name: "Get an Existing HostCatalog",
			req:  &pbs.GetHostCatalogRequest{Id: hc.GetPublicId()},
			res:  &pbs.GetHostCatalogResponse{Item: pHostCatalog},
		},
		{
			name: "Get a non existing Host Catalog",
			req:  &pbs.GetHostCatalogRequest{Id: static.HostCatalogPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Wrong id prefix",
			req:  &pbs.GetHostCatalogRequest{Id: "j_1234567890"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "space in id",
			req:  &pbs.GetHostCatalogRequest{Id: static.HostCatalogPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.GetHostCatalogRequest)
			proto.Merge(req, tc.req)

			s, err := host_catalogs.NewService(repo, pluginHostRepo, pluginRepo, iamRepoFn)
			require.NoError(err, "Couldn't create a new host catalog service.")

			got, gErr := s.GetHostCatalog(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetHostCatalog(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}

			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestGet_Plugin(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	rw := db.New(conn)
	repo := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	pluginHostRepo := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, new(host.PluginMap))
	}
	pluginRepo := func() (*host.Repository, error) {
		return host.NewRepository(rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	name := "test"
	plg := host.TestPlugin(t, conn, name)
	hc := plugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())

	toMerge := &pbs.GetHostCatalogRequest{
		Id: hc.GetPublicId(),
	}

	pHostCatalog := &pb.HostCatalog{
		Id:      hc.GetPublicId(),
		ScopeId: hc.GetScopeId(),
		Scope: &scopepb.ScopeInfo{
			Id:            proj.GetPublicId(),
			Type:          scope.Project.String(),
			ParentScopeId: proj.GetParentId(),
		},
		PluginId: plg.GetPublicId(),
		Plugin: &plugins.PluginInfo{
			Id:          plg.GetPublicId(),
			Name:        plg.GetName(),
			Description: plg.GetDescription(),
		},
		CreatedTime:                 hc.CreateTime.GetTimestamp(),
		UpdatedTime:                 hc.UpdateTime.GetTimestamp(),
		Type:                        plugin.Subtype.String(),
		AuthorizedActions:           testAuthorizedActions,
		AuthorizedCollectionActions: authorizedCollectionActions,
	}

	cases := []struct {
		name string
		req  *pbs.GetHostCatalogRequest
		res  *pbs.GetHostCatalogResponse
		err  error
	}{
		{
			name: "Get an Existing HostCatalog",
			req:  &pbs.GetHostCatalogRequest{Id: hc.GetPublicId()},
			res:  &pbs.GetHostCatalogResponse{Item: pHostCatalog},
		},
		{
			name: "Get a non existing Host Catalog",
			req:  &pbs.GetHostCatalogRequest{Id: plugin.HostCatalogPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Wrong id prefix",
			req:  &pbs.GetHostCatalogRequest{Id: "j_1234567890"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "space in id",
			req:  &pbs.GetHostCatalogRequest{Id: plugin.HostCatalogPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.GetHostCatalogRequest)
			proto.Merge(req, tc.req)

			s, err := host_catalogs.NewService(repo, pluginHostRepo, pluginRepo, iamRepoFn)
			require.NoError(err, "Couldn't create a new host catalog service.")

			got, gErr := s.GetHostCatalog(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetHostCatalog(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}

			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	pluginHostRepo := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, new(host.PluginMap))
	}
	pluginRepo := func() (*host.Repository, error) {
		return host.NewRepository(rw, rw, kms)
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, pNoCatalogs := iam.TestScopes(t, iamRepo)
	oWithCatalogs, pWithCatalogs := iam.TestScopes(t, iamRepo)
	oWithOtherCatalogs, pWithOtherCatalogs := iam.TestScopes(t, iamRepo)

	var wantSomeCatalogs []*pb.HostCatalog
	for _, hc := range static.TestCatalogs(t, conn, pWithCatalogs.GetPublicId(), 3) {
		wantSomeCatalogs = append(wantSomeCatalogs, &pb.HostCatalog{
			Id:                          hc.GetPublicId(),
			ScopeId:                     hc.GetScopeId(),
			CreatedTime:                 hc.GetCreateTime().GetTimestamp(),
			UpdatedTime:                 hc.GetUpdateTime().GetTimestamp(),
			Scope:                       &scopepb.ScopeInfo{Id: pWithCatalogs.GetPublicId(), Type: scope.Project.String(), ParentScopeId: oWithCatalogs.GetPublicId()},
			Version:                     1,
			Type:                        "static",
			AuthorizedActions:           testAuthorizedActions,
			AuthorizedCollectionActions: authorizedCollectionActions,
		})
	}

	var testPluginCatalogs []*pb.HostCatalog
	name := "test"
	plg := host.TestPlugin(t, conn, name)
	for i := 0; i < 3; i++ {
		hc := plugin.TestCatalog(t, conn, pWithCatalogs.GetPublicId(), plg.GetPublicId())
		cat := &pb.HostCatalog{
			Id:          hc.GetPublicId(),
			ScopeId:     hc.GetScopeId(),
			CreatedTime: hc.GetCreateTime().GetTimestamp(),
			UpdatedTime: hc.GetUpdateTime().GetTimestamp(),
			Scope:       &scopepb.ScopeInfo{Id: pWithCatalogs.GetPublicId(), Type: scope.Project.String(), ParentScopeId: oWithCatalogs.GetPublicId()},
			PluginId:    plg.GetPublicId(),
			Plugin: &plugins.PluginInfo{
				Id:          plg.GetPublicId(),
				Name:        plg.GetName(),
				Description: plg.GetDescription(),
			},
			Version:                     1,
			Type:                        plugin.Subtype.String(),
			AuthorizedActions:           testAuthorizedActions,
			AuthorizedCollectionActions: authorizedCollectionActions,
		}
		wantSomeCatalogs = append(wantSomeCatalogs, cat)
		testPluginCatalogs = append(testPluginCatalogs, cat)
	}

	var wantOtherCatalogs []*pb.HostCatalog
	for _, hc := range static.TestCatalogs(t, conn, pWithOtherCatalogs.GetPublicId(), 3) {
		wantOtherCatalogs = append(wantOtherCatalogs, &pb.HostCatalog{
			Id:                          hc.GetPublicId(),
			ScopeId:                     hc.GetScopeId(),
			CreatedTime:                 hc.GetCreateTime().GetTimestamp(),
			UpdatedTime:                 hc.GetUpdateTime().GetTimestamp(),
			Scope:                       &scopepb.ScopeInfo{Id: pWithOtherCatalogs.GetPublicId(), Type: scope.Project.String(), ParentScopeId: oWithOtherCatalogs.GetPublicId()},
			Version:                     1,
			Type:                        "static",
			AuthorizedActions:           testAuthorizedActions,
			AuthorizedCollectionActions: authorizedCollectionActions,
		})
	}

	name = "different"
	diffPlg := host.TestPlugin(t, conn, name)
	for i := 0; i < 3; i++ {
		hc := plugin.TestCatalog(t, conn, pWithOtherCatalogs.GetPublicId(), diffPlg.GetPublicId())
		wantOtherCatalogs = append(wantOtherCatalogs, &pb.HostCatalog{
			Id:          hc.GetPublicId(),
			ScopeId:     hc.GetScopeId(),
			CreatedTime: hc.GetCreateTime().GetTimestamp(),
			UpdatedTime: hc.GetUpdateTime().GetTimestamp(),
			Scope:       &scopepb.ScopeInfo{Id: pWithOtherCatalogs.GetPublicId(), Type: scope.Project.String(), ParentScopeId: oWithOtherCatalogs.GetPublicId()},
			PluginId:    diffPlg.GetPublicId(),
			Plugin: &plugins.PluginInfo{
				Id:          diffPlg.GetPublicId(),
				Name:        diffPlg.GetName(),
				Description: diffPlg.GetDescription(),
			},
			Version:                     1,
			Type:                        plugin.Subtype.String(),
			AuthorizedActions:           testAuthorizedActions,
			AuthorizedCollectionActions: authorizedCollectionActions,
		})
	}

	cases := []struct {
		name string
		req  *pbs.ListHostCatalogsRequest
		res  *pbs.ListHostCatalogsResponse
		err  error
	}{
		{
			name: "List Some Catalogs",
			req:  &pbs.ListHostCatalogsRequest{ScopeId: pWithCatalogs.GetPublicId()},
			res:  &pbs.ListHostCatalogsResponse{Items: wantSomeCatalogs},
		},
		{
			name: "List Other Catalogs",
			req:  &pbs.ListHostCatalogsRequest{ScopeId: pWithOtherCatalogs.GetPublicId()},
			res:  &pbs.ListHostCatalogsResponse{Items: wantOtherCatalogs},
		},
		{
			name: "List No Catalogs",
			req:  &pbs.ListHostCatalogsRequest{ScopeId: pNoCatalogs.GetPublicId()},
			res:  &pbs.ListHostCatalogsResponse{},
		},
		{
			name: "Unfound Catalogs",
			req:  &pbs.ListHostCatalogsRequest{ScopeId: scope.Project.Prefix() + "_DoesntExis"},
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Bad scope level (not recursive)",
			req:  &pbs.ListHostCatalogsRequest{ScopeId: scope.Global.String()},
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "List recursively",
			req:  &pbs.ListHostCatalogsRequest{ScopeId: scope.Global.String(), Recursive: true},
			res: &pbs.ListHostCatalogsResponse{
				Items: append(wantSomeCatalogs, wantOtherCatalogs...),
			},
		},
		{
			name: "Filter To Some Catalogs",
			req: &pbs.ListHostCatalogsRequest{
				ScopeId: scope.Global.String(), Recursive: true,
				Filter: fmt.Sprintf(`"/item/scope/id"==%q`, pWithCatalogs.GetPublicId()),
			},
			res: &pbs.ListHostCatalogsResponse{Items: wantSomeCatalogs},
		},
		{
			name: "Filter To Catalog Using Test Plugin",
			req: &pbs.ListHostCatalogsRequest{
				ScopeId: scope.Global.String(), Recursive: true,
				Filter: `"/item/plugin/name"=="test"`,
			},
			res: &pbs.ListHostCatalogsResponse{Items: testPluginCatalogs},
		},
		{
			name: "Filter To No Catalogs",
			req:  &pbs.ListHostCatalogsRequest{ScopeId: pWithCatalogs.GetPublicId(), Filter: `"/item/id"=="doesnt match"`},
			res:  &pbs.ListHostCatalogsResponse{},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListHostCatalogsRequest{ScopeId: pWithCatalogs.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := host_catalogs.NewService(repoFn, pluginHostRepo, pluginRepo, iamRepoFn)
			require.NoError(err, "Couldn't create new auth_method service.")

			// Test with non-anon user
			got, gErr := s.ListHostCatalogs(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListHostCatalogs() for scope %q got error %v, wanted %v", tc.req.GetScopeId(), gErr, tc.err)
				return
			}
			sort.Slice(got.Items, func(i, j int) bool {
				return got.Items[i].GetId() < got.Items[j].GetId()
			})
			sort.Slice(tc.res.Items, func(i, j int) bool {
				return tc.res.Items[i].GetId() < tc.res.Items[j].GetId()
			})

			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListHostCatalogs() for scope %q got response %q, wanted %q", tc.req.GetScopeId(), got, tc.res)

			// Test with anon user
			got, gErr = s.ListHostCatalogs(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId(), auth.WithUserId("u_anon")), tc.req)
			require.NoError(gErr)
			assert.Len(got.Items, len(tc.res.Items))
			for _, item := range got.GetItems() {
				require.Nil(item.CreatedTime)
				require.Nil(item.UpdatedTime)
				require.Zero(item.Version)
			}
		})
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	rw := db.New(conn)
	repo := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	pluginHostRepo := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, new(host.PluginMap))
	}
	pluginRepo := func() (*host.Repository, error) {
		return host.NewRepository(rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]

	s, err := host_catalogs.NewService(repo, pluginHostRepo, pluginRepo, iamRepoFn)
	require.NoError(t, err, "Couldn't create a new host catalog service.")

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.DeleteHostCatalogRequest
		res     *pbs.DeleteHostCatalogResponse
		err     error
	}{
		{
			name:    "Delete an Existing HostCatalog",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostCatalogRequest{
				Id: hc.GetPublicId(),
			},
		},
		{
			name:    "Delete bad id HostCatalog",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostCatalogRequest{
				Id: static.HostCatalogPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Bad HostCatalog Id formatting",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostCatalogRequest{
				Id: static.HostCatalogPrefix + "_bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteHostCatalog(auth.DisabledAuthTestContext(iamRepoFn, tc.scopeId), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteHostCatalog(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.EqualValuesf(tc.res, got, "DeleteHostCatalog(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	rw := db.New(conn)
	repo := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	pluginHostRepo := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, new(host.PluginMap))
	}
	pluginRepo := func() (*host.Repository, error) {
		return host.NewRepository(rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]

	s, err := host_catalogs.NewService(repo, pluginHostRepo, pluginRepo, iamRepoFn)
	require.NoError(err, "Couldn't create a new host catalog service.")
	req := &pbs.DeleteHostCatalogRequest{
		Id: hc.GetPublicId(),
	}
	ctx := auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId())
	_, gErr := s.DeleteHostCatalog(ctx, req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteHostCatalog(ctx, req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")
}

func TestCreate_Static(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	rw := db.New(conn)
	repo := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	pluginHostRepo := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, new(host.PluginMap))
	}
	pluginRepo := func() (*host.Repository, error) {
		return host.NewRepository(rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	defaultHc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	defaultHcCreated := defaultHc.GetCreateTime().GetTimestamp().AsTime()
	toMerge := &pbs.CreateHostCatalogRequest{}

	cases := []struct {
		name string
		req  *pbs.CreateHostCatalogRequest
		res  *pbs.CreateHostCatalogResponse
		err  error
	}{
		{
			name: "Create a valid HostCatalog",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				ScopeId:     proj.GetPublicId(),
				Name:        &wrappers.StringValue{Value: "name"},
				Description: &wrappers.StringValue{Value: "desc"},
				Type:        "static",
			}},
			res: &pbs.CreateHostCatalogResponse{
				Uri: fmt.Sprintf("host-catalogs/%s_", static.HostCatalogPrefix),
				Item: &pb.HostCatalog{
					ScopeId:                     proj.GetPublicId(),
					Scope:                       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
					Name:                        &wrappers.StringValue{Value: "name"},
					Description:                 &wrappers.StringValue{Value: "desc"},
					Type:                        "static",
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Cant create in org",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				ScopeId:     proj.GetParentId(),
				Name:        &wrappers.StringValue{Value: "name"},
				Description: &wrappers.StringValue{Value: "desc"},
				Type:        "static",
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant create in global",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				ScopeId:     scope.Global.String(),
				Name:        &wrappers.StringValue{Value: "name"},
				Description: &wrappers.StringValue{Value: "desc"},
				Type:        "static",
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Create with unknown type",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				Name:        &wrappers.StringValue{Value: "name"},
				Description: &wrappers.StringValue{Value: "desc"},
				Type:        "thisismadeup",
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Create with no type",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				Name:        &wrappers.StringValue{Value: "name"},
				Description: &wrappers.StringValue{Value: "desc"},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				Id: "not allowed to be set",
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				CreatedTime: timestamppb.Now(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				UpdatedTime: timestamppb.Now(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.CreateHostCatalogRequest)
			proto.Merge(req, tc.req)

			s, err := host_catalogs.NewService(repo, pluginHostRepo, pluginRepo, iamRepoFn)
			require.NoError(err, "Failed to create a new host catalog service.")

			got, gErr := s.CreateHostCatalog(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateHostCatalog(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.GetUri())
				assert.True(strings.HasPrefix(got.GetItem().GetId(), static.HostCatalogPrefix))
				gotCreateTime := got.GetItem().GetCreatedTime().AsTime()
				require.NoError(err, "Error converting proto to timestamp.")
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
				require.NoError(err, "Error converting proto to timestamp")
				// Verify it is a catalog created after the test setup's default catalog
				assert.True(gotCreateTime.After(defaultHcCreated), "New catalog should have been created after default catalog. Was created %v, which is after %v", gotCreateTime, defaultHcCreated)
				assert.True(gotUpdateTime.After(defaultHcCreated), "New catalog should have been updated after default catalog. Was updated %v, which is after %v", gotUpdateTime, defaultHcCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestCreate_Plugin(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, proj := iam.TestScopes(t, iamRepo)
	rw := db.New(conn)
	repo := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	pluginRepo := func() (*host.Repository, error) {
		return host.NewRepository(rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	name := "test"
	plg := host.TestPlugin(t, conn, name)
	pluginHostRepo := func() (*plugin.Repository, error) {
		plgm := new(host.PluginMap)
		plgm.Set(plg.GetPublicId(), &plugin.TestPluginServer{
			OnCreateCatalogFn: func(ctx context.Context, req *plgpb.OnCreateCatalogRequest) (*plgpb.OnCreateCatalogResponse, error) {
				return nil, nil
			},
		})
		return plugin.NewRepository(rw, rw, kms, plgm)
	}
	defaultHc := plugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	defaultHcCreated := defaultHc.GetCreateTime().GetTimestamp().AsTime()
	toMerge := &pbs.CreateHostCatalogRequest{}

	cases := []struct {
		name string
		req  *pbs.CreateHostCatalogRequest
		res  *pbs.CreateHostCatalogResponse
		err  error
	}{
		{
			name: "Create a valid HostCatalog",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				ScopeId:     proj.GetPublicId(),
				Name:        &wrappers.StringValue{Value: "name"},
				Description: &wrappers.StringValue{Value: "desc"},
				Type:        plugin.Subtype.String(),
				PluginId:    plg.GetPublicId(),
			}},
			res: &pbs.CreateHostCatalogResponse{
				Uri: fmt.Sprintf("host-catalogs/%s_", plugin.HostCatalogPrefix),
				Item: &pb.HostCatalog{
					ScopeId:  proj.GetPublicId(),
					Scope:    &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
					PluginId: plg.GetPublicId(),
					Plugin: &plugins.PluginInfo{
						Id:          plg.GetPublicId(),
						Name:        plg.GetName(),
						Description: plg.GetDescription(),
					},
					Name:                        &wrappers.StringValue{Value: "name"},
					Description:                 &wrappers.StringValue{Value: "desc"},
					Type:                        plugin.Subtype.String(),
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Cant create in org",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				ScopeId:  org.GetParentId(),
				Type:     plugin.Subtype.String(),
				PluginId: plg.GetPublicId(),
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant create in global",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				ScopeId:  scope.Global.String(),
				Type:     plugin.Subtype.String(),
				PluginId: plg.GetPublicId(),
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Create with unknown type",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				ScopeId:  proj.GetPublicId(),
				PluginId: plg.GetPublicId(),
				Type:     "thisismadeup",
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Create with no type",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				ScopeId:  proj.GetPublicId(),
				PluginId: plg.GetPublicId(),
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				Id:       "not allowed to be set",
				ScopeId:  proj.GetPublicId(),
				Type:     plugin.Subtype.String(),
				PluginId: plg.GetPublicId(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				CreatedTime: timestamppb.Now(),
				ScopeId:     proj.GetPublicId(),
				Type:        plugin.Subtype.String(),
				PluginId:    plg.GetPublicId(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				UpdatedTime: timestamppb.Now(),
				ScopeId:     proj.GetPublicId(),
				Type:        plugin.Subtype.String(),
				PluginId:    plg.GetPublicId(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.CreateHostCatalogRequest)
			proto.Merge(req, tc.req)

			s, err := host_catalogs.NewService(repo, pluginHostRepo, pluginRepo, iamRepoFn)
			require.NoError(err, "Failed to create a new host catalog service.")

			got, gErr := s.CreateHostCatalog(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateHostCatalog(%+v) got error %v, wanted %v", req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.GetUri())
				assert.True(strings.HasPrefix(got.GetItem().GetId(), fmt.Sprintf("%s_", plugin.HostCatalogPrefix)))
				gotCreateTime := got.GetItem().GetCreatedTime().AsTime()
				require.NoError(err, "Error converting proto to timestamp.")
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
				require.NoError(err, "Error converting proto to timestamp")
				// Verify it is a catalog created after the test setup's default catalog
				assert.True(gotCreateTime.After(defaultHcCreated), "New catalog should have been created after default catalog. Was created %v, which is after %v", gotCreateTime, defaultHcCreated)
				assert.True(gotUpdateTime.After(defaultHcCreated), "New catalog should have been updated after default catalog. Was updated %v, which is after %v", gotUpdateTime, defaultHcCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	pluginHostRepo := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, new(host.PluginMap))
	}
	pluginRepo := func() (*host.Repository, error) {
		return host.NewRepository(rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	tested, err := host_catalogs.NewService(repoFn, pluginHostRepo, pluginRepo, iamRepoFn)
	require.NoError(t, err, "Failed to create a new host catalog service.")

	hc, err := static.NewHostCatalog(proj.GetPublicId(), static.WithName("default"), static.WithDescription("default"))
	require.NoError(t, err, "Couldn't get new catalog.")
	repo, err := repoFn()
	require.NoError(t, err, "Couldn't create static repostitory")
	hc, err = repo.CreateCatalog(context.Background(), hc)
	require.NoError(t, err, "Couldn't persist new catalog.")

	var version uint32 = 1

	resetHostCatalog := func() {
		version++
		repo, err := repoFn()
		require.NoError(t, err, "Couldn't create new static repo.")
		hc, _, err = repo.UpdateCatalog(context.Background(), hc, version, []string{"Name", "Description"})
		require.NoError(t, err, "Failed to reset host catalog.")
		version++
	}

	hcCreated := hc.GetCreateTime().GetTimestamp().AsTime()
	toMerge := &pbs.UpdateHostCatalogRequest{
		Id: hc.GetPublicId(),
	}

	cases := []struct {
		name string
		req  *pbs.UpdateHostCatalogRequest
		res  *pbs.UpdateHostCatalogResponse
		err  error
	}{
		{
			name: "Update an Existing HostCatalog",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
					Type:        "static",
				},
			},
			res: &pbs.UpdateHostCatalogResponse{
				Item: &pb.HostCatalog{
					Id:                          hc.GetPublicId(),
					ScopeId:                     hc.GetScopeId(),
					Scope:                       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
					Name:                        &wrappers.StringValue{Value: "new"},
					Description:                 &wrappers.StringValue{Value: "desc"},
					CreatedTime:                 hc.GetCreateTime().GetTimestamp(),
					Type:                        "static",
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
					Type:        "static",
				},
			},
			res: &pbs.UpdateHostCatalogResponse{
				Item: &pb.HostCatalog{
					Id:                          hc.GetPublicId(),
					ScopeId:                     hc.GetScopeId(),
					Scope:                       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
					Name:                        &wrappers.StringValue{Value: "new"},
					Description:                 &wrappers.StringValue{Value: "desc"},
					CreatedTime:                 hc.GetCreateTime().GetTimestamp(),
					Type:                        "static",
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateHostCatalogRequest{
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Empty Path",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Only non-existant paths in Mask",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.HostCatalog{
					Description: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostCatalogResponse{
				Item: &pb.HostCatalog{
					Id:                          hc.GetPublicId(),
					ScopeId:                     hc.GetScopeId(),
					Scope:                       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
					Description:                 &wrappers.StringValue{Value: "default"},
					CreatedTime:                 hc.GetCreateTime().GetTimestamp(),
					Type:                        "static",
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Unset Description",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.HostCatalog{
					Name: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostCatalogResponse{
				Item: &pb.HostCatalog{
					Id:                          hc.GetPublicId(),
					ScopeId:                     hc.GetScopeId(),
					Scope:                       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
					Name:                        &wrappers.StringValue{Value: "default"},
					CreatedTime:                 hc.GetCreateTime().GetTimestamp(),
					Type:                        "static",
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "updated"},
					Description: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostCatalogResponse{
				Item: &pb.HostCatalog{
					Id:                          hc.GetPublicId(),
					ScopeId:                     hc.GetScopeId(),
					Scope:                       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
					Name:                        &wrappers.StringValue{Value: "updated"},
					Description:                 &wrappers.StringValue{Value: "default"},
					CreatedTime:                 hc.GetCreateTime().GetTimestamp(),
					Type:                        "static",
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "ignored"},
					Description: &wrappers.StringValue{Value: "notignored"},
				},
			},
			res: &pbs.UpdateHostCatalogResponse{
				Item: &pb.HostCatalog{
					Id:                          hc.GetPublicId(),
					ScopeId:                     hc.GetScopeId(),
					Scope:                       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
					Name:                        &wrappers.StringValue{Value: "default"},
					Description:                 &wrappers.StringValue{Value: "notignored"},
					CreatedTime:                 hc.GetCreateTime().GetTimestamp(),
					Type:                        "static",
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Cant change type",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "type"},
				},
				Item: &pb.HostCatalog{
					Name: &wrappers.StringValue{Value: "updated name"},
					Type: "ec2",
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Update a Non Existing HostCatalog",
			req: &pbs.UpdateHostCatalogRequest{
				Id: static.HostCatalogPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "new"},
					Scope:       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
					Description: &wrappers.StringValue{Value: "desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateHostCatalogRequest{
				Id: hc.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.HostCatalog{
					Id:          "p_somethinge",
					Scope:       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "new desc"},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.HostCatalog{
					CreatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.HostCatalog{
					UpdatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Valid mask, cant specify type",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.HostCatalog{
					Type: "unknown",
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			tc.req.Item.Version = version

			req := proto.Clone(toMerge).(*pbs.UpdateHostCatalogRequest)
			proto.Merge(req, tc.req)

			// Test some bad versions
			req.Item.Version = version + 2
			_, gErr := tested.UpdateHostCatalog(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			require.Error(gErr)
			req.Item.Version = version - 1
			_, gErr = tested.UpdateHostCatalog(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			require.Error(gErr)
			req.Item.Version = version

			got, gErr := tested.UpdateHostCatalog(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateHostCatalog(%+v) got error %v, wanted %v", req, gErr, tc.err)
				return
			}
			require.NoError(gErr)

			if tc.err == nil {
				defer resetHostCatalog()
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateHostCatalog response to be nil, but was %v", got)
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
				require.NoError(err, "Failed to convert proto to timestamp")
				// Verify it is a catalog updated after it was created
				// TODO: This is currently failing.
				// assert.True(gotUpdateTime.After(hcCreated), "Updated catalog should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, hcCreated)
				_ = gotUpdateTime
				_ = hcCreated

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil
			}
			if tc.res != nil {
				tc.res.Item.Version = version + 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "UpdateHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}
