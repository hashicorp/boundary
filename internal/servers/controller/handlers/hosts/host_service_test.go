package hosts_test

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
	hostplugin "github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/servers/controller/auth"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/hosts"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hosts"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/plugins"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var testAuthorizedActions = map[subtypes.Subtype][]string{
	static.Subtype: {"no-op", "read", "update", "delete"},
	plugin.Subtype: {"no-op", "read"},
}

func TestGet_Static(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	org, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	pluginRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]

	pHost := &pb.Host{
		HostCatalogId: hc.GetPublicId(),
		Id:            h.GetPublicId(),
		CreatedTime:   h.CreateTime.GetTimestamp(),
		UpdatedTime:   h.UpdateTime.GetTimestamp(),
		Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
		Type:          "static",
		Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
			"address": structpb.NewStringValue(h.GetAddress()),
		}},
		AuthorizedActions: testAuthorizedActions[static.Subtype],
	}

	cases := []struct {
		name string
		req  *pbs.GetHostRequest
		res  *pbs.GetHostResponse
		err  error
	}{
		{
			name: "Get an Existing Host",
			req:  &pbs.GetHostRequest{Id: h.GetPublicId()},
			res:  &pbs.GetHostResponse{Item: pHost},
		},
		{
			name: "Get a non existing Host Set",
			req:  &pbs.GetHostRequest{Id: static.HostPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Wrong id prefix",
			req:  &pbs.GetHostRequest{Id: "j_1234567890"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "space in id",
			req:  &pbs.GetHostRequest{Id: static.HostPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := hosts.NewService(repoFn, pluginRepoFn)
			require.NoError(err, "Couldn't create a new host service.")

			got, gErr := s.GetHost(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetHost(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}

			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetHost(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestGet_Plugin(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	org, proj := iam.TestScopes(t, iamRepo)

	plg := hostplugin.TestPlugin(t, conn, "test")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): plugin.NewWrappingPluginClient(&plugin.TestPluginServer{}),
	}

	rw := db.New(conn)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	pluginRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, sche, plgm)
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	hc := plugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	h := plugin.TestHost(t, conn, hc.GetPublicId(), "test")
	hs := plugin.TestSet(t, conn, kms, sche, hc, plgm)
	plugin.TestSetMembers(t, conn, hs.GetPublicId(), []*plugin.Host{h})

	pHost := &pb.Host{
		HostCatalogId: hc.GetPublicId(),
		Id:            h.GetPublicId(),
		CreatedTime:   h.CreateTime.GetTimestamp(),
		UpdatedTime:   h.UpdateTime.GetTimestamp(),
		Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
		Type:          plugin.Subtype.String(),
		Plugin: &plugins.PluginInfo{
			Id:          plg.GetPublicId(),
			Name:        plg.GetName(),
			Description: plg.GetDescription(),
		},
		HostSetIds:        []string{hs.GetPublicId()},
		ExternalId:        "test",
		AuthorizedActions: testAuthorizedActions[plugin.Subtype],
	}

	cases := []struct {
		name string
		req  *pbs.GetHostRequest
		res  *pbs.GetHostResponse
		err  error
	}{
		{
			name: "Get an Existing Host",
			req:  &pbs.GetHostRequest{Id: h.GetPublicId()},
			res:  &pbs.GetHostResponse{Item: pHost},
		},
		{
			name: "non existing",
			req:  &pbs.GetHostRequest{Id: plugin.HostPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Wrong id prefix",
			req:  &pbs.GetHostRequest{Id: "j_1234567890"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "space in id",
			req:  &pbs.GetHostRequest{Id: plugin.HostPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := hosts.NewService(repoFn, pluginRepoFn)
			require.NoError(err, "Couldn't create a new host service.")

			got, gErr := s.GetHost(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetHost(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)

			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetHost(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestList_Static(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	org, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	pluginRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	hcs := static.TestCatalogs(t, conn, proj.GetPublicId(), 2)
	hc, hcNoHosts := hcs[0], hcs[1]

	var wantHs []*pb.Host
	for _, h := range static.TestHosts(t, conn, hc.GetPublicId(), 10) {
		wantHs = append(wantHs, &pb.Host{
			Id:            h.GetPublicId(),
			HostCatalogId: h.GetCatalogId(),
			Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
			CreatedTime:   h.GetCreateTime().GetTimestamp(),
			UpdatedTime:   h.GetUpdateTime().GetTimestamp(),
			Version:       h.GetVersion(),
			Type:          static.Subtype.String(), Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
				"address": structpb.NewStringValue(h.GetAddress()),
			}},
			AuthorizedActions: testAuthorizedActions[static.Subtype],
		})
	}

	cases := []struct {
		name string
		req  *pbs.ListHostsRequest
		res  *pbs.ListHostsResponse
		err  error
	}{
		{
			name: "List Many Hosts",
			req:  &pbs.ListHostsRequest{HostCatalogId: hc.GetPublicId()},
			res:  &pbs.ListHostsResponse{Items: wantHs},
		},
		{
			name: "List Non Existing Hosts",
			req:  &pbs.ListHostsRequest{HostCatalogId: "hcst_doesntexist"},
			err: handlers.NotFoundError(),
		},
		{
			name: "List No Hosts",
			req:  &pbs.ListHostsRequest{HostCatalogId: hcNoHosts.GetPublicId()},
			res:  &pbs.ListHostsResponse{},
		},
		{
			name: "Filter to One Host",
			req:  &pbs.ListHostsRequest{HostCatalogId: hc.GetPublicId(), Filter: fmt.Sprintf(`"/item/id"==%q`, wantHs[1].GetId())},
			res:  &pbs.ListHostsResponse{Items: wantHs[1:2]},
		},
		{
			name: "Filter to No Hosts",
			req:  &pbs.ListHostsRequest{HostCatalogId: hc.GetPublicId(), Filter: `"/item/id"=="doesnt match"`},
			res:  &pbs.ListHostsResponse{},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListHostsRequest{HostCatalogId: hc.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := hosts.NewService(repoFn, pluginRepoFn)
			require.NoError(err, "Couldn't create new host set service.")

			// Test non-anonymous listing
			got, gErr := s.ListHosts(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListHosts(%q) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListHosts(%q) got response %q, wanted %q", tc.req, got, tc.res)

			// Test anonymous listing
			got, gErr = s.ListHosts(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId(), auth.WithUserId(auth.AnonymousUserId)), tc.req)
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

func TestList_Plugin(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	org, proj := iam.TestScopes(t, iamRepo)
	plg := hostplugin.TestPlugin(t, conn, "test")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): plugin.NewWrappingPluginClient(&plugin.TestPluginServer{}),
	}

	rw := db.New(conn)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	pluginRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, sche, plgm)
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	hcs := plugin.TestCatalogs(t, conn, proj.GetPublicId(), plg.GetPublicId(), 2)
	hc, hcNoHosts := hcs[0], hcs[1]
	hs := plugin.TestSet(t, conn, kms, sche, hc, plgm)

	var wantHs []*pb.Host
	for i := 0; i < 10; i++ {
		extId := fmt.Sprintf("host %d", i)
		h := plugin.TestHost(t, conn, hc.GetPublicId(), extId)
		plugin.TestSetMembers(t, conn, hs.GetPublicId(), []*plugin.Host{h})
		wantHs = append(wantHs, &pb.Host{
			Id:            h.GetPublicId(),
			HostCatalogId: h.GetCatalogId(),
			Plugin: &plugins.PluginInfo{
				Id:          plg.GetPublicId(),
				Name:        plg.GetName(),
				Description: plg.GetDescription(),
			},
			Scope:             &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
			CreatedTime:       h.GetCreateTime().GetTimestamp(),
			UpdatedTime:       h.GetUpdateTime().GetTimestamp(),
			HostSetIds:        []string{hs.GetPublicId()},
			Version:           1,
			ExternalId:        extId,
			Type:              plugin.Subtype.String(),
			AuthorizedActions: testAuthorizedActions[plugin.Subtype],
		})
	}
	sort.Slice(wantHs, func(i, j int) bool {
		return wantHs[i].GetId() < wantHs[j].GetId()
	})

	cases := []struct {
		name string
		req  *pbs.ListHostsRequest
		res  *pbs.ListHostsResponse
		err  error
	}{
		{
			name: "List Many Hosts",
			req:  &pbs.ListHostsRequest{HostCatalogId: hc.GetPublicId()},
			res:  &pbs.ListHostsResponse{Items: wantHs},
		},
		{
			name: "List Non Existing Hosts",
			req:  &pbs.ListHostsRequest{HostCatalogId: "hc_doesntexist"},
			err: handlers.NotFoundError(),
		},
		{
			name: "List No Hosts",
			req:  &pbs.ListHostsRequest{HostCatalogId: hcNoHosts.GetPublicId()},
			res:  &pbs.ListHostsResponse{},
		},
		{
			name: "Filter to One Host",
			req:  &pbs.ListHostsRequest{HostCatalogId: hc.GetPublicId(), Filter: fmt.Sprintf(`"/item/id"==%q`, wantHs[1].GetId())},
			res:  &pbs.ListHostsResponse{Items: wantHs[1:2]},
		},
		{
			name: "Filter to No Hosts",
			req:  &pbs.ListHostsRequest{HostCatalogId: hc.GetPublicId(), Filter: `"/item/id"=="doesnt match"`},
			res:  &pbs.ListHostsResponse{},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListHostsRequest{HostCatalogId: hc.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := hosts.NewService(repoFn, pluginRepoFn)
			require.NoError(err, "Couldn't create new host set service.")

			// Test non-anonymous listing
			got, gErr := s.ListHosts(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListHosts(%q) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)

			sort.Slice(got.Items, func(i, j int) bool {
				return got.Items[i].GetId() < got.Items[j].GetId()
			})
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListHosts(%q) got response %q, wanted %q", tc.req, got, tc.res)

			// Test anonymous listing
			got, gErr = s.ListHosts(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId(), auth.WithUserId(auth.AnonymousUserId)), tc.req)
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
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	pluginRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]

	plg := hostplugin.TestPlugin(t, conn, "test")
	pluginHc := plugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	pluginH := plugin.TestHost(t, conn, pluginHc.GetPublicId(), "test")

	s, err := hosts.NewService(repoFn, pluginRepoFn)
	require.NoError(t, err, "Couldn't create a new host set service.")

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.DeleteHostRequest
		res     *pbs.DeleteHostResponse
		err     error
	}{
		{
			name:    "Delete an Existing Host",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostRequest{
				Id: h.GetPublicId(),
			},
		},
		{
			name:    "Delete a plugin Host",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostRequest{
				Id: pluginH.GetPublicId(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Delete bad id Host",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostRequest{
				Id: static.HostPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Bad Host Id formatting",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostRequest{
				Id: static.HostPrefix + "_bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteHost(auth.DisabledAuthTestContext(iamRepoFn, tc.scopeId), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteHost(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(tc.res, got, protocmp.Transform()), "DeleteHost(%q) got response %q, wanted %q", tc.req, got, tc.res)
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
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	pluginRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]

	s, err := hosts.NewService(repoFn, pluginRepoFn)
	require.NoError(err, "Couldn't create a new host set service.")
	req := &pbs.DeleteHostRequest{
		Id: h.GetPublicId(),
	}
	ctx := auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId())
	_, gErr := s.DeleteHost(ctx, req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteHost(ctx, req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")
}

func TestCreate(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	org, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	pluginRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]

	plg := hostplugin.TestPlugin(t, conn, "test")
	pluginHc := plugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())

	defaultHcCreated := hc.GetCreateTime().GetTimestamp().AsTime()

	cases := []struct {
		name string
		req  *pbs.CreateHostRequest
		res  *pbs.CreateHostResponse
		err  error
	}{
		{
			name: "Create a valid Host",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "name"},
				Description:   &wrappers.StringValue{Value: "desc"},
				Type:          "static",
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"address": structpb.NewStringValue("123.456.789"),
				}},
			}},
			res: &pbs.CreateHostResponse{
				Uri: fmt.Sprintf("hosts/%s_", static.HostPrefix),
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:          &wrappers.StringValue{Value: "name"},
					Description:   &wrappers.StringValue{Value: "desc"},
					Type:          "static",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewStringValue("123.456.789"),
					}},
					AuthorizedActions: testAuthorizedActions[static.Subtype],
				},
			},
		},
		{
			name: "Create a plugin Host",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				HostCatalogId: pluginHc.GetPublicId(),
				Type:          "plugin",
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Create with empty address",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "name"},
				Description:   &wrappers.StringValue{Value: "desc"},
				Type:          "static",
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"address": structpb.NewStringValue(""),
				}},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Create without address",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "name"},
				Description:   &wrappers.StringValue{Value: "desc"},
				Type:          "static",
				Attributes:    &structpb.Struct{Fields: map[string]*structpb.Value{}},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Create with unknown type",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "name"},
				Description:   &wrappers.StringValue{Value: "desc"},
				Type:          "ThisIsMadeUp",
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Create with no type",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "no type name"},
				Description:   &wrappers.StringValue{Value: "no type desc"},
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"address": structpb.NewStringValue("123.456.789"),
				}},
			}},
			res: &pbs.CreateHostResponse{
				Uri: fmt.Sprintf("hosts/%s_", static.HostPrefix),
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:          &wrappers.StringValue{Value: "no type name"},
					Description:   &wrappers.StringValue{Value: "no type desc"},
					Type:          "static",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewStringValue("123.456.789"),
					}},
					AuthorizedActions: testAuthorizedActions[static.Subtype],
				},
			},
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				HostCatalogId: hc.GetPublicId(),
				Id:            "not allowed to be set",
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				HostCatalogId: hc.GetPublicId(),
				CreatedTime:   timestamppb.Now(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				UpdatedTime: timestamppb.Now(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := hosts.NewService(repoFn, pluginRepoFn)
			require.NoError(err, "Failed to create a new host set service.")

			got, gErr := s.CreateHost(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateHost(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.GetUri())
				assert.True(strings.HasPrefix(got.GetItem().GetId(), static.HostPrefix))
				gotCreateTime := got.GetItem().GetCreatedTime().AsTime()
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
				// Verify it is a set created after the test setup's default set
				assert.True(gotCreateTime.After(defaultHcCreated), "New host should have been created after default host. Was created %v, which is after %v", gotCreateTime, defaultHcCreated)
				assert.True(gotUpdateTime.After(defaultHcCreated), "New host should have been updated after default host. Was updated %v, which is after %v", gotUpdateTime, defaultHcCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateHost(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestUpdate_Static(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	org, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	pluginRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	repo, err := repoFn()
	require.NoError(t, err, "Couldn't create new static repo.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]

	h, err := static.NewHost(hc.GetPublicId(), static.WithName("default"), static.WithDescription("default"), static.WithAddress("defaultaddress"))
	require.NoError(t, err)
	h, err = repo.CreateHost(context.Background(), proj.GetPublicId(), h)
	require.NoError(t, err)

	var version uint32 = 1

	resetHost := func() {
		version++
		_, _, err = repo.UpdateHost(context.Background(), proj.GetPublicId(), h, version, []string{"Name", "Description", "Address"})
		require.NoError(t, err, "Failed to reset host.")
		version++
	}

	hCreated := h.GetCreateTime().GetTimestamp().AsTime()
	toMerge := &pbs.UpdateHostRequest{
		Id: h.GetPublicId(),
	}

	tested, err := hosts.NewService(repoFn, pluginRepoFn)
	require.NoError(t, err, "Failed to create a new host set service.")

	cases := []struct {
		name string
		req  *pbs.UpdateHostRequest
		res  *pbs.UpdateHostResponse
		err  error
	}{
		{
			name: "Update an Existing Host",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description", "type"},
				},
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
					Type:        "static",
				},
			},
			res: &pbs.UpdateHostResponse{
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Id:            h.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:          &wrappers.StringValue{Value: "new"},
					Description:   &wrappers.StringValue{Value: "desc"},
					CreatedTime:   h.GetCreateTime().GetTimestamp(),
					Type:          "static",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewStringValue("defaultaddress"),
					}},
					AuthorizedActions: testAuthorizedActions[static.Subtype],
				},
			},
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description,type"},
				},
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
					Type:        "static",
				},
			},
			res: &pbs.UpdateHostResponse{
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Id:            h.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:          &wrappers.StringValue{Value: "new"},
					Description:   &wrappers.StringValue{Value: "desc"},
					CreatedTime:   h.GetCreateTime().GetTimestamp(),
					Type:          "static",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewStringValue("defaultaddress"),
					}},
					AuthorizedActions: testAuthorizedActions[static.Subtype],
				},
			},
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateHostRequest{
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,type"},
				},
				Item: &pb.Host{
					Name: &wrappers.StringValue{Value: "updated name"},
					Type: "ec2",
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Empty Path",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Only non-existant paths in Mask",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Host{
					Description: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostResponse{
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Id:            h.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Description:   &wrappers.StringValue{Value: "default"},
					CreatedTime:   h.GetCreateTime().GetTimestamp(),
					Type:          "static",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewStringValue("defaultaddress"),
					}},
					AuthorizedActions: testAuthorizedActions[static.Subtype],
				},
			},
		},
		{
			name: "Unset Description",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Host{
					Name: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostResponse{
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Id:            h.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:          &wrappers.StringValue{Value: "default"},
					CreatedTime:   h.GetCreateTime().GetTimestamp(),
					Type:          "static",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewStringValue("defaultaddress"),
					}},
					AuthorizedActions: testAuthorizedActions[static.Subtype],
				},
			},
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "updated"},
					Description: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostResponse{
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Id:            h.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:          &wrappers.StringValue{Value: "updated"},
					Description:   &wrappers.StringValue{Value: "default"},
					CreatedTime:   h.GetCreateTime().GetTimestamp(),
					Type:          "static",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewStringValue("defaultaddress"),
					}},
					AuthorizedActions: testAuthorizedActions[static.Subtype],
				},
			},
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "ignored"},
					Description: &wrappers.StringValue{Value: "notignored"},
				},
			},
			res: &pbs.UpdateHostResponse{
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Id:            h.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:          &wrappers.StringValue{Value: "default"},
					Description:   &wrappers.StringValue{Value: "notignored"},
					CreatedTime:   h.GetCreateTime().GetTimestamp(),
					Type:          "static",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewStringValue("defaultaddress"),
					}},
					AuthorizedActions: testAuthorizedActions[static.Subtype],
				},
			},
		},
		{
			name: "Update a Non Existing Host",
			req: &pbs.UpdateHostRequest{
				Id: static.HostPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "new"},
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Description: &wrappers.StringValue{Value: "desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateHostRequest{
				Id: hc.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.Host{
					Id:          "p_somethinge",
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "new desc"},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant unset address",
			req: &pbs.UpdateHostRequest{
				Id: hc.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.address"},
				},
				Item: &pb.Host{
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewNullValue(),
					}},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant set address to empty string",
			req: &pbs.UpdateHostRequest{
				Id: hc.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.address"},
				},
				Item: &pb.Host{
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"address": structpb.NewStringValue(""),
					}},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.Host{
					CreatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.Host{
					UpdatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Valid mask, cant specify type",
			req: &pbs.UpdateHostRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Host{
					Type: "Unknown",
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

			req := proto.Clone(toMerge).(*pbs.UpdateHostRequest)
			proto.Merge(req, tc.req)

			// Test some bad versions
			req.Item.Version = version + 2
			_, gErr := tested.UpdateHost(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			require.Error(gErr)
			req.Item.Version = version - 1
			_, gErr = tested.UpdateHost(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			require.Error(gErr)
			req.Item.Version = version

			got, gErr := tested.UpdateHost(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateHost(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}

			if tc.err == nil {
				defer resetHost()
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateHost response to be nil, but was %v", got)
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
				// Verify it is a set updated after it was created
				// TODO: This is currently failing.
				assert.True(gotUpdateTime.After(hCreated), "Updated set should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, hCreated)

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil
			}
			if tc.res != nil {
				tc.res.Item.Version = version + 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "UpdateHost(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestUpdate_Plugin(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	pluginRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}

	plg := hostplugin.TestPlugin(t, conn, "test")
	hc := plugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	h := plugin.TestHost(t, conn, hc.GetPublicId(), "test")

	tested, err := hosts.NewService(repoFn, pluginRepoFn)
	require.NoError(t, err)

	got, err := tested.UpdateHost(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), &pbs.UpdateHostRequest{
		Id:         h.GetPublicId(),
		Item:       &pb.Host{Name: wrapperspb.String("foo")},
		UpdateMask: &field_mask.FieldMask{Paths: []string{"name"}},
	})
	assert.Nil(t, got)
	require.Error(t, err)
	assert.True(t, errors.Is(err, handlers.ApiErrorWithCode(codes.InvalidArgument)))
}
