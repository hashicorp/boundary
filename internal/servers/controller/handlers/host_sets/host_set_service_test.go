package host_sets_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	hostplugin "github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/hashicorp/boundary/internal/servers/controller/auth"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/host_sets"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/plugins"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var testAuthorizedActions = []string{"no-op", "read", "update", "delete", "add-hosts", "set-hosts", "remove-hosts"}

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
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	pluginRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, map[string]plgpb.HostPluginServiceServer{})
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

	h := static.TestHosts(t, conn, hc.GetPublicId(), 2)
	static.TestSetMembers(t, conn, hs.GetPublicId(), h)
	hIds := []string{h[0].GetPublicId(), h[1].GetPublicId()}

	toMerge := &pbs.GetHostSetRequest{}

	pHost := &pb.HostSet{
		HostCatalogId:     hc.GetPublicId(),
		Id:                hs.GetPublicId(),
		CreatedTime:       hs.CreateTime.GetTimestamp(),
		UpdatedTime:       hs.UpdateTime.GetTimestamp(),
		Scope:             &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
		Type:              "static",
		HostIds:           hIds,
		AuthorizedActions: testAuthorizedActions,
	}

	cases := []struct {
		name string
		req  *pbs.GetHostSetRequest
		res  *pbs.GetHostSetResponse
		err  error
	}{
		{
			name: "Get an Existing Host",
			req:  &pbs.GetHostSetRequest{Id: hs.GetPublicId()},
			res:  &pbs.GetHostSetResponse{Item: pHost},
		},
		{
			name: "Get a non existing Host Set",
			req:  &pbs.GetHostSetRequest{Id: static.HostSetPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Wrong id prefix",
			req:  &pbs.GetHostSetRequest{Id: "j_1234567890"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "space in id",
			req:  &pbs.GetHostSetRequest{Id: static.HostPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.GetHostSetRequest)
			proto.Merge(req, tc.req)

			s, err := host_sets.NewService(repoFn, pluginRepoFn)
			require.NoError(err, "Couldn't create a new host set service.")

			got, gErr := s.GetHostSet(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetHostSet(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}

			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetHostSet(%q) got response %q, wanted %q", req, got, tc.res)
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

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}

	name := "test"
	prefEndpoints := []string{"cidr:1.2.3.4", "cidr:2.3.4.5/24"}
	plg := hostplugin.TestPlugin(t, conn, name)
	plgm := map[string]plgpb.HostPluginServiceServer{
		plg.GetPublicId(): &plugin.TestPluginServer{},
	}
	pluginRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, plgm)
	}

	hc := plugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	hs := plugin.TestSet(t, conn, kms, hc, plgm, plugin.WithPreferredEndpoints(prefEndpoints))

	toMerge := &pbs.GetHostSetRequest{}

	pHost := &pb.HostSet{
		HostCatalogId: hc.GetPublicId(),
		Id:            hs.GetPublicId(),
		CreatedTime:   hs.CreateTime.GetTimestamp(),
		UpdatedTime:   hs.UpdateTime.GetTimestamp(),
		Type:          plugin.Subtype.String(),
		Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
		Plugin: &plugins.PluginInfo{
			Id:          plg.GetPublicId(),
			Name:        plg.GetName(),
			Description: plg.GetDescription(),
		},
		PreferredEndpoints: prefEndpoints,
		AuthorizedActions:  testAuthorizedActions,
	}

	cases := []struct {
		name string
		req  *pbs.GetHostSetRequest
		res  *pbs.GetHostSetResponse
		err  error
	}{
		{
			name: "Get an Existing Host",
			req:  &pbs.GetHostSetRequest{Id: hs.GetPublicId()},
			res:  &pbs.GetHostSetResponse{Item: pHost},
		},
		{
			name: "Get a non existing Host Set",
			req:  &pbs.GetHostSetRequest{Id: plugin.HostSetPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Wrong id prefix",
			req:  &pbs.GetHostSetRequest{Id: "j_1234567890"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "space in id",
			req:  &pbs.GetHostSetRequest{Id: plugin.HostSetPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.GetHostSetRequest)
			proto.Merge(req, tc.req)

			s, err := host_sets.NewService(repoFn, pluginRepoFn)
			require.NoError(err, "Couldn't create a new host set service.")

			got, gErr := s.GetHostSet(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetHostSet(%+v) got error %v, wanted %v", req, gErr, tc.err)
				return
			}
			require.NoError(gErr)

			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got.GetItem(), tc.res.GetItem(), protocmp.Transform()), "GetHostSet(%q) got response %q, wanted %q", req, got, tc.res)
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
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	pluginRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, map[string]plgpb.HostPluginServiceServer{})
	}
	hcs := static.TestCatalogs(t, conn, proj.GetPublicId(), 2)
	hc, hcNoHosts := hcs[0], hcs[1]

	var wantHs []*pb.HostSet
	for _, h := range static.TestSets(t, conn, hc.GetPublicId(), 10) {
		wantHs = append(wantHs, &pb.HostSet{
			Id:                h.GetPublicId(),
			HostCatalogId:     h.GetCatalogId(),
			Scope:             &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
			CreatedTime:       h.GetCreateTime().GetTimestamp(),
			UpdatedTime:       h.GetUpdateTime().GetTimestamp(),
			Version:           h.GetVersion(),
			Type:              static.Subtype.String(),
			AuthorizedActions: testAuthorizedActions,
		})
	}

	cases := []struct {
		name string
		req  *pbs.ListHostSetsRequest
		res  *pbs.ListHostSetsResponse
		err  error
	}{
		{
			name: "List Many Host Sets",
			req:  &pbs.ListHostSetsRequest{HostCatalogId: hc.GetPublicId()},
			res:  &pbs.ListHostSetsResponse{Items: wantHs},
		},
		{
			name: "List No Host Sets",
			req:  &pbs.ListHostSetsRequest{HostCatalogId: hcNoHosts.GetPublicId()},
			res:  &pbs.ListHostSetsResponse{},
		},
		{
			name: "Filter To One Host Set",
			req:  &pbs.ListHostSetsRequest{HostCatalogId: hc.GetPublicId(), Filter: fmt.Sprintf(`"/item/id"==%q`, wantHs[1].GetId())},
			res:  &pbs.ListHostSetsResponse{Items: wantHs[1:2]},
		},
		{
			name: "Filter To No Host Sets",
			req:  &pbs.ListHostSetsRequest{HostCatalogId: hc.GetPublicId(), Filter: `"/item/name"=="doesnt match"`},
			res:  &pbs.ListHostSetsResponse{},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListHostSetsRequest{HostCatalogId: hc.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := host_sets.NewService(repoFn, pluginRepoFn)
			require.NoError(err, "Couldn't create new host set service.")

			// Test with non-anon user
			got, gErr := s.ListHostSets(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListHostSets(%q) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListHostSets(%q) got response %q, wanted %q", tc.req, got, tc.res)

			// Test with anon user
			got, gErr = s.ListHostSets(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId(), auth.WithUserId(auth.AnonymousUserId)), tc.req)
			require.NoError(gErr)
			assert.Len(got.Items, len(tc.res.Items))
			for _, item := range got.GetItems() {
				require.Nil(item.CreatedTime)
				require.Nil(item.UpdatedTime)
				require.Zero(item.Version)
				require.Empty(item.HostIds)
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

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	name := "test"
	plg := hostplugin.TestPlugin(t, conn, name)
	plgm := map[string]plgpb.HostPluginServiceServer{
		plg.GetPublicId(): &plugin.TestPluginServer{},
	}
	pluginRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, plgm)
	}
	hc := plugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	hcNoHosts := plugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	preferredEndpoints := []string{"cidr:1.2.3.4", "dns:*.foobar.com"}

	var wantHs []*pb.HostSet
	for i := 0; i < 10; i++ {
		h := plugin.TestSet(t, conn, kms, hc, plgm, plugin.WithPreferredEndpoints(preferredEndpoints))
		wantHs = append(wantHs, &pb.HostSet{
			Id:            h.GetPublicId(),
			HostCatalogId: h.GetCatalogId(),
			Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
			Plugin: &plugins.PluginInfo{
				Id:          plg.GetPublicId(),
				Name:        plg.GetName(),
				Description: plg.GetDescription(),
			},
			CreatedTime:        h.GetCreateTime().GetTimestamp(),
			UpdatedTime:        h.GetUpdateTime().GetTimestamp(),
			Version:            h.GetVersion(),
			Type:               plugin.Subtype.String(),
			AuthorizedActions:  testAuthorizedActions,
			PreferredEndpoints: preferredEndpoints,
		})
	}

	cases := []struct {
		name string
		req  *pbs.ListHostSetsRequest
		res  *pbs.ListHostSetsResponse
		err  error
	}{
		{
			name: "List Many Host Sets",
			req:  &pbs.ListHostSetsRequest{HostCatalogId: hc.GetPublicId()},
			res:  &pbs.ListHostSetsResponse{Items: wantHs},
		},
		{
			name: "List No Host Sets",
			req:  &pbs.ListHostSetsRequest{HostCatalogId: hcNoHosts.GetPublicId()},
			res:  &pbs.ListHostSetsResponse{},
		},
		{
			name: "Filter To One Host Set",
			req:  &pbs.ListHostSetsRequest{HostCatalogId: hc.GetPublicId(), Filter: fmt.Sprintf(`"/item/id"==%q`, wantHs[1].GetId())},
			res:  &pbs.ListHostSetsResponse{Items: wantHs[1:2]},
		},
		{
			name: "Filter To No Host Sets",
			req:  &pbs.ListHostSetsRequest{HostCatalogId: hc.GetPublicId(), Filter: `"/item/name"=="doesnt match"`},
			res:  &pbs.ListHostSetsResponse{},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListHostSetsRequest{HostCatalogId: hc.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := host_sets.NewService(repoFn, pluginRepoFn)
			require.NoError(err, "Couldn't create new host set service.")

			// Test with non-anon user
			got, gErr := s.ListHostSetsWithOptions(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req, host.WithOrderByCreateTime(false))
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListHostSets(%q) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListHostSets(%q) got response %q, wanted %q", tc.req, got, tc.res)

			// Test with anon user
			got, gErr = s.ListHostSets(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId(), auth.WithUserId(auth.AnonymousUserId)), tc.req)
			require.NoError(gErr)
			assert.Len(got.Items, len(tc.res.Items))
			for _, item := range got.GetItems() {
				require.Nil(item.CreatedTime)
				require.Nil(item.UpdatedTime)
				require.Zero(item.Version)
				require.Empty(item.HostIds)
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
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	pluginRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, map[string]plgpb.HostPluginServiceServer{})
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	h := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

	s, err := host_sets.NewService(repoFn, pluginRepoFn)
	require.NoError(t, err, "Couldn't create a new host set service.")

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.DeleteHostSetRequest
		res     *pbs.DeleteHostSetResponse
		err     error
	}{
		{
			name:    "Delete an Existing Host Set",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostSetRequest{
				Id: h.GetPublicId(),
			},
		},
		{
			name:    "Delete bad id Host Set",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostSetRequest{
				Id: static.HostSetPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Delete bad host catalog id in Host Set",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostSetRequest{
				Id: h.GetPublicId(),
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Bad Host Id formatting",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostSetRequest{
				Id: static.HostSetPrefix + "_bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteHostSet(auth.DisabledAuthTestContext(iamRepoFn, tc.scopeId), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteHostSet(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(tc.res, got, protocmp.Transform()), "DeleteHostSet(%q) got response %q, wanted %q", tc.req, got, tc.res)
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
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	plgRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, map[string]plgpb.HostPluginServiceServer{})
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	h := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

	s, err := host_sets.NewService(repoFn, plgRepoFn)
	require.NoError(err, "Couldn't create a new host set service.")
	req := &pbs.DeleteHostSetRequest{
		Id: h.GetPublicId(),
	}
	ctx := auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId())
	_, gErr := s.DeleteHostSet(ctx, req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteHostSet(ctx, req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")
}

func TestCreate_Static(t *testing.T) {
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
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	plgRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, map[string]plgpb.HostPluginServiceServer{})
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]

	defaultHcCreated := hc.GetCreateTime().GetTimestamp().AsTime()

	cases := []struct {
		name string
		req  *pbs.CreateHostSetRequest
		res  *pbs.CreateHostSetResponse
		err  error
	}{
		{
			name: "Create a valid Host",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "name"},
				Description:   &wrappers.StringValue{Value: "desc"},
				Type:          "static",
			}},
			res: &pbs.CreateHostSetResponse{
				Uri: fmt.Sprintf("host-sets/%s_", static.HostSetPrefix),
				Item: &pb.HostSet{
					HostCatalogId:     hc.GetPublicId(),
					Scope:             &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:              &wrappers.StringValue{Value: "name"},
					Description:       &wrappers.StringValue{Value: "desc"},
					Type:              "static",
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Create with unknown type",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "name"},
				Description:   &wrappers.StringValue{Value: "desc"},
				Type:          "ThisIsMadeUp",
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Create with no type",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "no type name"},
				Description:   &wrappers.StringValue{Value: "no type desc"},
			}},
			res: &pbs.CreateHostSetResponse{
				Uri: fmt.Sprintf("host-sets/%s_", static.HostSetPrefix),
				Item: &pb.HostSet{
					HostCatalogId:     hc.GetPublicId(),
					Scope:             &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:              &wrappers.StringValue{Value: "no type name"},
					Description:       &wrappers.StringValue{Value: "no type desc"},
					Type:              "static",
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				HostCatalogId: hc.GetPublicId(),
				Id:            "not allowed to be set",
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				HostCatalogId: hc.GetPublicId(),
				CreatedTime:   timestamppb.Now(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				HostCatalogId: hc.GetPublicId(),
				UpdatedTime:   timestamppb.Now(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := host_sets.NewService(repoFn, plgRepoFn)
			require.NoError(err, "Failed to create a new host set service.")

			got, gErr := s.CreateHostSet(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateHostSet(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.GetUri())
				assert.True(strings.HasPrefix(got.GetItem().GetId(), static.HostSetPrefix), got.GetItem().GetId())
				gotCreateTime := got.GetItem().GetCreatedTime().AsTime()
				require.NoError(err, "Error converting proto to timestamp.")
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
				require.NoError(err, "Error converting proto to timestamp")
				// Verify it is a set created after the test setup's default set
				assert.True(gotCreateTime.After(defaultHcCreated), "New set should have been created after default set. Was created %v, which is after %v", gotCreateTime, defaultHcCreated)
				assert.True(gotUpdateTime.After(defaultHcCreated), "New set should have been updated after default set. Was updated %v, which is after %v", gotUpdateTime, defaultHcCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateHostSet(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestCreate_Plugin(t *testing.T) {
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
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	name := "test"
	plg := hostplugin.TestPlugin(t, conn, name)
	plgRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, map[string]plgpb.HostPluginServiceServer{
			plg.GetPublicId(): &plugin.TestPluginServer{
				OnCreateSetFn: func(ctx context.Context, req *plgpb.OnCreateSetRequest) (*plgpb.OnCreateSetResponse, error) {
					return nil, nil
				},
			},
		})
	}
	hc := plugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())

	testAttrs, err := structpb.NewStruct(map[string]interface{}{
		"int":         1,
		"zero int":    0,
		"string":      "foo",
		"zero string": "",
		"bytes":       []byte("bar"),
		"zero bytes":  nil,
		"bool":        true,
		"zero bool":   false,
		"nested": map[string]interface{}{
			"int":         1,
			"zero int":    0,
			"string":      "foo",
			"zero string": "",
			"bytes":       []byte("bar"),
			"zero bytes":  nil,
			"bool":        true,
			"zero bool":   false,
		},
	})
	require.NoError(t, err)

	prefEndpoints := []string{"cidr:1.2.3.4", "cidr:2.3.4.5/24"}

	defaultHcCreated := hc.GetCreateTime().GetTimestamp().AsTime()

	cases := []struct {
		name string
		req  *pbs.CreateHostSetRequest
		res  *pbs.CreateHostSetResponse
		err  error
	}{
		{
			name: "No Attributes",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "No Attributes"},
				Description:   &wrappers.StringValue{Value: "desc"},
				Type:          plugin.Subtype.String(),
			}},
			res: &pbs.CreateHostSetResponse{
				Uri: fmt.Sprintf("host-sets/%s_", plugin.HostSetPrefix),
				Item: &pb.HostSet{
					HostCatalogId: hc.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Plugin: &plugins.PluginInfo{
						Id:          plg.GetPublicId(),
						Name:        plg.GetName(),
						Description: plg.GetDescription(),
					},
					Name:              &wrappers.StringValue{Value: "No Attributes"},
					Description:       &wrappers.StringValue{Value: "desc"},
					Type:              plugin.Subtype.String(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "With Attributes",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "With Attributes"},
				Description:   &wrappers.StringValue{Value: "desc"},
				Type:          plugin.Subtype.String(),
				Attributes:    testAttrs,
			}},
			res: &pbs.CreateHostSetResponse{
				Uri: fmt.Sprintf("host-sets/%s_", plugin.HostSetPrefix),
				Item: &pb.HostSet{
					HostCatalogId: hc.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Plugin: &plugins.PluginInfo{
						Id:          plg.GetPublicId(),
						Name:        plg.GetName(),
						Description: plg.GetDescription(),
					},
					Name:              &wrappers.StringValue{Value: "With Attributes"},
					Description:       &wrappers.StringValue{Value: "desc"},
					Type:              plugin.Subtype.String(),
					AuthorizedActions: testAuthorizedActions,
					Attributes:        testAttrs,
				},
			},
		},
		{
			name: "With Preferred Endpoints",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				HostCatalogId:      hc.GetPublicId(),
				Name:               &wrappers.StringValue{Value: "name"},
				Description:        &wrappers.StringValue{Value: "desc"},
				Type:               plugin.Subtype.String(),
				PreferredEndpoints: prefEndpoints,
			}},
			res: &pbs.CreateHostSetResponse{
				Uri: fmt.Sprintf("host-sets/%s_", plugin.HostSetPrefix),
				Item: &pb.HostSet{
					HostCatalogId: hc.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Plugin: &plugins.PluginInfo{
						Id:          plg.GetPublicId(),
						Name:        plg.GetName(),
						Description: plg.GetDescription(),
					},
					Name:               &wrappers.StringValue{Value: "name"},
					Description:        &wrappers.StringValue{Value: "desc"},
					Type:               plugin.Subtype.String(),
					PreferredEndpoints: prefEndpoints,
					AuthorizedActions:  testAuthorizedActions,
				},
			},
		},
		{
			name: "Bad Preferred Endpoints",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				HostCatalogId:      hc.GetPublicId(),
				Name:               &wrappers.StringValue{Value: "name"},
				Description:        &wrappers.StringValue{Value: "desc"},
				Type:               plugin.Subtype.String(),
				PreferredEndpoints: append(prefEndpoints, "foobar:1.2.3.4"),
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Create with mismatched type/name",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "name"},
				Description:   &wrappers.StringValue{Value: "desc"},
				Type:          "ThisIsMadeUp",
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Create with no type",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "no type name"},
				Description:   &wrappers.StringValue{Value: "no type desc"},
			}},
			res: &pbs.CreateHostSetResponse{
				Uri: fmt.Sprintf("host-sets/%s_", plugin.HostSetPrefix),
				Item: &pb.HostSet{
					HostCatalogId: hc.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Plugin: &plugins.PluginInfo{
						Id:          plg.GetPublicId(),
						Name:        plg.GetName(),
						Description: plg.GetDescription(),
					},
					Name:              &wrappers.StringValue{Value: "no type name"},
					Description:       &wrappers.StringValue{Value: "no type desc"},
					Type:              plugin.Subtype.String(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				HostCatalogId: hc.GetPublicId(),
				Id:            "not allowed to be set",
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				HostCatalogId: hc.GetPublicId(),
				CreatedTime:   timestamppb.Now(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				HostCatalogId: hc.GetPublicId(),
				UpdatedTime:   timestamppb.Now(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := host_sets.NewService(repoFn, plgRepoFn)
			require.NoError(err, "Failed to create a new host set service.")

			got, gErr := s.CreateHostSet(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateHostSet(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.GetUri())
				assert.True(strings.HasPrefix(got.GetItem().GetId(), plugin.HostSetPrefix), got.GetItem().GetId())
				gotCreateTime := got.GetItem().GetCreatedTime().AsTime()
				require.NoError(err, "Error converting proto to timestamp.")
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
				require.NoError(err, "Error converting proto to timestamp")
				// Verify it is a set created after the test setup's default set
				assert.True(gotCreateTime.After(defaultHcCreated), "New set should have been created after default set. Was created %v, which is after %v", gotCreateTime, defaultHcCreated)
				assert.True(gotUpdateTime.After(defaultHcCreated), "New set should have been updated after default set. Was updated %v, which is after %v", gotUpdateTime, defaultHcCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateHostSet(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
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
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	repo, err := repoFn()
	require.NoError(t, err, "Couldn't create new static repo.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]

	h := static.TestHosts(t, conn, hc.GetPublicId(), 2)
	hIds := []string{h[0].GetPublicId(), h[1].GetPublicId()}

	hs, err := static.NewHostSet(hc.GetPublicId(), static.WithName("default"), static.WithDescription("default"))
	require.NoError(t, err)
	hs, err = repo.CreateSet(context.Background(), proj.GetPublicId(), hs)
	require.NoError(t, err)

	static.TestSetMembers(t, conn, hs.GetPublicId(), h)

	var version uint32 = 1

	resetHostSet := func() {
		version++
		_, _, _, err = repo.UpdateSet(context.Background(), proj.GetPublicId(), hs, version, []string{"Name", "Description"})
		require.NoError(t, err, "Failed to reset host.")
		version++
	}

	hCreated := hs.GetCreateTime().GetTimestamp().AsTime()
	toMerge := &pbs.UpdateHostSetRequest{
		Id: hs.GetPublicId(),
	}

	plgRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, map[string]plgpb.HostPluginServiceServer{})
	}
	tested, err := host_sets.NewService(repoFn, plgRepoFn)
	require.NoError(t, err, "Failed to create a new host set service.")

	cases := []struct {
		name string
		req  *pbs.UpdateHostSetRequest
		res  *pbs.UpdateHostSetResponse
		err  error
	}{
		{
			name: "Update an Existing Host",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description", "type"},
				},
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
					Type:        "static",
				},
			},
			res: &pbs.UpdateHostSetResponse{
				Item: &pb.HostSet{
					HostCatalogId:     hc.GetPublicId(),
					Id:                hs.GetPublicId(),
					Scope:             &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:              &wrappers.StringValue{Value: "new"},
					Description:       &wrappers.StringValue{Value: "desc"},
					CreatedTime:       hs.GetCreateTime().GetTimestamp(),
					Type:              "static",
					HostIds:           hIds,
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description,type"},
				},
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
					Type:        "static",
				},
			},
			res: &pbs.UpdateHostSetResponse{
				Item: &pb.HostSet{
					HostCatalogId:     hc.GetPublicId(),
					Id:                hs.GetPublicId(),
					Scope:             &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:              &wrappers.StringValue{Value: "new"},
					Description:       &wrappers.StringValue{Value: "desc"},
					CreatedTime:       hs.GetCreateTime().GetTimestamp(),
					Type:              "static",
					HostIds:           hIds,
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Cant modify type",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,type"},
				},
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
					Type:        "ec2",
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateHostSetRequest{
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Empty Path",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Only non-existant paths in Mask",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.HostSet{
					Description: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostSetResponse{
				Item: &pb.HostSet{
					HostCatalogId:     hc.GetPublicId(),
					Id:                hs.GetPublicId(),
					Scope:             &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Description:       &wrappers.StringValue{Value: "default"},
					CreatedTime:       hs.GetCreateTime().GetTimestamp(),
					Type:              "static",
					HostIds:           hIds,
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Unset Description",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.HostSet{
					Name: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostSetResponse{
				Item: &pb.HostSet{
					HostCatalogId:     hc.GetPublicId(),
					Id:                hs.GetPublicId(),
					Scope:             &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:              &wrappers.StringValue{Value: "default"},
					CreatedTime:       hs.GetCreateTime().GetTimestamp(),
					Type:              "static",
					HostIds:           hIds,
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "updated"},
					Description: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostSetResponse{
				Item: &pb.HostSet{
					HostCatalogId:     hc.GetPublicId(),
					Id:                hs.GetPublicId(),
					Scope:             &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:              &wrappers.StringValue{Value: "updated"},
					Description:       &wrappers.StringValue{Value: "default"},
					CreatedTime:       hs.GetCreateTime().GetTimestamp(),
					Type:              "static",
					HostIds:           hIds,
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "ignored"},
					Description: &wrappers.StringValue{Value: "notignored"},
				},
			},
			res: &pbs.UpdateHostSetResponse{
				Item: &pb.HostSet{
					HostCatalogId:     hc.GetPublicId(),
					Id:                hs.GetPublicId(),
					Scope:             &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:              &wrappers.StringValue{Value: "default"},
					Description:       &wrappers.StringValue{Value: "notignored"},
					CreatedTime:       hs.GetCreateTime().GetTimestamp(),
					Type:              "static",
					HostIds:           hIds,
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Update a Non Existing Host Set",
			req: &pbs.UpdateHostSetRequest{
				Id: static.HostSetPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "new"},
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Description: &wrappers.StringValue{Value: "desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateHostSetRequest{
				Id: hc.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.HostSet{
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
			name: "Cant specify Created Time",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.HostSet{
					CreatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.HostSet{
					UpdatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Valid mask, cant specify type",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.HostSet{
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

			req := proto.Clone(toMerge).(*pbs.UpdateHostSetRequest)
			proto.Merge(req, tc.req)

			// Test some bad versions
			req.Item.Version = version + 2
			_, gErr := tested.UpdateHostSet(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			require.Error(gErr)
			req.Item.Version = version - 1
			_, gErr = tested.UpdateHostSet(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			require.Error(gErr)
			req.Item.Version = version

			got, gErr := tested.UpdateHostSet(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateHostSet(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}

			if tc.err == nil {
				defer resetHostSet()
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
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "UpdateHostSet(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestAddHostSetHosts(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	plgRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, map[string]plgpb.HostPluginServiceServer{})
	}
	s, err := host_sets.NewService(repoFn, plgRepoFn)
	require.NoError(t, err, "Error when getting new host set service.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestHosts(t, conn, hc.GetPublicId(), 4)

	addCases := []struct {
		name        string
		setup       func(*static.HostSet)
		addHosts    []string
		resultHosts []string
	}{
		{
			name:        "Add host on empty set",
			setup:       func(g *static.HostSet) {},
			addHosts:    []string{hs[1].GetPublicId()},
			resultHosts: []string{hs[1].GetPublicId()},
		},
		{
			name: "Add host on populated set",
			setup: func(g *static.HostSet) {
				static.TestSetMembers(t, conn, g.GetPublicId(), hs[:1])
			},
			addHosts:    []string{hs[1].GetPublicId()},
			resultHosts: []string{hs[0].GetPublicId(), hs[1].GetPublicId()},
		},
		{
			name: "Add duplicate host on populated set",
			setup: func(g *static.HostSet) {
				static.TestSetMembers(t, conn, g.GetPublicId(), hs[:1])
			},
			addHosts:    []string{hs[1].GetPublicId(), hs[1].GetPublicId()},
			resultHosts: []string{hs[0].GetPublicId(), hs[1].GetPublicId()},
		},
	}

	for _, tc := range addCases {
		t.Run(tc.name, func(t *testing.T) {
			ss := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
			tc.setup(ss)
			req := &pbs.AddHostSetHostsRequest{
				Id:      ss.GetPublicId(),
				Version: ss.GetVersion(),
				HostIds: tc.addHosts,
			}

			got, err := s.AddHostSetHosts(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			s, ok := status.FromError(err)
			require.True(t, ok)
			require.NoError(t, err, "Got error: %v", s)

			assert.ElementsMatch(t, tc.resultHosts, got.GetItem().GetHostIds())
		})
	}

	ss := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

	failCases := []struct {
		name string
		req  *pbs.AddHostSetHostsRequest
		err  error
	}{
		{
			name: "Bad Set Id",
			req: &pbs.AddHostSetHostsRequest{
				Id:      "bad id",
				Version: ss.GetVersion(),
				HostIds: []string{hs[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Empty host list",
			req: &pbs.AddHostSetHostsRequest{
				Id:      ss.GetPublicId(),
				Version: ss.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid hosts in list",
			req: &pbs.AddHostSetHostsRequest{
				Id:      ss.GetPublicId(),
				Version: ss.GetVersion(),
				HostIds: []string{"invalid_id"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.AddHostSetHosts(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "AddHostSetHosts(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestSetHostSetHosts(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	plgRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, map[string]plgpb.HostPluginServiceServer{})
	}
	s, err := host_sets.NewService(repoFn, plgRepoFn)
	require.NoError(t, err, "Error when getting new host set service.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestHosts(t, conn, hc.GetPublicId(), 4)

	setCases := []struct {
		name        string
		setup       func(*static.HostSet)
		setHosts    []string
		resultHosts []string
	}{
		{
			name:        "Set host on empty set",
			setup:       func(r *static.HostSet) {},
			setHosts:    []string{hs[1].GetPublicId()},
			resultHosts: []string{hs[1].GetPublicId()},
		},
		{
			name: "Set host on populated set",
			setup: func(r *static.HostSet) {
				static.TestSetMembers(t, conn, r.GetPublicId(), hs[:1])
			},
			setHosts:    []string{hs[1].GetPublicId()},
			resultHosts: []string{hs[1].GetPublicId()},
		},
		{
			name: "Set duplicate host on populated set",
			setup: func(r *static.HostSet) {
				static.TestSetMembers(t, conn, r.GetPublicId(), hs[:1])
			},
			setHosts:    []string{hs[1].GetPublicId(), hs[1].GetPublicId()},
			resultHosts: []string{hs[1].GetPublicId()},
		},
		{
			name: "Set empty on populated set",
			setup: func(r *static.HostSet) {
				static.TestSetMembers(t, conn, r.GetPublicId(), hs[:2])
			},
			setHosts:    []string{},
			resultHosts: nil,
		},
	}
	for _, tc := range setCases {
		t.Run(tc.name, func(t *testing.T) {
			ss := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
			tc.setup(ss)
			req := &pbs.SetHostSetHostsRequest{
				Id:      ss.GetPublicId(),
				Version: ss.GetVersion(),
				HostIds: tc.setHosts,
			}

			got, err := s.SetHostSetHosts(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			require.NoError(t, err, "Got error: %v", s)
			assert.ElementsMatch(t, tc.resultHosts, got.GetItem().GetHostIds())
		})
	}

	ss := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

	failCases := []struct {
		name string
		req  *pbs.SetHostSetHostsRequest
		err  error
	}{
		{
			name: "Bad Set Id",
			req: &pbs.SetHostSetHostsRequest{
				Id:      "bad id",
				Version: ss.GetVersion(),
				HostIds: []string{hs[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Bad Host Id",
			req: &pbs.SetHostSetHostsRequest{
				Id:      ss.GetPublicId(),
				Version: ss.GetVersion(),
				HostIds: []string{"invalid_id"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.SetHostSetHosts(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "SetHostSetHosts(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestRemoveHostSetHosts(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	plgRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(rw, rw, kms, map[string]plgpb.HostPluginServiceServer{})
	}
	s, err := host_sets.NewService(repoFn, plgRepoFn)
	require.NoError(t, err, "Error when getting new host set service.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestHosts(t, conn, hc.GetPublicId(), 4)

	removeCases := []struct {
		name        string
		setup       func(*static.HostSet)
		removeHosts []string
		resultHosts []string
		wantErr     bool
	}{
		{
			name:        "Remove host on empty set",
			setup:       func(r *static.HostSet) {},
			removeHosts: []string{hs[1].GetPublicId()},
			wantErr:     true,
		},
		{
			name: "Remove 1 of 2 hosts from set",
			setup: func(r *static.HostSet) {
				static.TestSetMembers(t, conn, r.GetPublicId(), hs[:2])
			},
			removeHosts: []string{hs[1].GetPublicId()},
			resultHosts: []string{hs[0].GetPublicId()},
		},
		{
			name: "Remove 1 duplicate of 2 hosts from set",
			setup: func(r *static.HostSet) {
				static.TestSetMembers(t, conn, r.GetPublicId(), hs[:2])
			},
			removeHosts: []string{hs[1].GetPublicId(), hs[1].GetPublicId()},
			resultHosts: []string{hs[0].GetPublicId()},
		},
		{
			name: "Remove all hosts from set",
			setup: func(r *static.HostSet) {
				static.TestSetMembers(t, conn, r.GetPublicId(), hs[:2])
			},
			removeHosts: []string{hs[0].GetPublicId(), hs[1].GetPublicId()},
			resultHosts: []string{},
		},
	}

	for _, tc := range removeCases {
		t.Run(tc.name, func(t *testing.T) {
			ss := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
			tc.setup(ss)
			req := &pbs.RemoveHostSetHostsRequest{
				Id:      ss.GetPublicId(),
				Version: ss.GetVersion(),
				HostIds: tc.removeHosts,
			}

			got, err := s.RemoveHostSetHosts(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			s, ok := status.FromError(err)
			require.True(t, ok)
			require.NoError(t, err, "Got error: %v", s)

			assert.ElementsMatch(t, tc.resultHosts, got.GetItem().GetHostIds())
		})
	}

	ss := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

	failCases := []struct {
		name string
		req  *pbs.RemoveHostSetHostsRequest
		err  error
	}{
		{
			name: "Bad set Id",
			req: &pbs.RemoveHostSetHostsRequest{
				Id:      "bad id",
				Version: ss.GetVersion(),
				HostIds: []string{hs[0].GetPublicId()},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "empty hosts",
			req: &pbs.RemoveHostSetHostsRequest{
				Id:      ss.GetPublicId(),
				Version: ss.GetVersion(),
				HostIds: []string{},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "improperly formatted hosts",
			req: &pbs.RemoveHostSetHostsRequest{
				Id:      ss.GetPublicId(),
				Version: ss.GetVersion(),
				HostIds: []string{"invalid_host_id"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.RemoveHostSetHosts(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "RemoveHostSetHosts(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}
