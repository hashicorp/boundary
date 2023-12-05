// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package host_sets_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/host_sets"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host"
	hostplugin "github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/plugin/loopback"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/internal/types/subtypes"
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
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var testAuthorizedActions = map[subtypes.Subtype][]string{
	static.Subtype:     {"no-op", "read", "update", "delete", "add-hosts", "set-hosts", "remove-hosts"},
	hostplugin.Subtype: {"no-op", "read", "update", "delete"},
}

func TestGet_Static(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	org, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	pluginRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
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
		AuthorizedActions: testAuthorizedActions[static.Subtype],
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
			req:  &pbs.GetHostSetRequest{Id: globals.StaticHostSetPrefix + "_DoesntExis"},
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
			req:  &pbs.GetHostSetRequest{Id: globals.StaticHostPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.GetHostSetRequest)
			proto.Merge(req, tc.req)

			s, err := host_sets.NewService(ctx, repoFn, pluginRepoFn)
			require.NoError(err, "Couldn't create a new host set service.")

			got, gErr := s.GetHostSet(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetHostSet(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}

			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "GetHostSet(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestGet_Plugin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	org, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}

	name := "test"
	prefEndpoints := []string{"cidr:1.2.3.4", "cidr:2.3.4.5/24"}
	plg := plugin.TestPlugin(t, conn, name)
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&loopback.TestPluginServer{}),
	}
	pluginRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, plgm)
	}

	hc := hostplugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	hs := hostplugin.TestSet(t, conn, kms, sche, hc, plgm, hostplugin.WithPreferredEndpoints(prefEndpoints), hostplugin.WithSyncIntervalSeconds(-1))
	hsPrev := hostplugin.TestSet(t, conn, kms, sche, hc, plgm, hostplugin.WithPreferredEndpoints(prefEndpoints), hostplugin.WithSyncIntervalSeconds(-1), hostplugin.WithPublicId(fmt.Sprintf("%s_1234567890", globals.PluginHostSetPreviousPrefix)))

	toMerge := &pbs.GetHostSetRequest{}

	pHostSet := &pb.HostSet{
		HostCatalogId: hc.GetPublicId(),
		Id:            hs.GetPublicId(),
		CreatedTime:   hs.CreateTime.GetTimestamp(),
		UpdatedTime:   hs.UpdateTime.GetTimestamp(),
		Type:          hostplugin.Subtype.String(),
		Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
		Plugin: &plugins.PluginInfo{
			Id:          plg.GetPublicId(),
			Name:        plg.GetName(),
			Description: plg.GetDescription(),
		},
		PreferredEndpoints:  prefEndpoints,
		SyncIntervalSeconds: &wrappers.Int32Value{Value: -1},
		AuthorizedActions:   testAuthorizedActions[hostplugin.Subtype],
	}

	cases := []struct {
		name string
		req  *pbs.GetHostSetRequest
		res  *pbs.GetHostSetResponse
		err  error
	}{
		{
			name: "Get an Existing HostSet",
			req:  &pbs.GetHostSetRequest{Id: hs.GetPublicId()},
			res:  &pbs.GetHostSetResponse{Item: pHostSet},
		},
		{
			name: "Get an Existing Previous-ID HostSet",
			req:  &pbs.GetHostSetRequest{Id: hsPrev.GetPublicId()},
			res: func() *pbs.GetHostSetResponse {
				resp := proto.Clone(pHostSet).(*pb.HostSet)
				resp.Id = hsPrev.PublicId
				resp.CreatedTime = hsPrev.CreateTime.GetTimestamp()
				resp.UpdatedTime = hsPrev.UpdateTime.GetTimestamp()
				return &pbs.GetHostSetResponse{Item: resp}
			}(),
		},
		{
			name: "Get a non existing Host Set",
			req:  &pbs.GetHostSetRequest{Id: globals.PluginHostSetPrefix + "_DoesntExis"},
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
			req:  &pbs.GetHostSetRequest{Id: globals.PluginHostSetPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.GetHostSetRequest)
			proto.Merge(req, tc.req)

			s, err := host_sets.NewService(ctx, repoFn, pluginRepoFn)
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
			assert.Empty(cmp.Diff(
				got.GetItem(),
				tc.res.GetItem(),
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "GetHostSet(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestList_Static(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	org, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	pluginRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
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
			AuthorizedActions: testAuthorizedActions[static.Subtype],
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
			s, err := host_sets.NewService(ctx, repoFn, pluginRepoFn)
			require.NoError(err, "Couldn't create new host set service.")

			// Test with non-anon user
			got, gErr := s.ListHostSets(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListHostSets(%q) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "ListHostSets(%q) got response %q, wanted %q", tc.req, got, tc.res)

			// Test with anon user
			got, gErr = s.ListHostSets(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId(), auth.WithUserId(globals.AnonymousUserId)), tc.req)
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
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	org, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	name := "test"
	plg := plugin.TestPlugin(t, conn, name)
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&loopback.TestPluginServer{}),
	}
	pluginRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, plgm)
	}
	hc := hostplugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	hcNoHosts := hostplugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	preferredEndpoints := []string{"cidr:1.2.3.4", "dns:*.foobar.com"}

	var wantHs []*pb.HostSet
	for i := 0; i < 10; i++ {
		h := hostplugin.TestSet(t, conn, kms, sche, hc, plgm, hostplugin.WithPreferredEndpoints(preferredEndpoints), hostplugin.WithSyncIntervalSeconds(5))
		wantHs = append(wantHs, &pb.HostSet{
			Id:            h.GetPublicId(),
			HostCatalogId: h.GetCatalogId(),
			Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
			Plugin: &plugins.PluginInfo{
				Id:          plg.GetPublicId(),
				Name:        plg.GetName(),
				Description: plg.GetDescription(),
			},
			CreatedTime:         h.GetCreateTime().GetTimestamp(),
			UpdatedTime:         h.GetUpdateTime().GetTimestamp(),
			Version:             h.GetVersion(),
			Type:                hostplugin.Subtype.String(),
			AuthorizedActions:   testAuthorizedActions[hostplugin.Subtype],
			PreferredEndpoints:  preferredEndpoints,
			SyncIntervalSeconds: &wrappers.Int32Value{Value: 5},
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
			s, err := host_sets.NewService(ctx, repoFn, pluginRepoFn)
			require.NoError(err, "Couldn't create new host set service.")

			// Test with non-anon user
			got, gErr := s.ListHostSetsWithOptions(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req, host.WithOrderByCreateTime(false))
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListHostSets(%q) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "ListHostSets(%q) got response %q, wanted %q", tc.req, got, tc.res)

			// Test with anon user
			got, gErr = s.ListHostSets(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId(), auth.WithUserId(globals.AnonymousUserId)), tc.req)
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

func TestDelete_Static(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	pluginRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	h := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

	s, err := host_sets.NewService(ctx, repoFn, pluginRepoFn)
	require.NoError(t, err, "Couldn't create a new host set service.")

	cases := []struct {
		name      string
		projectId string
		req       *pbs.DeleteHostSetRequest
		res       *pbs.DeleteHostSetResponse
		err       error
	}{
		{
			name:      "Delete an Existing Host Set",
			projectId: proj.GetPublicId(),
			req: &pbs.DeleteHostSetRequest{
				Id: h.GetPublicId(),
			},
		},
		{
			name:      "Delete bad id Host Set",
			projectId: proj.GetPublicId(),
			req: &pbs.DeleteHostSetRequest{
				Id: globals.StaticHostSetPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:      "Bad Host Id formatting",
			projectId: proj.GetPublicId(),
			req: &pbs.DeleteHostSetRequest{
				Id: globals.StaticHostSetPrefix + "_bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteHostSet(auth.DisabledAuthTestContext(iamRepoFn, tc.projectId), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteHostSet(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(
				tc.res,
				got,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "DeleteHostSet(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_Plugin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	pluginRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	name := "test"
	plg := plugin.TestPlugin(t, conn, name)
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&loopback.TestPluginServer{}),
	}

	hc := hostplugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	h := hostplugin.TestSet(t, conn, kms, sche, hc, plgm)

	s, err := host_sets.NewService(ctx, repoFn, pluginRepoFn)
	require.NoError(t, err, "Couldn't create a new host set service.")

	cases := []struct {
		name      string
		projectId string
		req       *pbs.DeleteHostSetRequest
		res       *pbs.DeleteHostSetResponse
		err       error
	}{
		{
			name:      "Delete an Existing Host Set",
			projectId: proj.GetPublicId(),
			req: &pbs.DeleteHostSetRequest{
				Id: h.GetPublicId(),
			},
		},
		{
			name:      "Delete bad id Host Set",
			projectId: proj.GetPublicId(),
			req: &pbs.DeleteHostSetRequest{
				Id: globals.PluginHostSetPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:      "Bad Host Id formatting",
			projectId: proj.GetPublicId(),
			req: &pbs.DeleteHostSetRequest{
				Id: globals.PluginHostSetPrefix + "_bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteHostSet(auth.DisabledAuthTestContext(iamRepoFn, tc.projectId), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteHostSet(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(
				tc.res,
				got,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "DeleteHostSet(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	plgRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	h := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

	s, err := host_sets.NewService(ctx, repoFn, plgRepoFn)
	require.NoError(err, "Couldn't create a new host set service.")
	req := &pbs.DeleteHostSetRequest{
		Id: h.GetPublicId(),
	}
	ctx = auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId())
	_, gErr := s.DeleteHostSet(ctx, req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteHostSet(ctx, req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")
}

func TestCreate_Static(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	org, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	plgRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	prefEndpoints := []string{"cidr:1.2.3.4", "cidr:2.3.4.5/24"}

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
				Uri: fmt.Sprintf("host-sets/%s_", globals.StaticHostSetPrefix),
				Item: &pb.HostSet{
					HostCatalogId:     hc.GetPublicId(),
					Scope:             &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:              &wrappers.StringValue{Value: "name"},
					Description:       &wrappers.StringValue{Value: "desc"},
					Type:              "static",
					AuthorizedActions: testAuthorizedActions[static.Subtype],
				},
			},
		},
		{
			name: "With Preferred Endpoints",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				HostCatalogId:      hc.GetPublicId(),
				Name:               &wrappers.StringValue{Value: "name"},
				Description:        &wrappers.StringValue{Value: "desc"},
				Type:               static.Subtype.String(),
				PreferredEndpoints: prefEndpoints,
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
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
				Uri: fmt.Sprintf("host-sets/%s_", globals.StaticHostSetPrefix),
				Item: &pb.HostSet{
					HostCatalogId:     hc.GetPublicId(),
					Scope:             &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:              &wrappers.StringValue{Value: "no type name"},
					Description:       &wrappers.StringValue{Value: "no type desc"},
					Type:              "static",
					AuthorizedActions: testAuthorizedActions[static.Subtype],
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

			s, err := host_sets.NewService(ctx, repoFn, plgRepoFn)
			require.NoError(err, "Failed to create a new host set service.")

			got, gErr := s.CreateHostSet(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateHostSet(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.GetUri())
				assert.True(strings.HasPrefix(got.GetItem().GetId(), globals.StaticHostSetPrefix), got.GetItem().GetId())
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
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "CreateHostSet(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestCreate_Plugin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	org, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	name := "test"
	plg := plugin.TestPlugin(t, conn, name)
	plgRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{
			plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&loopback.TestPluginHostServer{
				OnCreateSetFn: func(ctx context.Context, req *plgpb.OnCreateSetRequest) (*plgpb.OnCreateSetResponse, error) {
					return nil, nil
				},
			}),
		})
	}
	hc := hostplugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())

	attrs := map[string]any{
		"int":         1,
		"zero int":    0,
		"string":      "foo",
		"zero string": "",
		"bytes":       []byte("bar"),
		"zero bytes":  nil,
		"bool":        true,
		"zero bool":   false,
		"nested": map[string]any{
			"int":         1,
			"zero int":    0,
			"string":      "foo",
			"zero string": "",
			"bytes":       []byte("bar"),
			"zero bytes":  nil,
			"bool":        true,
			"zero bool":   false,
		},
	}
	testInputAttrs, err := structpb.NewStruct(attrs)
	require.NoError(t, err)
	// The result should clear out all keys with nil values...
	delete(attrs, "zero bytes")
	delete(attrs["nested"].(map[string]any), "zero bytes")
	testOutputAttrs, err := structpb.NewStruct(attrs)
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
				HostCatalogId:       hc.GetPublicId(),
				Name:                &wrappers.StringValue{Value: "No Attributes"},
				Description:         &wrappers.StringValue{Value: "desc"},
				Type:                hostplugin.Subtype.String(),
				SyncIntervalSeconds: &wrapperspb.Int32Value{Value: -1},
			}},
			res: &pbs.CreateHostSetResponse{
				Uri: fmt.Sprintf("host-sets/%s_", globals.PluginHostSetPrefix),
				Item: &pb.HostSet{
					HostCatalogId: hc.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Plugin: &plugins.PluginInfo{
						Id:          plg.GetPublicId(),
						Name:        plg.GetName(),
						Description: plg.GetDescription(),
					},
					Name:                &wrappers.StringValue{Value: "No Attributes"},
					Description:         &wrappers.StringValue{Value: "desc"},
					Type:                hostplugin.Subtype.String(),
					AuthorizedActions:   testAuthorizedActions[hostplugin.Subtype],
					SyncIntervalSeconds: &wrapperspb.Int32Value{Value: -1},
				},
			},
		},
		{
			name: "With Attributes",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				HostCatalogId:       hc.GetPublicId(),
				Name:                &wrappers.StringValue{Value: "With Attributes"},
				Description:         &wrappers.StringValue{Value: "desc"},
				Type:                hostplugin.Subtype.String(),
				SyncIntervalSeconds: &wrapperspb.Int32Value{Value: 90},
				Attrs: &pb.HostSet_Attributes{
					Attributes: testInputAttrs,
				},
			}},
			res: &pbs.CreateHostSetResponse{
				Uri: fmt.Sprintf("host-sets/%s_", globals.PluginHostSetPrefix),
				Item: &pb.HostSet{
					HostCatalogId: hc.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Plugin: &plugins.PluginInfo{
						Id:          plg.GetPublicId(),
						Name:        plg.GetName(),
						Description: plg.GetDescription(),
					},
					Name:                &wrappers.StringValue{Value: "With Attributes"},
					Description:         &wrappers.StringValue{Value: "desc"},
					Type:                hostplugin.Subtype.String(),
					SyncIntervalSeconds: &wrapperspb.Int32Value{Value: 90},
					AuthorizedActions:   testAuthorizedActions[hostplugin.Subtype],
					Attrs: &pb.HostSet_Attributes{
						Attributes: testOutputAttrs,
					},
				},
			},
		},
		{
			name: "With Preferred Endpoints",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				HostCatalogId:      hc.GetPublicId(),
				Name:               &wrappers.StringValue{Value: "name"},
				Description:        &wrappers.StringValue{Value: "desc"},
				Type:               hostplugin.Subtype.String(),
				PreferredEndpoints: prefEndpoints,
			}},
			res: &pbs.CreateHostSetResponse{
				Uri: fmt.Sprintf("host-sets/%s_", globals.PluginHostSetPrefix),
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
					Type:               hostplugin.Subtype.String(),
					PreferredEndpoints: prefEndpoints,
					AuthorizedActions:  testAuthorizedActions[hostplugin.Subtype],
				},
			},
		},
		{
			name: "Bad Preferred Endpoints",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				HostCatalogId:      hc.GetPublicId(),
				Name:               &wrappers.StringValue{Value: "name"},
				Description:        &wrappers.StringValue{Value: "desc"},
				Type:               hostplugin.Subtype.String(),
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
				Uri: fmt.Sprintf("host-sets/%s_", globals.PluginHostSetPrefix),
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
					Type:              hostplugin.Subtype.String(),
					AuthorizedActions: testAuthorizedActions[hostplugin.Subtype],
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

			s, err := host_sets.NewService(ctx, repoFn, plgRepoFn)
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
				assert.True(strings.HasPrefix(got.GetItem().GetId(), globals.PluginHostSetPrefix), got.GetItem().GetId())
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
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "CreateHostSet(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestUpdate_Static(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	org, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	repo, err := repoFn()
	require.NoError(t, err, "Couldn't create new static repo.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]

	h := static.TestHosts(t, conn, hc.GetPublicId(), 2)
	hIds := []string{h[0].GetPublicId(), h[1].GetPublicId()}

	hs, err := static.NewHostSet(ctx, hc.GetPublicId(), static.WithName("default"), static.WithDescription("default"))
	require.NoError(t, err)
	hs, err = repo.CreateSet(ctx, proj.GetPublicId(), hs)
	require.NoError(t, err)

	static.TestSetMembers(t, conn, hs.GetPublicId(), h)

	var version uint32 = 1

	resetHostSet := func() {
		version++
		_, _, _, err = repo.UpdateSet(ctx, proj.GetPublicId(), hs, version, []string{"Name", "Description"})
		require.NoError(t, err, "Failed to reset host.")
		version++
	}

	hCreated := hs.GetCreateTime().GetTimestamp().AsTime()
	toMerge := &pbs.UpdateHostSetRequest{
		Id: hs.GetPublicId(),
	}

	plgRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	tested, err := host_sets.NewService(ctx, repoFn, plgRepoFn)
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
					AuthorizedActions: testAuthorizedActions[static.Subtype],
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
					AuthorizedActions: testAuthorizedActions[static.Subtype],
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
					AuthorizedActions: testAuthorizedActions[static.Subtype],
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
					AuthorizedActions: testAuthorizedActions[static.Subtype],
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
					AuthorizedActions: testAuthorizedActions[static.Subtype],
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
					AuthorizedActions: testAuthorizedActions[static.Subtype],
				},
			},
		},
		{
			name: "Update a Non Existing Host Set",
			req: &pbs.UpdateHostSetRequest{
				Id: globals.StaticHostSetPrefix + "_DoesntExis",
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
			if tc.res != nil {
				sort.Slice(tc.res.GetItem().HostIds, func(i, j int) bool {
					return tc.res.GetItem().HostIds[i] < tc.res.GetItem().HostIds[j]
				})
			}
			if got != nil && got.Item != nil {
				sort.Slice(got.GetItem().HostIds, func(i, j int) bool {
					return got.GetItem().HostIds[i] < got.GetItem().HostIds[j]
				})
			}

			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "UpdateHostSet(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestUpdate_Plugin(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	rw := db.New(conn)

	name := "test"
	plg := plugin.TestPlugin(t, conn, name)
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&loopback.TestPluginServer{}),
	}

	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(testCtx, rw, rw, kms)
	}
	pluginHostRepo := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(testCtx, rw, rw, kms, sche, plgm)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	tested, err := host_sets.NewService(testCtx, repoFn, pluginHostRepo)
	require.NoError(t, err, "Failed to create a new host catalog service.")

	hc := hostplugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	ctx := auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId())

	freshSet := func(t *testing.T) *pb.HostSet {
		attr, err := structpb.NewStruct(map[string]any{
			"foo": "bar",
		})
		require.NoError(t, err)
		resp, err := tested.CreateHostSet(ctx, &pbs.CreateHostSetRequest{Item: &pb.HostSet{
			HostCatalogId: hc.GetPublicId(),
			Name:          wrapperspb.String("default"),
			Description:   wrapperspb.String("default"),
			Type:          hostplugin.Subtype.String(),
			Attrs: &pb.HostSet_Attributes{
				Attributes: attr,
			},
			PreferredEndpoints: []string{"dns:default"},
		}})
		require.NoError(t, err)
		id := resp.GetItem().GetId()
		t.Cleanup(func() {
			_, err := tested.DeleteHostSet(ctx, &pbs.DeleteHostSetRequest{Id: id})
			require.NoError(t, err)
		})
		return resp.GetItem()
	}

	type updateFn func(catalog *pb.HostSet)
	clearReadOnlyFields := func() updateFn {
		return func(c *pb.HostSet) {
			c.Id = ""
			c.Plugin = nil
			c.AuthorizedActions = nil
			c.CreatedTime = nil
			c.UpdatedTime = nil
		}
	}
	updateName := func(i *wrappers.StringValue) updateFn {
		return func(c *pb.HostSet) {
			c.Name = i
		}
	}
	updateDesc := func(i *wrappers.StringValue) updateFn {
		return func(c *pb.HostSet) {
			c.Description = i
		}
	}
	updatePreferedEndpoints := func(i []string) updateFn {
		return func(c *pb.HostSet) {
			c.PreferredEndpoints = i
		}
	}
	updateSyncInterval := func(i *wrapperspb.Int32Value) updateFn {
		return func(c *pb.HostSet) {
			c.SyncIntervalSeconds = i
		}
	}
	updateAttrs := func(i *structpb.Struct) updateFn {
		return func(c *pb.HostSet) {
			c.Attrs = &pb.HostSet_Attributes{
				Attributes: i,
			}
		}
	}

	cases := []struct {
		name    string
		masks   []string
		changes []updateFn
		check   func(*testing.T, *pb.HostSet)
		err     error
	}{
		{
			name:  "Update an existing resource",
			masks: []string{"name", "description"},
			changes: []updateFn{
				clearReadOnlyFields(),
				updateName(wrapperspb.String("new")),
				updateDesc(wrapperspb.String("desc")),
			},
			check: func(t *testing.T, in *pb.HostSet) {
				assert.Equal(t, "new", in.Name.GetValue())
				assert.Equal(t, "desc", in.Description.GetValue())
			},
		},
		{
			name:  "Update arbitrary attribute",
			masks: []string{"attributes.newkey", "attributes.foo"},
			changes: []updateFn{
				clearReadOnlyFields(),
				updateAttrs(func() *structpb.Struct {
					attr, err := structpb.NewStruct(map[string]any{
						"newkey": "newvalue",
						"foo":    nil,
					})
					require.NoError(t, err)
					return attr
				}()),
			},
			check: func(t *testing.T, in *pb.HostSet) {
				assert.Equal(t, map[string]any{"newkey": "newvalue"}, in.GetAttributes().AsMap())
			},
		},
		{
			name:  "Set attributes null",
			masks: []string{"attributes"},
			changes: []updateFn{
				clearReadOnlyFields(),
				updateAttrs(func() *structpb.Struct {
					ret, _ := structpb.NewStruct(nil)
					return ret
				}()),
			},
			check: func(t *testing.T, in *pb.HostSet) {
				assert.Equal(t, (*structpb.Struct)(nil), in.GetAttributes())
			},
		},
		{
			name:  "Update preferred endpoints",
			masks: []string{"preferred_endpoints"},
			changes: []updateFn{
				clearReadOnlyFields(),
				updatePreferedEndpoints([]string{"dns:new"}),
			},
			check: func(t *testing.T, in *pb.HostSet) {
				assert.Equal(t, in.PreferredEndpoints, []string{"dns:new"})
			},
		},
		{
			name:  "Update sync interval",
			masks: []string{"sync_interval_seconds"},
			changes: []updateFn{
				clearReadOnlyFields(),
				updateSyncInterval(wrapperspb.Int32(42)),
			},
			check: func(t *testing.T, in *pb.HostSet) {
				assert.Equal(t, in.SyncIntervalSeconds, wrapperspb.Int32(42))
			},
		},
		{
			name:  "Don't update preferred_endpoints",
			masks: []string{"name"},
			changes: []updateFn{
				clearReadOnlyFields(),
				updateName(wrapperspb.String("new")),
				updatePreferedEndpoints([]string{"dns:ignored"}),
			},
			check: func(t *testing.T, in *pb.HostSet) {
				assert.Equal(t, "new", in.Name.GetValue())
				assert.Equal(t, in.PreferredEndpoints, []string{"dns:default"})
			},
		},
		{
			name:  "Multiple Paths in single string",
			masks: []string{"name,description"},
			changes: []updateFn{
				clearReadOnlyFields(),
				updateName(wrapperspb.String("new")),
				updateDesc(wrapperspb.String("desc")),
			},
			check: func(t *testing.T, in *pb.HostSet) {
				assert.Equal(t, "new", in.Name.GetValue())
				assert.Equal(t, "desc", in.Description.GetValue())
			},
		},
		{
			name: "No Update Mask",
			changes: []updateFn{
				clearReadOnlyFields(),
				updateName(wrapperspb.String("new")),
				updateDesc(wrapperspb.String("desc")),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:  "Empty Path",
			masks: []string{},
			changes: []updateFn{
				clearReadOnlyFields(),
				updateName(wrapperspb.String("new")),
				updateDesc(wrapperspb.String("desc")),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:  "Only non-existant paths in Mask",
			masks: []string{"nonexistant_field"},
			changes: []updateFn{
				clearReadOnlyFields(),
				updateName(wrapperspb.String("new")),
				updateDesc(wrapperspb.String("desc")),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:  "Unset Name",
			masks: []string{"name"},
			changes: []updateFn{
				clearReadOnlyFields(),
				updateName(nil),
				updateDesc(wrapperspb.String("ignored")),
			},
			check: func(t *testing.T, in *pb.HostSet) {
				assert.Nil(t, in.Name)
				assert.Equal(t, "default", in.Description.GetValue())
			},
		},
		{
			name:  "Unset Description",
			masks: []string{"description"},
			changes: []updateFn{
				clearReadOnlyFields(),
				updateName(wrapperspb.String("ignored")),
				updateDesc(nil),
			},
			check: func(t *testing.T, in *pb.HostSet) {
				assert.Nil(t, in.Description)
				assert.Equal(t, "default", in.Name.GetValue())
			},
		},
		{
			name:  "Update Only Name",
			masks: []string{"name"},
			changes: []updateFn{
				clearReadOnlyFields(),
				updateName(wrapperspb.String("updated")),
				updateDesc(wrapperspb.String("ignored")),
			},
			check: func(t *testing.T, in *pb.HostSet) {
				assert.Equal(t, "updated", in.Name.GetValue())
				assert.Equal(t, "default", in.Description.GetValue())
			},
		},
		{
			name:  "Update Only Description",
			masks: []string{"description"},
			changes: []updateFn{
				clearReadOnlyFields(),
				updateName(wrapperspb.String("ignored")),
				updateDesc(wrapperspb.String("updated")),
			},
			check: func(t *testing.T, in *pb.HostSet) {
				assert.Equal(t, "default", in.Name.GetValue())
				assert.Equal(t, "updated", in.Description.GetValue())
			},
		},
		{
			name:  "Cant change type",
			masks: []string{"type"},
			changes: []updateFn{
				clearReadOnlyFields(),
				func(c *pb.HostSet) {
					c.Type = "static"
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:  "Cant specify Updated Time",
			masks: []string{"updated_time"},
			changes: []updateFn{
				clearReadOnlyFields(),
				func(c *pb.HostSet) {
					c.UpdatedTime = timestamppb.Now()
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			hc := freshSet(t)

			id := hc.GetId()
			for _, f := range tc.changes {
				f(hc)
			}

			req := &pbs.UpdateHostSetRequest{
				Id:         id,
				Item:       hc,
				UpdateMask: &field_mask.FieldMask{Paths: tc.masks},
			}

			// Test some bad versions
			req.Item.Version = 2
			_, gErr := tested.UpdateHostSet(ctx, req)
			require.Error(gErr)
			req.Item.Version = 0
			_, gErr = tested.UpdateHostSet(ctx, req)
			require.Error(gErr)
			req.Item.Version = 1

			got, gErr := tested.UpdateHostSet(ctx, req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateHostSet(%+v) got error %v, wanted %v", req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			require.NotNil(got)

			item := got.GetItem()
			assert.Equal(uint32(2), item.GetVersion())
			assert.Greater(item.GetUpdatedTime().AsTime().UnixNano(), item.GetCreatedTime().AsTime().UnixNano())
			tc.check(t, item)
		})
	}
}

func TestAddHostSetHosts(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	plgRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	s, err := host_sets.NewService(ctx, repoFn, plgRepoFn)
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
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	plgRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	s, err := host_sets.NewService(ctx, repoFn, plgRepoFn)
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
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	plgRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	s, err := host_sets.NewService(ctx, repoFn, plgRepoFn)
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
