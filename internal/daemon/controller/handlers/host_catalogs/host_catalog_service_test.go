// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

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
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/host_catalogs"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	hostplugin "github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/plugin/loopback"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/plugins"
	scopepb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/mr-tron/base58"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var authorizedCollectionActions = map[globals.Subtype]map[string]*structpb.ListValue{
	static.Subtype: {
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
	},
	hostplugin.Subtype: {
		"host-sets": {
			Values: []*structpb.Value{
				structpb.NewStringValue("create"),
				structpb.NewStringValue("list"),
			},
		},
		"hosts": {
			Values: []*structpb.Value{
				structpb.NewStringValue("list"),
			},
		},
	},
}

var testAuthorizedActions = []string{"no-op", "read", "update", "delete"}

func TestGet_Static(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	rw := db.New(conn)
	repo := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	pluginHostRepo := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	pluginRepo := func() (*plugin.Repository, error) {
		return plugin.NewRepository(ctx, rw, rw, kms)
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
		ScopeId:                     hc.GetProjectId(),
		Scope:                       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
		CreatedTime:                 hc.CreateTime.GetTimestamp(),
		UpdatedTime:                 hc.UpdateTime.GetTimestamp(),
		Type:                        "static",
		AuthorizedActions:           testAuthorizedActions,
		AuthorizedCollectionActions: authorizedCollectionActions[static.Subtype],
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
			req:  &pbs.GetHostCatalogRequest{Id: globals.StaticHostCatalogPrefix + "_DoesntExis"},
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
			req:  &pbs.GetHostCatalogRequest{Id: globals.StaticHostCatalogPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.GetHostCatalogRequest)
			proto.Merge(req, tc.req)

			s, err := host_catalogs.NewService(ctx, repo, pluginHostRepo, pluginRepo, iamRepoFn)
			require.NoError(err, "Couldn't create a new host catalog service.")

			got, gErr := s.GetHostCatalog(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetHostCatalog(%+v) got error %v, wanted %v", req, gErr, tc.err)
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
				cmpopts.SortSlices(func(a, b protocmp.Message) bool {
					return a.String() < b.String()
				}),
			), "GetHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestGet_Plugin(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	rw := db.New(conn)
	repo := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	pluginHostRepo := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	pluginRepo := func() (*plugin.Repository, error) {
		return plugin.NewRepository(ctx, rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	name := "test"
	plg := plugin.TestPlugin(t, conn, name)
	hc := hostplugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId(), hostplugin.WithSecretsHmac([]byte("foobar")))
	hcPrev := hostplugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId(), hostplugin.WithSecretsHmac([]byte("foobar")), hostplugin.WithPublicId(fmt.Sprintf("%s_1234567890", globals.PluginHostCatalogPreviousPrefix)))

	toMerge := &pbs.GetHostCatalogRequest{
		Id: hc.GetPublicId(),
	}

	pHostCatalog := &pb.HostCatalog{
		Id:      hc.GetPublicId(),
		ScopeId: hc.GetProjectId(),
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
		Type:                        hostplugin.Subtype.String(),
		AuthorizedActions:           testAuthorizedActions,
		AuthorizedCollectionActions: authorizedCollectionActions[hostplugin.Subtype],
		SecretsHmac:                 base58.Encode([]byte("foobar")),
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
			name: "Get an Existing Previous-ID HostCatalog",
			req:  &pbs.GetHostCatalogRequest{Id: hcPrev.GetPublicId()},
			res: func() *pbs.GetHostCatalogResponse {
				resp := proto.Clone(pHostCatalog).(*pb.HostCatalog)
				resp.Id = hcPrev.PublicId
				resp.CreatedTime = hcPrev.CreateTime.GetTimestamp()
				resp.UpdatedTime = hcPrev.UpdateTime.GetTimestamp()
				return &pbs.GetHostCatalogResponse{Item: resp}
			}(),
		},
		{
			name: "Get a non existing Host Catalog",
			req:  &pbs.GetHostCatalogRequest{Id: globals.PluginHostCatalogPrefix + "_DoesntExis"},
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
			req:  &pbs.GetHostCatalogRequest{Id: globals.PluginHostCatalogPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.GetHostCatalogRequest)
			proto.Merge(req, tc.req)

			s, err := host_catalogs.NewService(ctx, repo, pluginHostRepo, pluginRepo, iamRepoFn)
			require.NoError(err, "Couldn't create a new host catalog service.")

			got, gErr := s.GetHostCatalog(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetHostCatalog(%+v) got error %v, wanted %v", req, gErr, tc.err)
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
				cmpopts.SortSlices(func(a, b protocmp.Message) bool {
					return a.String() < b.String()
				}),
			), "GetHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	pluginHostRepo := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	pluginRepo := func() (*plugin.Repository, error) {
		return plugin.NewRepository(ctx, rw, rw, kms)
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, pNoCatalogs := iam.TestScopes(t, iamRepo)
	oWithCatalogs, pWithCatalogs := iam.TestScopes(t, iamRepo)
	oWithOtherCatalogs, pWithOtherCatalogs := iam.TestScopes(t, iamRepo)

	var wantSomeCatalogs []*pb.HostCatalog
	for _, hc := range static.TestCatalogs(t, conn, pWithCatalogs.GetPublicId(), 3) {
		wantSomeCatalogs = append(wantSomeCatalogs, &pb.HostCatalog{
			Id:                          hc.GetPublicId(),
			ScopeId:                     hc.GetProjectId(),
			CreatedTime:                 hc.GetCreateTime().GetTimestamp(),
			UpdatedTime:                 hc.GetUpdateTime().GetTimestamp(),
			Scope:                       &scopepb.ScopeInfo{Id: pWithCatalogs.GetPublicId(), Type: scope.Project.String(), ParentScopeId: oWithCatalogs.GetPublicId()},
			Version:                     1,
			Type:                        "static",
			AuthorizedActions:           testAuthorizedActions,
			AuthorizedCollectionActions: authorizedCollectionActions[static.Subtype],
		})
	}

	var testPluginCatalogs []*pb.HostCatalog
	name := "test"
	plg := plugin.TestPlugin(t, conn, name)
	for i := 0; i < 3; i++ {
		hc := hostplugin.TestCatalog(t, conn, pWithCatalogs.GetPublicId(), plg.GetPublicId())
		cat := &pb.HostCatalog{
			Id:          hc.GetPublicId(),
			ScopeId:     hc.GetProjectId(),
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
			Type:                        hostplugin.Subtype.String(),
			AuthorizedActions:           testAuthorizedActions,
			AuthorizedCollectionActions: authorizedCollectionActions[hostplugin.Subtype],
		}
		wantSomeCatalogs = append(wantSomeCatalogs, cat)
		testPluginCatalogs = append(testPluginCatalogs, cat)
	}

	var wantOtherCatalogs []*pb.HostCatalog
	for _, hc := range static.TestCatalogs(t, conn, pWithOtherCatalogs.GetPublicId(), 3) {
		wantOtherCatalogs = append(wantOtherCatalogs, &pb.HostCatalog{
			Id:                          hc.GetPublicId(),
			ScopeId:                     hc.GetProjectId(),
			CreatedTime:                 hc.GetCreateTime().GetTimestamp(),
			UpdatedTime:                 hc.GetUpdateTime().GetTimestamp(),
			Scope:                       &scopepb.ScopeInfo{Id: pWithOtherCatalogs.GetPublicId(), Type: scope.Project.String(), ParentScopeId: oWithOtherCatalogs.GetPublicId()},
			Version:                     1,
			Type:                        "static",
			AuthorizedActions:           testAuthorizedActions,
			AuthorizedCollectionActions: authorizedCollectionActions[static.Subtype],
		})
	}

	name = "different"
	diffPlg := plugin.TestPlugin(t, conn, name)
	for i := 0; i < 3; i++ {
		hc := hostplugin.TestCatalog(t, conn, pWithOtherCatalogs.GetPublicId(), diffPlg.GetPublicId())
		wantOtherCatalogs = append(wantOtherCatalogs, &pb.HostCatalog{
			Id:          hc.GetPublicId(),
			ScopeId:     hc.GetProjectId(),
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
			Type:                        hostplugin.Subtype.String(),
			AuthorizedActions:           testAuthorizedActions,
			AuthorizedCollectionActions: authorizedCollectionActions[hostplugin.Subtype],
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
			s, err := host_catalogs.NewService(ctx, repoFn, pluginHostRepo, pluginRepo, iamRepoFn)
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

			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				cmpopts.SortSlices(func(a, b protocmp.Message) bool {
					return a.String() < b.String()
				}),
			), "ListHostCatalogs() for scope %q got response %q, wanted %q", tc.req.GetScopeId(), got, tc.res)

			// Test with anon user
			got, gErr = s.ListHostCatalogs(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId(), auth.WithUserId(globals.AnonymousUserId)), tc.req)
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

func TestDelete_Static(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	rw := db.New(conn)
	repo := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	pluginHostRepo := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	pluginRepo := func() (*plugin.Repository, error) {
		return plugin.NewRepository(ctx, rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]

	s, err := host_catalogs.NewService(ctx, repo, pluginHostRepo, pluginRepo, iamRepoFn)
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
				Id: globals.StaticHostCatalogPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Bad HostCatalog Id formatting",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostCatalogRequest{
				Id: globals.StaticHostCatalogPrefix + "_bad_format",
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

func TestDelete_Plugin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	rw := db.New(conn)
	repo := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	pluginHostRepo := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	pluginRepo := func() (*plugin.Repository, error) {
		return plugin.NewRepository(ctx, rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	plg := plugin.TestPlugin(t, conn, "test")
	hc := hostplugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())

	s, err := host_catalogs.NewService(ctx, repo, pluginHostRepo, pluginRepo, iamRepoFn)
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
				Id: globals.PluginHostCatalogPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Bad HostCatalog Id formatting",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostCatalogRequest{
				Id: globals.PluginHostCatalogPrefix + "_bad_format",
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
	testCtx := context.Background()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	rw := db.New(conn)
	repo := func() (*static.Repository, error) {
		return static.NewRepository(testCtx, rw, rw, kms)
	}
	pluginHostRepo := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(testCtx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	pluginRepo := func() (*plugin.Repository, error) {
		return plugin.NewRepository(testCtx, rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]

	s, err := host_catalogs.NewService(testCtx, repo, pluginHostRepo, pluginRepo, iamRepoFn)
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
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	rw := db.New(conn)
	repo := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	pluginHostRepo := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	pluginRepo := func() (*plugin.Repository, error) {
		return plugin.NewRepository(ctx, rw, rw, kms)
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
				Uri: fmt.Sprintf("host-catalogs/%s_", globals.StaticHostCatalogPrefix),
				Item: &pb.HostCatalog{
					ScopeId:                     proj.GetPublicId(),
					Scope:                       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
					Name:                        &wrappers.StringValue{Value: "name"},
					Description:                 &wrappers.StringValue{Value: "desc"},
					Type:                        "static",
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions[static.Subtype],
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

			s, err := host_catalogs.NewService(ctx, repo, pluginHostRepo, pluginRepo, iamRepoFn)
			require.NoError(err, "Failed to create a new host catalog service.")

			got, gErr := s.CreateHostCatalog(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateHostCatalog(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.GetUri())
				assert.True(strings.HasPrefix(got.GetItem().GetId(), globals.StaticHostCatalogPrefix))
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
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				cmpopts.SortSlices(func(a, b protocmp.Message) bool {
					return a.String() < b.String()
				}),
			), "CreateHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
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
	org, proj := iam.TestScopes(t, iamRepo)
	rw := db.New(conn)
	repo := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	pluginRepo := func() (*plugin.Repository, error) {
		return plugin.NewRepository(ctx, rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	name := "test"
	plg := plugin.TestPlugin(t, conn, name)
	pluginHostRepo := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{
			plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&loopback.TestPluginHostServer{
				OnCreateCatalogFn: func(ctx context.Context, req *plgpb.OnCreateCatalogRequest) (*plgpb.OnCreateCatalogResponse, error) {
					return nil, nil
				},
			}),
		})
	}
	defaultHc := hostplugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
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
				Type:        hostplugin.Subtype.String(),
				PluginId:    plg.GetPublicId(),
			}},
			res: &pbs.CreateHostCatalogResponse{
				Uri: fmt.Sprintf("host-catalogs/%s_", globals.PluginHostCatalogPrefix),
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
					Type:                        hostplugin.Subtype.String(),
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions[hostplugin.Subtype],
				},
			},
		},
		{
			name: "Cant create in org",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				ScopeId:  org.GetParentId(),
				Type:     hostplugin.Subtype.String(),
				PluginId: plg.GetPublicId(),
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant create in global",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				ScopeId:  scope.Global.String(),
				Type:     hostplugin.Subtype.String(),
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
				Type:     hostplugin.Subtype.String(),
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
				Type:        hostplugin.Subtype.String(),
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
				Type:        hostplugin.Subtype.String(),
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

			s, err := host_catalogs.NewService(ctx, repo, pluginHostRepo, pluginRepo, iamRepoFn)
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
				assert.True(strings.HasPrefix(got.GetItem().GetId(), fmt.Sprintf("%s_", globals.PluginHostCatalogPrefix)))
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
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				cmpopts.SortSlices(func(a, b protocmp.Message) bool {
					return a.String() < b.String()
				}),
			), "CreateHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
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
	_, proj := iam.TestScopes(t, iamRepo)
	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	pluginHostRepo := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	pluginRepo := func() (*plugin.Repository, error) {
		return plugin.NewRepository(ctx, rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	tested, err := host_catalogs.NewService(ctx, repoFn, pluginHostRepo, pluginRepo, iamRepoFn)
	require.NoError(t, err, "Failed to create a new host catalog service.")

	hc, err := static.NewHostCatalog(ctx, proj.GetPublicId(), static.WithName("default"), static.WithDescription("default"))
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
					ScopeId:                     hc.GetProjectId(),
					Scope:                       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
					Name:                        &wrappers.StringValue{Value: "new"},
					Description:                 &wrappers.StringValue{Value: "desc"},
					CreatedTime:                 hc.GetCreateTime().GetTimestamp(),
					Type:                        "static",
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions[static.Subtype],
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
					ScopeId:                     hc.GetProjectId(),
					Scope:                       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
					Name:                        &wrappers.StringValue{Value: "new"},
					Description:                 &wrappers.StringValue{Value: "desc"},
					CreatedTime:                 hc.GetCreateTime().GetTimestamp(),
					Type:                        "static",
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions[static.Subtype],
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
					ScopeId:                     hc.GetProjectId(),
					Scope:                       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
					Description:                 &wrappers.StringValue{Value: "default"},
					CreatedTime:                 hc.GetCreateTime().GetTimestamp(),
					Type:                        "static",
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions[static.Subtype],
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
					ScopeId:                     hc.GetProjectId(),
					Scope:                       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
					Name:                        &wrappers.StringValue{Value: "default"},
					CreatedTime:                 hc.GetCreateTime().GetTimestamp(),
					Type:                        "static",
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions[static.Subtype],
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
					ScopeId:                     hc.GetProjectId(),
					Scope:                       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
					Name:                        &wrappers.StringValue{Value: "updated"},
					Description:                 &wrappers.StringValue{Value: "default"},
					CreatedTime:                 hc.GetCreateTime().GetTimestamp(),
					Type:                        "static",
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions[static.Subtype],
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
					ScopeId:                     hc.GetProjectId(),
					Scope:                       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
					Name:                        &wrappers.StringValue{Value: "default"},
					Description:                 &wrappers.StringValue{Value: "notignored"},
					CreatedTime:                 hc.GetCreateTime().GetTimestamp(),
					Type:                        "static",
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions[static.Subtype],
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
				Id: globals.StaticHostCatalogPrefix + "_DoesntExis",
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
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				cmpopts.SortSlices(func(a, b protocmp.Message) bool {
					return a.String() < b.String()
				}),
			), "UpdateHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
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
	lp, err := loopback.NewLoopbackPlugin()
	require.NoError(t, err)
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(lp),
	}

	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(testCtx, rw, rw, kms)
	}
	pluginHostRepo := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(testCtx, rw, rw, kms, sche, plgm)
	}
	pluginRepo := func() (*plugin.Repository, error) {
		return plugin.NewRepository(testCtx, rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	tested, err := host_catalogs.NewService(testCtx, repoFn, pluginHostRepo, pluginRepo, iamRepoFn)
	require.NoError(t, err, "Failed to create a new host catalog service.")

	ctx := auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId())

	freshCatalog := func(t *testing.T) *pb.HostCatalog {
		attr, err := structpb.NewStruct(map[string]any{
			"foo": "bar",
		})
		require.NoError(t, err)
		resp, err := tested.CreateHostCatalog(ctx, &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
			ScopeId:     proj.GetPublicId(),
			PluginId:    plg.GetPublicId(),
			Name:        wrapperspb.String("default"),
			Description: wrapperspb.String("default"),
			Type:        "plugin",
			Attrs: &pb.HostCatalog_Attributes{
				Attributes: attr,
			},
		}})
		require.NoError(t, err)
		id := resp.GetItem().GetId()
		t.Cleanup(func() {
			_, err := tested.DeleteHostCatalog(ctx, &pbs.DeleteHostCatalogRequest{Id: id})
			require.NoError(t, err)
		})
		return resp.GetItem()
	}

	type updateFn func(catalog *pb.HostCatalog)
	clearReadOnlyFields := func() updateFn {
		return func(c *pb.HostCatalog) {
			c.Id = ""
			c.Plugin = nil
			c.AuthorizedActions = nil
			c.AuthorizedCollectionActions = nil
			c.CreatedTime = nil
			c.UpdatedTime = nil
		}
	}
	updateName := func(i *wrappers.StringValue) updateFn {
		return func(c *pb.HostCatalog) {
			c.Name = i
		}
	}
	updateDesc := func(i *wrappers.StringValue) updateFn {
		return func(c *pb.HostCatalog) {
			c.Description = i
		}
	}
	updateAttrs := func(i *structpb.Struct) updateFn {
		return func(c *pb.HostCatalog) {
			c.Attrs = &pb.HostCatalog_Attributes{
				Attributes: i,
			}
		}
	}
	updateSecrets := func(i *structpb.Struct) updateFn {
		return func(c *pb.HostCatalog) {
			c.Secrets = i
		}
	}

	cases := []struct {
		name    string
		masks   []string
		changes []updateFn
		check   func(*testing.T, *pb.HostCatalog)
		err     error
	}{
		{
			name:  "Update an Existing HostCatalog",
			masks: []string{"name", "description"},
			changes: []updateFn{
				clearReadOnlyFields(),
				updateName(wrapperspb.String("new")),
				updateDesc(wrapperspb.String("desc")),
			},
			check: func(t *testing.T, in *pb.HostCatalog) {
				assert.Equal(t, "new", in.Name.GetValue())
				assert.Equal(t, "desc", in.Description.GetValue())
				assert.Empty(t, cmp.Diff(
					authorizedCollectionActions[hostplugin.Subtype],
					in.GetAuthorizedCollectionActions(),
					cmpopts.IgnoreUnexported(structpb.ListValue{}, structpb.Value{}),
					cmpopts.SortSlices(func(a, b string) bool {
						return a < b
					}),
					cmpopts.SortSlices(func(a, b protocmp.Message) bool {
						return a.String() < b.String()
					}),
				))
			},
		},
		{
			name:  "Update arbitrary attribute for catalog",
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
			check: func(t *testing.T, in *pb.HostCatalog) {
				assert.Equal(t, map[string]any{"newkey": "newvalue"}, in.GetAttributes().AsMap())
			},
		},
		{
			name:  "Update empty attributes for catalog",
			masks: []string{"attributes"},
			changes: []updateFn{
				clearReadOnlyFields(),
				updateAttrs(func() *structpb.Struct {
					ret, _ := structpb.NewStruct(nil)
					return ret
				}()),
			},
			check: func(t *testing.T, in *pb.HostCatalog) {
				assert.Equal(t, (*structpb.Struct)(nil), in.GetAttributes())
			},
		},
		{
			name:  "Update secrets",
			masks: []string{"secrets.key1", "secrets.key2"},
			changes: []updateFn{
				clearReadOnlyFields(),
				updateSecrets(func() *structpb.Struct {
					attr, err := structpb.NewStruct(map[string]any{
						"key1": "val1",
					})
					require.NoError(t, err)
					return attr
				}()),
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
			check: func(t *testing.T, in *pb.HostCatalog) {
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
			check: func(t *testing.T, in *pb.HostCatalog) {
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
			check: func(t *testing.T, in *pb.HostCatalog) {
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
			check: func(t *testing.T, in *pb.HostCatalog) {
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
			check: func(t *testing.T, in *pb.HostCatalog) {
				assert.Equal(t, "default", in.Name.GetValue())
				assert.Equal(t, "updated", in.Description.GetValue())
			},
		},
		{
			name:  "Cant change type",
			masks: []string{"type"},
			changes: []updateFn{
				clearReadOnlyFields(),
				func(c *pb.HostCatalog) {
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
				func(c *pb.HostCatalog) {
					c.UpdatedTime = timestamppb.Now()
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			hc := freshCatalog(t)

			id := hc.GetId()
			for _, f := range tc.changes {
				f(hc)
			}

			req := &pbs.UpdateHostCatalogRequest{
				Id:         id,
				Item:       hc,
				UpdateMask: &field_mask.FieldMask{Paths: tc.masks},
			}

			// Test some bad versions
			req.Item.Version = 2
			_, gErr := tested.UpdateHostCatalog(ctx, req)
			require.Error(gErr)
			req.Item.Version = 0
			_, gErr = tested.UpdateHostCatalog(ctx, req)
			require.Error(gErr)
			req.Item.Version = 1

			got, gErr := tested.UpdateHostCatalog(ctx, req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateHostCatalog(%+v) got error %v, wanted %v", req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			require.NotNil(got)

			item := got.GetItem()
			assert.Equal(uint32(2), item.GetVersion())
			assert.Greater(item.GetUpdatedTime().AsTime().UnixNano(), item.GetCreatedTime().AsTime().UnixNano())
			if tc.check != nil {
				tc.check(t, item)
			}
		})
	}
}
