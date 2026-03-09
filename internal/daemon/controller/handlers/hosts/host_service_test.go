// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package hosts_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/hosts"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/host"
	hostplugin "github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/plugin/loopback"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/scope"
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
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var testAuthorizedActions = map[globals.Subtype][]string{
	static.Subtype:     {"no-op", "read", "update", "delete"},
	hostplugin.Subtype: {"no-op", "read"},
}

func staticHostToProto(h host.Host, proj *iam.Scope, hostSet *static.HostSet) *pb.Host {
	return &pb.Host{
		Id:            h.GetPublicId(),
		HostCatalogId: h.GetCatalogId(),
		Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
		CreatedTime:   h.GetCreateTime().GetTimestamp(),
		UpdatedTime:   h.GetUpdateTime().GetTimestamp(),
		Version:       h.GetVersion(),
		Type:          static.Subtype.String(),
		Attrs: &pb.Host_StaticHostAttributes{
			StaticHostAttributes: &pb.StaticHostAttributes{
				Address: wrapperspb.String(h.GetAddress()),
			},
		},
		AuthorizedActions: testAuthorizedActions[static.Subtype],
		HostSetIds:        []string{hostSet.GetPublicId()},
	}
}

func pluginHostToProto(h host.Host, proj *iam.Scope, hostSet *hostplugin.HostSet, plg *plugin.Plugin, extId string, extName string) *pb.Host {
	return &pb.Host{
		Id:            h.GetPublicId(),
		HostCatalogId: h.GetCatalogId(),
		Plugin: &plugins.PluginInfo{
			Id:          plg.GetPublicId(),
			Name:        plg.GetName(),
			Description: plg.GetDescription(),
		},
		Scope:             &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
		CreatedTime:       h.GetCreateTime().GetTimestamp(),
		UpdatedTime:       h.GetUpdateTime().GetTimestamp(),
		HostSetIds:        []string{hostSet.GetPublicId()},
		Version:           1,
		ExternalId:        extId,
		ExternalName:      extName,
		Type:              hostplugin.Subtype.String(),
		AuthorizedActions: testAuthorizedActions[hostplugin.Subtype],
	}
}

func TestGet_Static(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
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
	pluginRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	s := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, s.GetPublicId(), []*static.Host{h})

	pHost := staticHostToProto(h, proj, s)

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
			req:  &pbs.GetHostRequest{Id: globals.StaticHostPrefix + "_DoesntExis"},
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
			req:  &pbs.GetHostRequest{Id: globals.StaticHostPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := hosts.NewService(ctx, repoFn, pluginRepoFn, 1000)
			require.NoError(err, "Couldn't create a new host service.")

			got, gErr := s.GetHost(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetHost(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
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
			), "GetHost(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestGet_Plugin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	plg := plugin.TestPlugin(t, conn, "test")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&loopback.TestPluginServer{}),
	}

	rw := db.New(conn)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	pluginRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, plgm)
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	hc := hostplugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	h := hostplugin.TestHost(t, conn, hc.GetPublicId(), "test", hostplugin.WithExternalName("test-ext-name"))
	hPrev := hostplugin.TestHost(t, conn, hc.GetPublicId(), "test-prev",
		hostplugin.WithPublicId(fmt.Sprintf("%s_1234567890", globals.PluginHostPreviousPrefix)),
		hostplugin.WithExternalName("test-prev-name"),
	)
	hs := hostplugin.TestSet(t, conn, kms, sche, hc, plgm)
	hostplugin.TestSetMembers(t, conn, hs.GetPublicId(), []*hostplugin.Host{h, hPrev})

	pHost := pluginHostToProto(h, proj, hs, plg, "test", "test-ext-name")

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
			name: "Get an Existing Previous-ID Host",
			req:  &pbs.GetHostRequest{Id: hPrev.GetPublicId()},
			res: func() *pbs.GetHostResponse {
				resp := proto.Clone(pHost).(*pb.Host)
				resp.Id = hPrev.PublicId
				resp.CreatedTime = hPrev.CreateTime.GetTimestamp()
				resp.UpdatedTime = hPrev.UpdateTime.GetTimestamp()
				resp.ExternalId = "test-prev"
				resp.ExternalName = "test-prev-name"
				return &pbs.GetHostResponse{Item: resp}
			}(),
		},
		{
			name: "non existing",
			req:  &pbs.GetHostRequest{Id: globals.PluginHostPrefix + "_DoesntExis"},
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
			req:  &pbs.GetHostRequest{Id: globals.PluginHostPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := hosts.NewService(ctx, repoFn, pluginRepoFn, 1000)
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
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "GetHost(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestList_Static(t *testing.T) {
	ctx := context.Background()
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
	pluginRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	hcs := static.TestCatalogs(t, conn, proj.GetPublicId(), 2)
	hc, hcNoHosts := hcs[0], hcs[1]

	hset := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	var wantHs []*pb.Host
	testHosts := static.TestHosts(t, conn, hc.GetPublicId(), 10)
	static.TestSetMembers(t, conn, hset.GetPublicId(), testHosts)
	for _, h := range testHosts {
		wantHs = append(wantHs, staticHostToProto(h, proj, hset))
	}

	slices.Reverse(wantHs)

	cases := []struct {
		name string
		req  *pbs.ListHostsRequest
		res  *pbs.ListHostsResponse
		err  error
	}{
		{
			name: "List Many Hosts",
			req:  &pbs.ListHostsRequest{HostCatalogId: hc.GetPublicId()},
			res: &pbs.ListHostsResponse{
				Items:        wantHs,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				EstItemCount: 10,
			},
		},
		{
			name: "List Non Existing Hosts",
			req:  &pbs.ListHostsRequest{HostCatalogId: "hcst_doesntexist"},
			err:  handlers.NotFoundError(),
		},
		{
			name: "List No Hosts",
			req:  &pbs.ListHostsRequest{HostCatalogId: hcNoHosts.GetPublicId()},
			res: &pbs.ListHostsResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "Filter to One Host",
			req:  &pbs.ListHostsRequest{HostCatalogId: hc.GetPublicId(), Filter: fmt.Sprintf(`"/item/id"==%q`, wantHs[1].GetId())},
			res: &pbs.ListHostsResponse{
				Items:        wantHs[1:2],
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				EstItemCount: 1,
			},
		},
		{
			name: "Filter to No Hosts",
			req:  &pbs.ListHostsRequest{HostCatalogId: hc.GetPublicId(), Filter: `"/item/id"=="doesnt match"`},
			res: &pbs.ListHostsResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
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
			s, err := hosts.NewService(ctx, repoFn, pluginRepoFn, 1000)
			require.NoError(err, "Couldn't create new host set service.")

			// Test non-anonymous listing
			got, gErr := s.ListHosts(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListHosts(%q) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListHostsResponse{}, "list_token"),
			))

			// Test anonymous listing
			got, gErr = s.ListHosts(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId(), auth.WithUserId(globals.AnonymousUserId)), tc.req)
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
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)
	plg := plugin.TestPlugin(t, conn, "test")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&loopback.TestPluginServer{}),
	}

	rw := db.New(conn)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	pluginRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, plgm)
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	hcs := hostplugin.TestCatalogs(t, conn, proj.GetPublicId(), plg.GetPublicId(), 2)
	hc, hcNoHosts := hcs[0], hcs[1]
	hs := hostplugin.TestSet(t, conn, kms, sche, hc, plgm)

	var wantHs []*pb.Host
	for i := 0; i < 10; i++ {
		extId := fmt.Sprintf("ext-id-%d", i)
		extName := fmt.Sprintf("ext-name-%d", i)
		h := hostplugin.TestHost(t, conn, hc.GetPublicId(), extId, hostplugin.WithExternalName(extName))
		hostplugin.TestSetMembers(t, conn, hs.GetPublicId(), []*hostplugin.Host{h})
		wantHs = append(wantHs, pluginHostToProto(h, proj, hs, plg, extId, extName))
	}

	slices.Reverse(wantHs)

	cases := []struct {
		name string
		req  *pbs.ListHostsRequest
		res  *pbs.ListHostsResponse
		err  error
	}{
		{
			name: "List Many Hosts",
			req:  &pbs.ListHostsRequest{HostCatalogId: hc.GetPublicId()},
			res: &pbs.ListHostsResponse{
				Items:        wantHs,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				EstItemCount: 10,
			},
		},
		{
			name: "List Non Existing Hosts",
			req:  &pbs.ListHostsRequest{HostCatalogId: "hc_doesntexist"},
			err:  handlers.NotFoundError(),
		},
		{
			name: "List No Hosts",
			req:  &pbs.ListHostsRequest{HostCatalogId: hcNoHosts.GetPublicId()},
			res: &pbs.ListHostsResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "Filter to One Host",
			req:  &pbs.ListHostsRequest{HostCatalogId: hc.GetPublicId(), Filter: fmt.Sprintf(`"/item/id"==%q`, wantHs[1].GetId())},
			res: &pbs.ListHostsResponse{
				Items:        wantHs[1:2],
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				EstItemCount: 1,
			},
		},
		{
			name: "Filter to No Hosts",
			req:  &pbs.ListHostsRequest{HostCatalogId: hc.GetPublicId(), Filter: `"/item/id"=="doesnt match"`},
			res: &pbs.ListHostsResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
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
			s, err := hosts.NewService(ctx, repoFn, pluginRepoFn, 1000)
			require.NoError(err, "Couldn't create new host set service.")

			// Test non-anonymous listing
			got, gErr := s.ListHosts(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListHosts(%q) got error %v, wanted %v", tc.req, gErr, tc.err)
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
				protocmp.IgnoreFields(&pbs.ListHostsResponse{}, "list_token"),
			))

			// Test anonymous listing
			got, gErr = s.ListHosts(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId(), auth.WithUserId(globals.AnonymousUserId)), tc.req)
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

func TestListPagination(t *testing.T) {
	// Set database read timeout to avoid duplicates in response
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	sqlDB, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	kms := kms.TestKms(t, conn, wrapper)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	org, proj := iam.TestScopes(t, iamRepo)
	plg := plugin.TestPlugin(t, conn, "test")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&loopback.TestPluginServer{}),
	}

	rw := db.New(conn)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}
	pluginRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, plgm)
	}
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	staticRepo, err := staticRepoFn()
	require.NoError(t, err)
	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
	r := iam.TestRole(t, conn, proj.GetPublicId())
	_ = iam.TestUserRole(t, conn, r.GetPublicId(), at.GetIamUserId())
	_ = iam.TestRoleGrant(t, conn, r.GetPublicId(), "ids=*;type=*;actions=*")
	phc := hostplugin.TestCatalogs(t, conn, proj.GetPublicId(), plg.GetPublicId(), 1)[0]
	phs := hostplugin.TestSet(t, conn, kms, sche, phc, plgm)
	shc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	shs := static.TestSets(t, conn, shc.GetPublicId(), 1)[0]

	var staticPbHosts []*pb.Host
	staticHosts := static.TestHosts(t, conn, shc.GetPublicId(), 10)
	static.TestSetMembers(t, conn, shs.GetPublicId(), staticHosts)
	for _, host := range staticHosts {
		staticPbHosts = append(staticPbHosts, staticHostToProto(host, proj, shs))
	}
	var pluginPbHosts []*pb.Host
	for i := 0; i < 10; i++ {
		extId := fmt.Sprintf("ext-id-%d", i)
		extName := fmt.Sprintf("ext-name-%d", i)
		pluginHost := hostplugin.TestHost(t, conn, phc.GetPublicId(), extId, hostplugin.WithExternalName(extName))
		hostplugin.TestSetMembers(t, conn, phs.GetPublicId(), []*hostplugin.Host{pluginHost})
		pluginPbHosts = append(pluginPbHosts, pluginHostToProto(pluginHost, proj, phs, plg, extId, extName))
	}

	// Since we list by create_time descending, we need to reverse slices
	slices.Reverse(staticPbHosts)
	slices.Reverse(pluginPbHosts)

	// Run analyze to update postgres estimates
	_, err = sqlDB.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	// Test without anon user
	requestInfo := authpb.RequestInfo{
		TokenFormat: uint32(auth.AuthTokenTypeBearer),
		PublicId:    at.GetPublicId(),
		Token:       at.GetToken(),
	}
	requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
	ctx = auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)

	s, err := hosts.NewService(ctx, staticRepoFn, pluginRepoFn, 1000)
	require.NoError(t, err)

	t.Run("static-hosts", func(t *testing.T) {
		// Start paginating, recursively
		req := &pbs.ListHostsRequest{
			HostCatalogId: shc.GetPublicId(),
			Filter:        "",
			ListToken:     "",
			PageSize:      2,
		}
		got, err := s.ListHosts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 2)
		// Compare without comparing the list token
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListHostsResponse{
					Items:        staticPbHosts[0:2],
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListHostsResponse{}, "list_token"),
			),
		)

		// Request second page
		req.ListToken = got.ListToken
		got, err = s.ListHosts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 2)
		// Compare without comparing the list token
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListHostsResponse{
					Items:        staticPbHosts[2:4],
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListHostsResponse{}, "list_token"),
			),
		)

		// Request rest of results
		req.ListToken = got.ListToken
		req.PageSize = 10
		got, err = s.ListHosts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 6)
		// Compare without comparing the list token
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListHostsResponse{
					Items:        staticPbHosts[4:],
					ResponseType: "complete",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListHostsResponse{}, "list_token"),
			),
		)

		// Create another Host
		staticHost := static.TestHosts(t, conn, shc.GetPublicId(), 1)[0]
		static.TestSetMembers(t, conn, shs.GetPublicId(), []*static.Host{staticHost})
		// Add to the front since it's most recently updated
		staticPbHosts = append([]*pb.Host{staticHostToProto(staticHost, proj, shs)}, staticPbHosts...)

		// Delete one of the other Hosts
		_, err = staticRepo.DeleteHost(ctx, proj.GetPublicId(), staticPbHosts[len(staticPbHosts)-1].Id)
		require.NoError(t, err)
		deletedHost := staticPbHosts[len(staticPbHosts)-1]
		staticPbHosts = staticPbHosts[:len(staticPbHosts)-1]

		// Update one of the other Hosts
		staticPbHosts[1].Name = wrapperspb.String("new-name")
		staticPbHosts[1].Version = 2
		h := &static.Host{
			Host: &store.Host{
				PublicId:  staticPbHosts[1].Id,
				CatalogId: staticPbHosts[1].HostCatalogId,
				Name:      staticPbHosts[1].Name.GetValue(),
			},
		}
		newHost, _, err := staticRepo.UpdateHost(ctx, proj.PublicId, h, 1, []string{"name"})
		require.NoError(t, err)
		staticPbHosts[1].UpdatedTime = newHost.GetUpdateTime().GetTimestamp()
		staticPbHosts[1].Version = newHost.GetVersion()
		// Add to the front since it's most recently updated
		staticPbHosts = append(
			[]*pb.Host{staticPbHosts[1]},
			append(
				[]*pb.Host{staticPbHosts[0]},
				staticPbHosts[2:]...,
			)...,
		)
		// Run analyze to update postgres estimates
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// Request updated results
		req.ListToken = got.ListToken
		req.PageSize = 1
		got, err = s.ListHosts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		// Compare without comparing the list token
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListHostsResponse{
					Items:        []*pb.Host{staticPbHosts[0]},
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "updated_time",
					SortDir:      "desc",
					// Should contain the deleted Host
					RemovedIds:   []string{deletedHost.Id},
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListHostsResponse{}, "list_token"),
			),
		)

		// Get next page
		req.ListToken = got.ListToken
		got, err = s.ListHosts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		// Compare without comparing the list token
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListHostsResponse{
					Items:        []*pb.Host{staticPbHosts[1]},
					ResponseType: "complete",
					ListToken:    "",
					SortBy:       "updated_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListHostsResponse{}, "list_token"),
			),
		)

		// Request new page with filter requiring looping
		// to fill the page.
		req.ListToken = ""
		req.PageSize = 1
		req.Filter = fmt.Sprintf(`"/item/id"==%q or "/item/id"==%q`, staticPbHosts[len(staticPbHosts)-2].Id, staticPbHosts[len(staticPbHosts)-1].Id)
		got, err = s.ListHosts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListHostsResponse{
					Items:        []*pb.Host{staticPbHosts[len(staticPbHosts)-2]},
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					// Should be empty again
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListHostsResponse{}, "list_token"),
			),
		)

		// Get the second page
		req.ListToken = got.ListToken
		got, err = s.ListHosts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListHostsResponse{
					Items:        []*pb.Host{staticPbHosts[len(staticPbHosts)-1]},
					ResponseType: "complete",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListHostsResponse{}, "list_token"),
			),
		)

		// Create unauthenticated user
		unauthAt := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
		unauthR := iam.TestRole(t, conn, proj.GetPublicId())
		_ = iam.TestUserRole(t, conn, unauthR.GetPublicId(), unauthAt.GetIamUserId())

		// Make a request with the unauthenticated user,
		// ensure the response contains the pagination parameters.
		requestInfo := authpb.RequestInfo{
			TokenFormat: uint32(auth.AuthTokenTypeBearer),
			PublicId:    unauthAt.GetPublicId(),
			Token:       unauthAt.GetToken(),
		}
		requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
		ctx := auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)

		_, err = s.ListHosts(ctx, &pbs.ListHostsRequest{
			HostCatalogId: shc.GetPublicId(),
		})
		require.Error(t, err)
		assert.ErrorIs(t, handlers.ForbiddenError(), err)
	})

	t.Run("plugin-hosts", func(t *testing.T) {
		// Start paginating, recursively
		req := &pbs.ListHostsRequest{
			HostCatalogId: phc.GetPublicId(),
			Filter:        "",
			ListToken:     "",
			PageSize:      2,
		}
		got, err := s.ListHosts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 2)
		// Compare without comparing the list token
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListHostsResponse{
					Items:        pluginPbHosts[0:2],
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListHostsResponse{}, "list_token"),
			),
		)

		// Request second page
		req.ListToken = got.ListToken
		got, err = s.ListHosts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 2)
		// Compare without comparing the list token
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListHostsResponse{
					Items:        pluginPbHosts[2:4],
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListHostsResponse{}, "list_token"),
			),
		)

		// Request rest of results
		req.ListToken = got.ListToken
		req.PageSize = 10
		got, err = s.ListHosts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 6)
		// Compare without comparing the list token
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListHostsResponse{
					Items:        pluginPbHosts[4:],
					ResponseType: "complete",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListHostsResponse{}, "list_token"),
			),
		)

		// Create another Host
		extId := "ext-id-10"
		extName := "ext-name-10"
		pluginHost := hostplugin.TestHost(t, conn, phc.GetPublicId(), extId, hostplugin.WithExternalName(extName))
		hostplugin.TestSetMembers(t, conn, phs.GetPublicId(), []*hostplugin.Host{pluginHost})
		// Add to the front since it's most recently updated
		pluginPbHosts = append([]*pb.Host{pluginHostToProto(pluginHost, proj, phs, plg, extId, extName)}, pluginPbHosts...)

		// Note: it's non-trivial to delete and update plugin hosts, so we skip that part here.

		// Run analyze to update postgres estimates
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// Request updated results
		req.ListToken = got.ListToken
		got, err = s.ListHosts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		// Compare without comparing the list token
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListHostsResponse{
					Items:        []*pb.Host{pluginPbHosts[0]},
					ResponseType: "complete",
					ListToken:    "",
					SortBy:       "updated_time",
					SortDir:      "desc",
					EstItemCount: 11,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListHostsResponse{}, "list_token"),
			),
		)

		// Request new page with filter requiring looping
		// to fill the page.
		req.ListToken = ""
		req.PageSize = 1
		req.Filter = fmt.Sprintf(`"/item/id"==%q or "/item/id"==%q`, pluginPbHosts[len(pluginPbHosts)-2].Id, pluginPbHosts[len(pluginPbHosts)-1].Id)
		got, err = s.ListHosts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListHostsResponse{
					Items:        []*pb.Host{pluginPbHosts[len(pluginPbHosts)-2]},
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 11,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListHostsResponse{}, "list_token"),
			),
		)
		req.ListToken = got.ListToken
		// Get the second page
		got, err = s.ListHosts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListHostsResponse{
					Items:        []*pb.Host{pluginPbHosts[len(pluginPbHosts)-1]},
					ResponseType: "complete",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 11,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListHostsResponse{}, "list_token"),
			),
		)
		// Create unauthenticated user
		unauthAt := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
		unauthR := iam.TestRole(t, conn, proj.GetPublicId())
		_ = iam.TestUserRole(t, conn, unauthR.GetPublicId(), unauthAt.GetIamUserId())

		// Make a request with the unauthenticated user,
		// ensure the response contains the pagination parameters.
		requestInfo := authpb.RequestInfo{
			TokenFormat: uint32(auth.AuthTokenTypeBearer),
			PublicId:    unauthAt.GetPublicId(),
			Token:       unauthAt.GetToken(),
		}
		requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
		ctx := auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)

		_, err = s.ListHosts(ctx, &pbs.ListHostsRequest{
			HostCatalogId: phc.GetPublicId(),
		})
		require.Error(t, err)
		assert.ErrorIs(t, handlers.ForbiddenError(), err)
	})
}

func TestDelete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
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
	pluginRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]

	plg := plugin.TestPlugin(t, conn, "test")
	pluginHc := hostplugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	pluginH := hostplugin.TestHost(t, conn, pluginHc.GetPublicId(), "test")

	s, err := hosts.NewService(ctx, repoFn, pluginRepoFn, 1000)
	require.NoError(t, err, "Couldn't create a new host set service.")

	cases := []struct {
		name      string
		projectId string
		req       *pbs.DeleteHostRequest
		res       *pbs.DeleteHostResponse
		err       error
	}{
		{
			name:      "Delete an Existing Host",
			projectId: proj.GetPublicId(),
			req: &pbs.DeleteHostRequest{
				Id: h.GetPublicId(),
			},
		},
		{
			name:      "Delete a plugin Host",
			projectId: proj.GetPublicId(),
			req: &pbs.DeleteHostRequest{
				Id: pluginH.GetPublicId(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:      "Delete bad id Host",
			projectId: proj.GetPublicId(),
			req: &pbs.DeleteHostRequest{
				Id: globals.StaticHostPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:      "Bad Host Id formatting",
			projectId: proj.GetPublicId(),
			req: &pbs.DeleteHostRequest{
				Id: globals.StaticHostPrefix + "_bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteHost(auth.DisabledAuthTestContext(iamRepoFn, tc.projectId), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteHost(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(
				tc.res,
				got,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "DeleteHost(%q) got response %q, wanted %q", tc.req, got, tc.res)
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

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	_, proj := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	pluginRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(testCtx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(testCtx, rw, rw, kms)
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]

	s, err := hosts.NewService(testCtx, repoFn, pluginRepoFn, 1000)
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
	ctx := context.Background()
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
	pluginRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]

	plg := plugin.TestPlugin(t, conn, "test")
	pluginHc := hostplugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())

	defaultHcCreated := hc.GetCreateTime().GetTimestamp().AsTime()

	cases := []struct {
		name            string
		req             *pbs.CreateHostRequest
		res             *pbs.CreateHostResponse
		err             error
		wantErrContains string
	}{
		{
			name: "Create a valid Host",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "name"},
				Description:   &wrappers.StringValue{Value: "desc"},
				Type:          "static",
				Attrs: &pb.Host_StaticHostAttributes{
					StaticHostAttributes: &pb.StaticHostAttributes{
						Address: wrapperspb.String("123.456.789"),
					},
				},
			}},
			res: &pbs.CreateHostResponse{
				Uri: fmt.Sprintf("hosts/%s_", globals.StaticHostPrefix),
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:          &wrappers.StringValue{Value: "name"},
					Description:   &wrappers.StringValue{Value: "desc"},
					Type:          "static",
					Attrs: &pb.Host_StaticHostAttributes{
						StaticHostAttributes: &pb.StaticHostAttributes{
							Address: wrapperspb.String("123.456.789"),
						},
					},
					AuthorizedActions: testAuthorizedActions[static.Subtype],
				},
			},
		},
		{
			name: "Create a valid Host with IPv6 address",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "name-ipv6"},
				Description:   &wrappers.StringValue{Value: "desc-ipv6"},
				Type:          "static",
				Attrs: &pb.Host_StaticHostAttributes{
					StaticHostAttributes: &pb.StaticHostAttributes{
						Address: wrapperspb.String("2001:BEEF:0000:0000:0000:0000:0000:0001"),
					},
				},
			}},
			res: &pbs.CreateHostResponse{
				Uri: fmt.Sprintf("hosts/%s_", globals.StaticHostPrefix),
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:          &wrappers.StringValue{Value: "name-ipv6"},
					Description:   &wrappers.StringValue{Value: "desc-ipv6"},
					Type:          "static",
					Attrs: &pb.Host_StaticHostAttributes{
						StaticHostAttributes: &pb.StaticHostAttributes{
							Address: wrapperspb.String("2001:beef::1"),
						},
					},
					AuthorizedActions: testAuthorizedActions[static.Subtype],
				},
			},
		},
		{
			name: "no-attributes",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "name"},
				Description:   &wrappers.StringValue{Value: "desc"},
				Type:          "static",
			}},
			err:             handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: `Details: {{name: "attributes", desc: "This is a required field."}}`,
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
				Attrs: &pb.Host_StaticHostAttributes{
					StaticHostAttributes: &pb.StaticHostAttributes{
						Address: wrapperspb.String(""),
					},
				},
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
				Attrs: &pb.Host_StaticHostAttributes{
					StaticHostAttributes: &pb.StaticHostAttributes{
						Address: nil,
					},
				},
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
				Attrs: &pb.Host_StaticHostAttributes{
					StaticHostAttributes: &pb.StaticHostAttributes{
						Address: wrapperspb.String("123.456.789"),
					},
				},
			}},
			res: &pbs.CreateHostResponse{
				Uri: fmt.Sprintf("hosts/%s_", globals.StaticHostPrefix),
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:          &wrappers.StringValue{Value: "no type name"},
					Description:   &wrappers.StringValue{Value: "no type desc"},
					Type:          "static",
					Attrs: &pb.Host_StaticHostAttributes{
						StaticHostAttributes: &pb.StaticHostAttributes{
							Address: wrapperspb.String("123.456.789"),
						},
					},
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
			name: "Can't specify port",
			req: &pbs.CreateHostRequest{Item: &pb.Host{
				HostCatalogId: hc.GetPublicId(),
				Name:          &wrappers.StringValue{Value: "port name"},
				Description:   &wrappers.StringValue{Value: "port desc"},
				Attrs: &pb.Host_StaticHostAttributes{
					StaticHostAttributes: &pb.StaticHostAttributes{
						Address: wrapperspb.String("123.456.789:12345"),
					},
				},
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
			s, err := hosts.NewService(ctx, repoFn, pluginRepoFn, 1000)
			require.NoError(err, "Failed to create a new host set service.")

			got, gErr := s.CreateHost(auth.DisabledAuthTestContext(iamRepoFn, proj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.Nil(got)
				assert.True(errors.Is(gErr, tc.err), "CreateHost(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				if tc.wantErrContains != "" {
					assert.Contains(gErr.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(gErr)
			require.NotNil(got)

			if got != nil {
				assert.Contains(got.GetUri(), tc.res.GetUri())
				assert.True(strings.HasPrefix(got.GetItem().GetId(), globals.StaticHostPrefix))
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
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "CreateHost(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestUpdate_Static(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
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
	pluginRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	repo, err := repoFn()
	require.NoError(t, err, "Couldn't create new static repo.")

	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	s := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

	h, err := static.NewHost(ctx, hc.GetPublicId(), static.WithName("default"), static.WithDescription("default"), static.WithAddress("defaultaddress"))
	require.NoError(t, err)
	h, err = repo.CreateHost(ctx, proj.GetPublicId(), h)
	require.NoError(t, err)
	static.TestSetMembers(t, conn, s.GetPublicId(), []*static.Host{h})

	var version uint32 = 1

	resetHost := func() {
		version++
		_, _, err = repo.UpdateHost(ctx, proj.GetPublicId(), h, version, []string{"Name", "Description", "Address"})
		require.NoError(t, err, "Failed to reset host.")
		version++
	}

	hCreated := h.GetCreateTime().GetTimestamp().AsTime()

	tested, err := hosts.NewService(ctx, repoFn, pluginRepoFn, 1000)
	require.NoError(t, err, "Failed to create a new host set service.")

	cases := []struct {
		name            string
		req             *pbs.UpdateHostRequest
		res             *pbs.UpdateHostResponse
		err             error
		wantErrContains string
	}{
		{
			name: "Update an Existing Host",
			req: &pbs.UpdateHostRequest{
				Id: h.GetPublicId(),
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
					Attrs: &pb.Host_StaticHostAttributes{
						StaticHostAttributes: &pb.StaticHostAttributes{
							Address: wrapperspb.String("defaultaddress"),
						},
					},
					AuthorizedActions: testAuthorizedActions[static.Subtype],
					HostSetIds:        []string{s.GetPublicId()},
				},
			},
		},
		{
			name: "Update address",
			req: &pbs.UpdateHostRequest{
				Id: h.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.AttributesAddressField},
				},
				Item: &pb.Host{
					Attrs: &pb.Host_StaticHostAttributes{
						StaticHostAttributes: &pb.StaticHostAttributes{
							Address: wrapperspb.String("2001:BEEF:0000:0000:0000:0000:0000:0001"),
						},
					},
					Type: "static",
				},
			},
			res: &pbs.UpdateHostResponse{
				Item: &pb.Host{
					HostCatalogId: hc.GetPublicId(),
					Id:            h.GetPublicId(),
					Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Name:          &wrappers.StringValue{Value: "default"},
					Description:   &wrappers.StringValue{Value: "default"},
					CreatedTime:   h.GetCreateTime().GetTimestamp(),
					Type:          "static",
					Attrs: &pb.Host_StaticHostAttributes{
						StaticHostAttributes: &pb.StaticHostAttributes{
							Address: wrapperspb.String("2001:beef::1"),
						},
					},
					AuthorizedActions: testAuthorizedActions[static.Subtype],
					HostSetIds:        []string{s.GetPublicId()},
				},
			},
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateHostRequest{
				Id: h.GetPublicId(),
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
					Attrs: &pb.Host_StaticHostAttributes{
						StaticHostAttributes: &pb.StaticHostAttributes{
							Address: wrapperspb.String("defaultaddress"),
						},
					},
					AuthorizedActions: testAuthorizedActions[static.Subtype],
					HostSetIds:        []string{s.GetPublicId()},
				},
			},
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateHostRequest{
				Id: h.GetPublicId(),
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			err:             handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: "UpdateMask not provided",
		},
		{
			name: "Changing Type",
			req: &pbs.UpdateHostRequest{
				Id: h.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,type"},
				},
				Item: &pb.Host{
					Name: &wrappers.StringValue{Value: "updated name"},
					Type: "ec2",
				},
			},
			err:             handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: "Cannot modify the resource type",
		},
		{
			name: "Empty Path",
			req: &pbs.UpdateHostRequest{
				Id:         h.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			err:             handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: "No valid fields provided",
		},
		{
			name: "Only non-existent paths in Mask",
			req: &pbs.UpdateHostRequest{
				Id:         h.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistent_field"}},
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			err:             handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: "No valid fields provided",
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateHostRequest{
				Id: h.GetPublicId(),
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
					Attrs: &pb.Host_StaticHostAttributes{
						StaticHostAttributes: &pb.StaticHostAttributes{
							Address: wrapperspb.String("defaultaddress"),
						},
					},
					AuthorizedActions: testAuthorizedActions[static.Subtype],
					HostSetIds:        []string{s.GetPublicId()},
				},
			},
		},
		{
			name: "Unset Description",
			req: &pbs.UpdateHostRequest{
				Id: h.GetPublicId(),
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
					Attrs: &pb.Host_StaticHostAttributes{
						StaticHostAttributes: &pb.StaticHostAttributes{
							Address: wrapperspb.String("defaultaddress"),
						},
					},
					AuthorizedActions: testAuthorizedActions[static.Subtype],
					HostSetIds:        []string{s.GetPublicId()},
				},
			},
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateHostRequest{
				Id: h.GetPublicId(),
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
					Attrs: &pb.Host_StaticHostAttributes{
						StaticHostAttributes: &pb.StaticHostAttributes{
							Address: wrapperspb.String("defaultaddress"),
						},
					},
					AuthorizedActions: testAuthorizedActions[static.Subtype],
					HostSetIds:        []string{s.GetPublicId()},
				},
			},
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateHostRequest{
				Id: h.GetPublicId(),
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
					Attrs: &pb.Host_StaticHostAttributes{
						StaticHostAttributes: &pb.StaticHostAttributes{
							Address: wrapperspb.String("defaultaddress"),
						},
					},
					AuthorizedActions: testAuthorizedActions[static.Subtype],
					HostSetIds:        []string{s.GetPublicId()},
				},
			},
		},
		{
			name: "Update a Non Existing Host",
			req: &pbs.UpdateHostRequest{
				Id: globals.StaticHostPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "new"},
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: org.GetPublicId()},
					Description: &wrappers.StringValue{Value: "desc"},
				},
			},
			err:             handlers.ApiErrorWithCode(codes.NotFound),
			wantErrContains: "Resource not found",
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateHostRequest{
				Id: h.GetPublicId(),
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
			err:             handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: "This is a read only field",
		},
		{
			name: "Cant unset address",
			req: &pbs.UpdateHostRequest{
				Id: h.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.AttributesAddressField},
				},
				Item: &pb.Host{
					Attrs: &pb.Host_StaticHostAttributes{
						StaticHostAttributes: &pb.StaticHostAttributes{
							Address: nil,
						},
					},
				},
			},
			err:             handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: "Address length must be",
		},
		{
			name: "Cant set address to empty string",
			req: &pbs.UpdateHostRequest{
				Id: h.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.AttributesAddressField},
				},
				Item: &pb.Host{
					Attrs: &pb.Host_StaticHostAttributes{
						StaticHostAttributes: &pb.StaticHostAttributes{
							Address: wrapperspb.String(""),
						},
					},
				},
			},
			err:             handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: "Address length must be",
		},
		{
			name: "Cant specify port in address",
			req: &pbs.UpdateHostRequest{
				Id: h.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.AttributesAddressField},
				},
				Item: &pb.Host{
					Name:        &wrappers.StringValue{Value: "port name"},
					Description: &wrappers.StringValue{Value: "port desc"},
					Attrs: &pb.Host_StaticHostAttributes{
						StaticHostAttributes: &pb.StaticHostAttributes{
							Address: wrapperspb.String("123.456.789:12345"),
						},
					},
				},
			},
			err:             handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: "does not support a port",
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateHostRequest{
				Id: h.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.Host{
					CreatedTime: timestamppb.Now(),
				},
			},
			err:             handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: "This is a read only field",
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateHostRequest{
				Id: h.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.Host{
					UpdatedTime: timestamppb.Now(),
				},
			},
			err:             handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: "This is a read only field",
		},
		{
			name: "Valid mask, cant specify type",
			req: &pbs.UpdateHostRequest{
				Id: h.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Host{
					Type: "Unknown",
				},
			},
			err:             handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: "Cannot modify the resource type",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			tc.req.Item.Version = version

			req := tc.req

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
				assert.Nil(got)
				assert.True(errors.Is(gErr, tc.err), "UpdateHost(%+v) got error %v, wanted %v", req, gErr, tc.err)
				if tc.wantErrContains != "" {
					assert.Contains(gErr.Error(), tc.wantErrContains)
				}
				return
			}

			defer resetHost()
			require.NoError(gErr)
			require.NotNil(got)

			require.NotNilf(tc.res, "Expected UpdateHost response to be nil, but was %v", got)
			gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
			// Verify it is a set updated after it was created
			assert.True(gotUpdateTime.After(hCreated), "Updated set should have been updated after its creation. Was updated %v, which is after %v", gotUpdateTime, hCreated)

			// Clear all values which are hard to compare against.
			got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil
			tc.res.Item.Version = version + 1
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "UpdateHost(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestUpdate_Plugin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
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
	pluginRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kms, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}

	plg := plugin.TestPlugin(t, conn, "test")
	hc := hostplugin.TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())
	h := hostplugin.TestHost(t, conn, hc.GetPublicId(), "test")

	tested, err := hosts.NewService(ctx, repoFn, pluginRepoFn, 1000)
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
