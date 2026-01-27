// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package scopes_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/scopes"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	wrappingKms "github.com/hashicorp/go-kms-wrapping/extras/kms/v2"
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

var (
	testAuthorizedOrgActions    = []string{"no-op", "read", "update", "delete", "attach-storage-policy", "detach-storage-policy"}
	testAuthorizedPrjActions    = []string{"no-op", "read", "update", "delete"}
	testAuthorizedGlobalActions = []string{"no-op", "read", "update", "attach-storage-policy", "detach-storage-policy"}
)

func createDefaultScopesRepoAndKms(t *testing.T) (*iam.Scope, *iam.Scope, func() (*iam.Repository, error), *kms.Kms) {
	t.Helper()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	kms := kms.TestKms(t, conn, wrap)

	oRes, pRes := iam.TestScopes(t, iamRepo)

	oRes.Name = "defaultOrg"
	oRes.Description = "defaultOrg"
	repo, err := repoFn()
	require.NoError(t, err)
	oRes, _, err = repo.UpdateScope(context.Background(), oRes, 1, []string{"Name", "Description"})
	require.NoError(t, err)

	pRes.Name = "defaultProj"
	pRes.Description = "defaultProj"
	repo, err = repoFn()
	require.NoError(t, err)
	pRes, _, err = repo.UpdateScope(context.Background(), pRes, 1, []string{"Name", "Description"})
	require.NoError(t, err)
	return oRes, pRes, repoFn, kms
}

var globalAuthorizedCollectionActions = map[string]*structpb.ListValue{
	"aliases": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"app-tokens": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"auth-methods": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"auth-tokens": {
		Values: []*structpb.Value{
			structpb.NewStringValue("list"),
		},
	},
	"groups": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"policies": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"roles": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"scopes": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("destroy-key-version"),
			structpb.NewStringValue("list"),
			structpb.NewStringValue("list-key-version-destruction-jobs"),
			structpb.NewStringValue("list-keys"),
			structpb.NewStringValue("rotate-keys"),
		},
	},
	"session-recordings": {
		Values: []*structpb.Value{
			structpb.NewStringValue("list"),
		},
	},
	"storage-buckets": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"users": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"workers": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create:controller-led"),
			structpb.NewStringValue("create:worker-led"),
			structpb.NewStringValue("list"),
			structpb.NewStringValue("read-certificate-authority"),
			structpb.NewStringValue("reinitialize-certificate-authority"),
		},
	},
}

var orgAuthorizedCollectionActions = map[string]*structpb.ListValue{
	"app-tokens": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"auth-methods": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"auth-tokens": {
		Values: []*structpb.Value{
			structpb.NewStringValue("list"),
		},
	},
	"groups": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"policies": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"roles": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"scopes": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("destroy-key-version"),
			structpb.NewStringValue("list"),
			structpb.NewStringValue("list-key-version-destruction-jobs"),
			structpb.NewStringValue("list-keys"),
			structpb.NewStringValue("rotate-keys"),
		},
	},
	"session-recordings": {
		Values: []*structpb.Value{
			structpb.NewStringValue("list"),
		},
	},
	"storage-buckets": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"users": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
}

var projectAuthorizedCollectionActions = map[string]*structpb.ListValue{
	"credential-stores": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"groups": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"host-catalogs": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"roles": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"sessions": {
		Values: []*structpb.Value{
			structpb.NewStringValue("list"),
		},
	},
	"scopes": {
		Values: []*structpb.Value{
			structpb.NewStringValue("destroy-key-version"),
			structpb.NewStringValue("list-key-version-destruction-jobs"),
			structpb.NewStringValue("list-keys"),
			structpb.NewStringValue("rotate-keys"),
		},
	},
	"targets": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
}

func TestGet(t *testing.T) {
	org, proj, repoFn, kms := createDefaultScopesRepoAndKms(t)
	toMerge := &pbs.GetScopeRequest{
		Id: proj.GetPublicId(),
	}

	oScope := &pb.Scope{
		Id:                          org.GetPublicId(),
		ScopeId:                     org.GetParentId(),
		Scope:                       &pb.ScopeInfo{Id: "global", Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
		Name:                        &wrapperspb.StringValue{Value: org.GetName()},
		Description:                 &wrapperspb.StringValue{Value: org.GetDescription()},
		CreatedTime:                 org.CreateTime.GetTimestamp(),
		UpdatedTime:                 org.UpdateTime.GetTimestamp(),
		Version:                     2,
		Type:                        scope.Org.String(),
		AuthorizedActions:           testAuthorizedOrgActions,
		AuthorizedCollectionActions: orgAuthorizedCollectionActions,
	}

	pScope := &pb.Scope{
		Id:                          proj.GetPublicId(),
		ScopeId:                     proj.GetParentId(),
		Scope:                       &pb.ScopeInfo{Id: oScope.Id, Type: scope.Org.String(), ParentScopeId: scope.Global.String(), Name: "defaultOrg", Description: "defaultOrg"},
		Name:                        &wrapperspb.StringValue{Value: proj.GetName()},
		Description:                 &wrapperspb.StringValue{Value: proj.GetDescription()},
		CreatedTime:                 proj.CreateTime.GetTimestamp(),
		UpdatedTime:                 proj.UpdateTime.GetTimestamp(),
		Version:                     2,
		Type:                        scope.Project.String(),
		AuthorizedActions:           testAuthorizedPrjActions,
		AuthorizedCollectionActions: projectAuthorizedCollectionActions,
	}

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.GetScopeRequest
		res     *pbs.GetScopeResponse
		err     error
	}{
		{
			name:    "Get an existing org",
			scopeId: "global",
			req:     &pbs.GetScopeRequest{Id: org.GetPublicId()},
			res:     &pbs.GetScopeResponse{Item: oScope},
		},
		{
			name:    "Get a non existing org",
			scopeId: "global",
			req:     &pbs.GetScopeRequest{Id: "o_DoesntExis"},
			res:     nil,
			err:     handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Get an existing project",
			scopeId: org.GetPublicId(),
			req:     &pbs.GetScopeRequest{Id: proj.GetPublicId()},
			res:     &pbs.GetScopeResponse{Item: pScope},
		},
		{
			name:    "Get a non existing project",
			scopeId: org.GetPublicId(),
			req:     &pbs.GetScopeRequest{Id: "p_DoesntExist"},
			res:     nil,
			err:     handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Wrong id prefix",
			scopeId: org.GetPublicId(),
			req:     &pbs.GetScopeRequest{Id: "j_1234567890"},
			res:     nil,
			err:     handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "space in id",
			scopeId: org.GetPublicId(),
			req:     &pbs.GetScopeRequest{Id: "p_1 23456789"},
			res:     nil,
			err:     handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			req := proto.Clone(toMerge).(*pbs.GetScopeRequest)
			proto.Merge(req, tc.req)

			s, err := scopes.NewServiceFn(context.Background(), repoFn, kms, 1000)
			require.NoError(err, "Couldn't create new project service.")

			got, gErr := s.GetScope(auth.DisabledAuthTestContext(repoFn, tc.scopeId), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetScope(%+v) got error\n%v, wanted\n%v", req, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(
				tc.res,
				got,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				cmpopts.SortSlices(func(a, b protocmp.Message) bool {
					return a.String() < b.String()
				}),
			), "GetScope(%q) got response\n%q, wanted\n%q", req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repo, err := repoFn()
	require.NoError(t, err)
	kms := kms.TestKms(t, conn, wrap)

	oNoProjects, p1 := iam.TestScopes(t, repo)
	_, err = repo.DeleteScope(context.Background(), p1.GetPublicId())
	require.NoError(t, err)
	oWithProjects, p2 := iam.TestScopes(t, repo)
	_, err = repo.DeleteScope(context.Background(), p2.GetPublicId())
	require.NoError(t, err)

	outputFields := new(perms.OutputFields).SelfOrDefaults(globals.AnyAuthenticatedUserId)
	var initialOrgs []*pb.Scope
	globalScope := &pb.ScopeInfo{Id: "global", Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"}
	oNoProjectsProto, err := scopes.ToProto(context.Background(), oNoProjects, handlers.WithOutputFields(outputFields))
	require.NoError(t, err)
	oNoProjectsProto.Scope = globalScope
	oNoProjectsProto.AuthorizedActions = testAuthorizedOrgActions
	oNoProjectsProto.AuthorizedCollectionActions = orgAuthorizedCollectionActions
	oWithProjectsProto, err := scopes.ToProto(context.Background(), oWithProjects, handlers.WithOutputFields(outputFields))
	require.NoError(t, err)
	oWithProjectsProto.Scope = globalScope
	oWithProjectsProto.AuthorizedActions = testAuthorizedOrgActions
	oWithProjectsProto.AuthorizedCollectionActions = orgAuthorizedCollectionActions
	initialOrgs = append(initialOrgs, oNoProjectsProto, oWithProjectsProto)

	// Reverse slice since we order by create time (newest first)
	slices.Reverse(initialOrgs)

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.ListScopesRequest
		res     *pbs.ListScopesResponse
		err     error
	}{
		{
			name:    "List initial orgs",
			scopeId: scope.Global.String(),
			req:     &pbs.ListScopesRequest{ScopeId: "global"},
			res: &pbs.ListScopesResponse{
				Items:        initialOrgs,
				EstItemCount: 2,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name:    "List No Projects",
			scopeId: oNoProjects.GetPublicId(),
			req:     &pbs.ListScopesRequest{ScopeId: oNoProjects.GetPublicId()},
			res: &pbs.ListScopesResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name:    "Cant List Project Scopes",
			scopeId: p1.GetPublicId(),
			req:     &pbs.ListScopesRequest{ScopeId: p1.GetPublicId()},
			err:     handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Filter To Single Org",
			scopeId: scope.Global.String(),
			req:     &pbs.ListScopesRequest{ScopeId: "global", Filter: fmt.Sprintf(`"/item/id"==%q`, initialOrgs[1].GetId())},
			res: &pbs.ListScopesResponse{
				Items:        initialOrgs[1:2],
				EstItemCount: 1,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := scopes.NewServiceFn(context.Background(), repoFn, kms, 1000)
			require.NoError(err, "Couldn't create new role service.")

			// Test with non-anonymous listing first
			got, gErr := s.ListScopes(auth.DisabledAuthTestContext(repoFn, tc.scopeId), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListScopes(%+v) got error\n%v, wanted\n%v", tc.req, gErr, tc.err)
				return
			}
			assert.Empty(
				cmp.Diff(
					got,
					tc.res,
					cmpopts.SortSlices(func(a, b string) bool {
						return a < b
					}),
					cmpopts.SortSlices(func(a, b protocmp.Message) bool {
						return a.String() < b.String()
					}),
					protocmp.Transform(),
					protocmp.IgnoreFields(&pbs.ListScopesResponse{}, "list_token"),
				),
			)

			// Now test with anonymous listing
			got, gErr = s.ListScopes(auth.DisabledAuthTestContext(repoFn, tc.scopeId, auth.WithUserId(globals.AnonymousUserId)), tc.req)
			require.NoError(gErr)
			assert.Len(got.Items, len(tc.res.Items))
			for _, item := range got.GetItems() {
				assert.Nil(item.CreatedTime)
				assert.Nil(item.UpdatedTime)
				assert.Empty(item.Version)
			}
		})
	}

	var wantOrgs []*pb.Scope
	for i := 0; i < 10; i++ {
		newO, err := iam.NewOrg(ctx)
		require.NoError(t, err)
		o, err := repo.CreateScope(ctx, newO, "")
		require.NoError(t, err)
		wantOrgs = append(wantOrgs, &pb.Scope{
			Id:                          o.GetPublicId(),
			ScopeId:                     globalScope.GetId(),
			Scope:                       globalScope,
			CreatedTime:                 o.GetCreateTime().GetTimestamp(),
			UpdatedTime:                 o.GetUpdateTime().GetTimestamp(),
			Version:                     1,
			Type:                        scope.Org.String(),
			AuthorizedActions:           testAuthorizedOrgActions,
			AuthorizedCollectionActions: orgAuthorizedCollectionActions,
		})
	}

	// Reverse slice since we order by create time (newest first)
	slices.Reverse(wantOrgs)

	wantOrgs = append(wantOrgs, initialOrgs...)

	var wantProjects []*pb.Scope
	for i := 0; i < 10; i++ {
		newP, err := iam.NewProject(ctx, oWithProjects.GetPublicId())
		require.NoError(t, err)
		p, err := repo.CreateScope(ctx, newP, "")
		require.NoError(t, err)
		wantProjects = append(wantProjects, &pb.Scope{
			Id:                          p.GetPublicId(),
			ScopeId:                     oWithProjects.GetPublicId(),
			Scope:                       &pb.ScopeInfo{Id: oWithProjects.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			CreatedTime:                 p.GetCreateTime().GetTimestamp(),
			UpdatedTime:                 p.GetUpdateTime().GetTimestamp(),
			Version:                     1,
			Type:                        scope.Project.String(),
			AuthorizedActions:           testAuthorizedPrjActions,
			AuthorizedCollectionActions: projectAuthorizedCollectionActions,
		})
	}

	// Reverse slice since we order by create time (newest first)
	slices.Reverse(wantProjects)

	totalScopes := append(wantOrgs, wantProjects...)

	cases = []struct {
		name    string
		scopeId string
		req     *pbs.ListScopesRequest
		res     *pbs.ListScopesResponse
		err     error
	}{
		{
			name:    "List Many Orgs",
			scopeId: scope.Global.String(),
			req:     &pbs.ListScopesRequest{ScopeId: "global"},
			res: &pbs.ListScopesResponse{
				Items:        wantOrgs,
				EstItemCount: 12,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name:    "List Many Projects",
			scopeId: oWithProjects.GetPublicId(),
			req:     &pbs.ListScopesRequest{ScopeId: oWithProjects.GetPublicId()},
			res: &pbs.ListScopesResponse{
				Items:        wantProjects,
				EstItemCount: 10,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name:    "List Global Recursively",
			scopeId: scope.Global.String(),
			req:     &pbs.ListScopesRequest{ScopeId: scope.Global.String(), Recursive: true},
			res: &pbs.ListScopesResponse{
				Items:        totalScopes,
				EstItemCount: 22,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name:    "Filter To Orgs",
			scopeId: scope.Global.String(),
			req:     &pbs.ListScopesRequest{ScopeId: scope.Global.String(), Recursive: true, Filter: fmt.Sprintf(`"/item/scope/type"==%q`, scope.Global.String())},
			res: &pbs.ListScopesResponse{
				Items:        wantOrgs,
				EstItemCount: 12,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name:    "Filter To Projects",
			scopeId: scope.Global.String(),
			req:     &pbs.ListScopesRequest{ScopeId: scope.Global.String(), Recursive: true, Filter: fmt.Sprintf(`"/item/scope/type"==%q`, scope.Org.String())},
			res: &pbs.ListScopesResponse{
				Items:        wantProjects,
				EstItemCount: 10,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListScopesRequest{ScopeId: scope.Global.String(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := scopes.NewServiceFn(context.Background(), repoFn, kms, 1000)
			require.NoError(err, "Couldn't create new scope service.")

			// Test with non-anonymous listing first
			got, gErr := s.ListScopes(auth.DisabledAuthTestContext(repoFn, tc.scopeId), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListScopes(%+v) got error\n%v, wanted\n%v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			assert.Empty(
				cmp.Diff(
					got,
					tc.res,
					cmpopts.SortSlices(func(a, b string) bool {
						return a < b
					}),
					cmpopts.SortSlices(func(a, b protocmp.Message) bool {
						return a.String() < b.String()
					}),
					protocmp.Transform(),
					protocmp.IgnoreFields(&pbs.ListScopesResponse{}, "list_token"),
				),
			)

			// Now test with anonymous listing
			got, gErr = s.ListScopes(auth.DisabledAuthTestContext(repoFn, tc.scopeId, auth.WithUserId(globals.AnonymousUserId)), tc.req)
			require.NoError(gErr)
			assert.Len(got.Items, len(tc.res.Items))
			for _, item := range got.GetItems() {
				assert.Nil(item.CreatedTime)
				assert.Nil(item.UpdatedTime)
				assert.Empty(item.Version)
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
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)

	repoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	repo, err := repoFn()
	require.NoError(t, err)

	iamRepoFn := func() (*iam.Repository, error) {
		return repo, nil
	}
	iamRepo, err := iamRepoFn()
	require.NoError(t, err)

	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}
	tokenRepo, err := tokenRepoFn()
	require.NoError(t, err)

	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}

	oWithProjects, p2 := iam.TestScopes(t, repo, iam.WithSkipDefaultRoleCreation(true))
	_, err = repo.DeleteScope(context.Background(), p2.GetPublicId())
	require.NoError(t, err)

	paginationAuthorizedCollectionActions := map[string]*structpb.ListValue{
		"sessions": {
			Values: []*structpb.Value{
				structpb.NewStringValue("list"),
			},
		},
		"targets": {
			Values: []*structpb.Value{
				structpb.NewStringValue("list"),
			},
		},
	}

	var wantProjects []*pb.Scope
	for i := 0; i < 10; i++ {
		newP, err := iam.NewProject(ctx, oWithProjects.GetPublicId())
		require.NoError(t, err)
		p, err := repo.CreateScope(ctx, newP, "")
		require.NoError(t, err)
		wantProjects = append(wantProjects, &pb.Scope{
			Id:                          p.GetPublicId(),
			ScopeId:                     oWithProjects.GetPublicId(),
			Scope:                       &pb.ScopeInfo{Id: oWithProjects.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			CreatedTime:                 p.GetCreateTime().GetTimestamp(),
			UpdatedTime:                 p.GetUpdateTime().GetTimestamp(),
			Version:                     1,
			Type:                        scope.Project.String(),
			AuthorizedActions:           testAuthorizedPrjActions,
			AuthorizedCollectionActions: paginationAuthorizedCollectionActions,
		})
	}

	// Reverse slice since we order by create time (newest first)
	slices.Reverse(wantProjects)

	// Run analyze to update scope estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	authMethod := ldap.TestAuthMethod(t, conn, wrapper, oWithProjects.PublicId, []string{"ldaps://no-managed-groups"})
	acct := ldap.TestAccount(t, conn, authMethod, "test-login-last")
	u := iam.TestUser(t, iamRepo, oWithProjects.GetPublicId(), iam.WithAccountIds(acct.PublicId))

	// privProjRole := iam.TestRole(t, conn, pwt.GetPublicId())
	// iam.TestRoleGrant(t, conn, privProjRole.GetPublicId(), "ids=*;type=*;actions=*")
	// iam.TestUserRole(t, conn, privProjRole.GetPublicId(), u.GetPublicId())
	privOrgRole := iam.TestRole(t, conn, oWithProjects.GetPublicId())
	iam.TestRoleGrant(t, conn, privOrgRole.GetPublicId(), "ids=*;type=*;actions=*")
	iam.TestUserRole(t, conn, privOrgRole.GetPublicId(), u.GetPublicId())

	at, _ := tokenRepo.CreateAuthToken(ctx, u, acct.GetPublicId())

	requestInfo := authpb.RequestInfo{
		TokenFormat: uint32(auth.AuthTokenTypeBearer),
		PublicId:    at.GetPublicId(),
		Token:       at.GetToken(),
	}
	requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
	ctx = auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)

	req := &pbs.ListScopesRequest{
		ScopeId:   oWithProjects.GetPublicId(),
		Filter:    "",
		ListToken: "",
		PageSize:  2,
	}

	s, err := scopes.NewServiceFn(ctx, repoFn, kms, 1000)
	require.NoError(t, err)

	got, err := s.ListScopes(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 2)

	// all comparisons will be done without refresh token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListScopesResponse{
				Items:        wantProjects[0:2],
				ResponseType: "delta",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 12,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			cmpopts.SortSlices(func(a, b protocmp.Message) bool {
				return a.String() < b.String()
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListScopesResponse{}, "list_token"),
		),
	)

	// second page
	req.ListToken = got.ListToken
	got, err = s.ListScopes(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 2)

	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListScopesResponse{
				Items:        wantProjects[2:4],
				ResponseType: "delta",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 12,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			cmpopts.SortSlices(func(a, b protocmp.Message) bool {
				return a.String() < b.String()
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListScopesResponse{}, "list_token"),
		),
	)

	// remainder of results
	req.ListToken = got.ListToken
	req.PageSize = 6
	got, err = s.ListScopes(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 6)

	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListScopesResponse{
				Items:        wantProjects[4:],
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 12,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			cmpopts.SortSlices(func(a, b protocmp.Message) bool {
				return a.String() < b.String()
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListScopesResponse{}, "list_token"),
		),
	)

	// create another scope
	newP, err := iam.NewProject(ctx, oWithProjects.GetPublicId())
	require.NoError(t, err)
	p, err := repo.CreateScope(ctx, newP, "")
	require.NoError(t, err)
	newScope := &pb.Scope{
		Id:                          p.GetPublicId(),
		ScopeId:                     oWithProjects.GetPublicId(),
		Scope:                       &pb.ScopeInfo{Id: oWithProjects.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
		CreatedTime:                 p.GetCreateTime().GetTimestamp(),
		UpdatedTime:                 p.GetUpdateTime().GetTimestamp(),
		Version:                     1,
		Type:                        scope.Project.String(),
		AuthorizedActions:           testAuthorizedPrjActions,
		AuthorizedCollectionActions: paginationAuthorizedCollectionActions,
	}
	// Add to the front of the slice since it's the most recently updated
	wantProjects = append([]*pb.Scope{newScope}, wantProjects...)

	// delete different scope
	_, err = repo.DeleteScope(ctx, wantProjects[len(wantProjects)-1].Id)
	wantProjects = wantProjects[:len(wantProjects)-1]
	require.NoError(t, err)

	// Run analyze to update postgres estimates
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	// request updated results
	// since both creating and deleting scopes will affect the grantsHash
	// we expect this to error
	req.ListToken = got.ListToken
	_, err = s.ListScopes(ctx, req)
	require.Error(t, err)
	require.True(t, errors.Match(errors.T(errors.InvalidListToken), err))

	// clear the refresh token
	req.ListToken = ""
	req.PageSize = 2
	got, err = s.ListScopes(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 2)
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListScopesResponse{
				Items:        wantProjects[0:2],
				ResponseType: "delta",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 12,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			cmpopts.SortSlices(func(a, b protocmp.Message) bool {
				return a.String() < b.String()
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListScopesResponse{}, "list_token"),
		),
	)

	// Request new page with filter requiring looping
	// to fill the page.
	req.ListToken = ""
	req.PageSize = 1
	req.Filter = fmt.Sprintf(`"/item/id"==%q or "/item/id"==%q`, wantProjects[len(wantProjects)-2].Id, wantProjects[len(wantProjects)-1].Id)
	got, err = s.ListScopes(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 1)
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListScopesResponse{
				Items:        []*pb.Scope{wantProjects[len(wantProjects)-2]},
				ResponseType: "delta",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				// Should be empty again
				RemovedIds:   nil,
				EstItemCount: 12,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			cmpopts.SortSlices(func(a, b protocmp.Message) bool {
				return a.String() < b.String()
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListScopesResponse{}, "list_token"),
		),
	)
	req.ListToken = got.ListToken
	// Get the second page
	got, err = s.ListScopes(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 1)
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListScopesResponse{
				Items:        []*pb.Scope{wantProjects[len(wantProjects)-1]},
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 12,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			cmpopts.SortSlices(func(a, b protocmp.Message) bool {
				return a.String() < b.String()
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListScopesResponse{}, "list_token"),
		),
	)

	// Create unauthenticated user
	unauthAt := authtoken.TestAuthToken(t, conn, kms, oWithProjects.GetPublicId())
	unauthR := iam.TestRole(t, conn, p.GetPublicId())
	_ = iam.TestUserRole(t, conn, unauthR.GetPublicId(), unauthAt.GetIamUserId())

	// Make a request with the unauthenticated user,
	// ensure the response contains the pagination parameters.
	requestInfo = authpb.RequestInfo{
		TokenFormat: uint32(auth.AuthTokenTypeBearer),
		PublicId:    unauthAt.GetPublicId(),
		Token:       unauthAt.GetToken(),
	}
	requestContext = context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
	ctx = auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)

	_, err = s.ListScopes(ctx, &pbs.ListScopesRequest{
		ScopeId:   "global",
		Recursive: true,
	})
	require.Error(t, err)
	assert.ErrorIs(t, handlers.ForbiddenError(), err)
}

func TestDelete(t *testing.T) {
	org, proj, repoFn, kms := createDefaultScopesRepoAndKms(t)

	s, err := scopes.NewServiceFn(context.Background(), repoFn, kms, 1000)
	require.NoError(t, err, "Error when getting new project service.")

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.DeleteScopeRequest
		res     *pbs.DeleteScopeResponse
		err     error
	}{
		{
			name:    "Delete an Existing Project",
			scopeId: org.GetPublicId(),
			req: &pbs.DeleteScopeRequest{
				Id: proj.GetPublicId(),
			},
		},
		{
			name:    "Delete bad project id Project",
			scopeId: org.GetPublicId(),
			req: &pbs.DeleteScopeRequest{
				Id: "p_DoesntExist",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Bad Project Id formatting",
			scopeId: org.GetPublicId(),
			req: &pbs.DeleteScopeRequest{
				Id: "bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Delete an Existing Org",
			scopeId: scope.Global.String(),
			req: &pbs.DeleteScopeRequest{
				Id: org.GetPublicId(),
			},
		},
		{
			name:    "Delete bad org id Org",
			scopeId: scope.Global.String(),
			req: &pbs.DeleteScopeRequest{
				Id: "p_DoesntExist",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Bad Org Id formatting",
			scopeId: scope.Global.String(),
			req: &pbs.DeleteScopeRequest{
				Id: "bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteScope(auth.DisabledAuthTestContext(repoFn, tc.scopeId), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteScope(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.EqualValuesf(tc.res, got, "DeleteScope(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	org, proj, repoFn, kms := createDefaultScopesRepoAndKms(t)

	s, err := scopes.NewServiceFn(context.Background(), repoFn, kms, 1000)
	require.NoError(err, "Error when getting new scopes service")
	ctx := auth.DisabledAuthTestContext(repoFn, org.GetPublicId())
	req := &pbs.DeleteScopeRequest{
		Id: proj.GetPublicId(),
	}
	_, gErr := s.DeleteScope(ctx, req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteScope(ctx, req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected not found for the second delete.")

	ctx = auth.DisabledAuthTestContext(repoFn, scope.Global.String())
	req = &pbs.DeleteScopeRequest{
		Id: org.GetPublicId(),
	}
	_, gErr = s.DeleteScope(ctx, req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteScope(ctx, req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected not found for the second delete.")
}

func TestCreate(t *testing.T) {
	ctx := context.Background()
	defaultOrg, defaultProj, repoFn, kms := createDefaultScopesRepoAndKms(t)
	defaultProjCreated := defaultProj.GetCreateTime().GetTimestamp().AsTime()
	toMerge := &pbs.CreateScopeRequest{}

	repo, err := repoFn()
	require.NoError(t, err)
	globalUser, err := iam.NewUser(ctx, scope.Global.String())
	require.NoError(t, err)
	globalUser, err = repo.CreateUser(ctx, globalUser)
	require.NoError(t, err)
	orgUser, err := iam.NewUser(ctx, defaultOrg.GetPublicId())
	require.NoError(t, err)
	orgUser, err = repo.CreateUser(ctx, orgUser)
	require.NoError(t, err)

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.CreateScopeRequest
		res     *pbs.CreateScopeResponse
		err     error
	}{
		{
			name:    "Create a valid Project",
			scopeId: defaultOrg.GetPublicId(),
			req: &pbs.CreateScopeRequest{
				Item: &pb.Scope{
					ScopeId:     defaultOrg.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.CreateScopeResponse{
				Uri: "scopes/p_",
				Item: &pb.Scope{
					ScopeId:                     defaultOrg.GetPublicId(),
					Scope:                       &pb.ScopeInfo{Id: defaultOrg.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String(), Name: "defaultOrg", Description: "defaultOrg"},
					Name:                        &wrapperspb.StringValue{Value: "name"},
					Description:                 &wrapperspb.StringValue{Value: "desc"},
					Version:                     1,
					Type:                        scope.Project.String(),
					AuthorizedActions:           testAuthorizedPrjActions,
					AuthorizedCollectionActions: projectAuthorizedCollectionActions,
				},
			},
		},
		{
			name:    "Create a valid Org",
			scopeId: scope.Global.String(),
			req: &pbs.CreateScopeRequest{
				Item: &pb.Scope{
					ScopeId:     scope.Global.String(),
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.CreateScopeResponse{
				Uri: "scopes/o_",
				Item: &pb.Scope{
					ScopeId:                     scope.Global.String(),
					Scope:                       &pb.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
					Name:                        &wrapperspb.StringValue{Value: "name"},
					Description:                 &wrapperspb.StringValue{Value: "desc"},
					Version:                     1,
					Type:                        scope.Org.String(),
					AuthorizedActions:           testAuthorizedOrgActions,
					AuthorizedCollectionActions: orgAuthorizedCollectionActions,
				},
			},
		},
		{
			name:    "Create a valid Project with type specified",
			scopeId: defaultOrg.GetPublicId(),
			req: &pbs.CreateScopeRequest{
				Item: &pb.Scope{
					ScopeId:     defaultOrg.GetPublicId(),
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        scope.Project.String(),
				},
			},
			res: &pbs.CreateScopeResponse{
				Uri: "scopes/p_",
				Item: &pb.Scope{
					ScopeId:                     defaultOrg.GetPublicId(),
					Scope:                       &pb.ScopeInfo{Id: defaultOrg.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String(), Name: "defaultOrg", Description: "defaultOrg"},
					Description:                 &wrapperspb.StringValue{Value: "desc"},
					Version:                     1,
					Type:                        scope.Project.String(),
					AuthorizedActions:           testAuthorizedPrjActions,
					AuthorizedCollectionActions: projectAuthorizedCollectionActions,
				},
			},
		},
		{
			name:    "Create a valid Org with type specified",
			scopeId: scope.Global.String(),
			req: &pbs.CreateScopeRequest{
				Item: &pb.Scope{
					ScopeId:     scope.Global.String(),
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        scope.Org.String(),
				},
			},
			res: &pbs.CreateScopeResponse{
				Uri: "scopes/o_",
				Item: &pb.Scope{
					ScopeId:                     scope.Global.String(),
					Scope:                       &pb.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
					Description:                 &wrapperspb.StringValue{Value: "desc"},
					Version:                     1,
					Type:                        scope.Org.String(),
					AuthorizedActions:           testAuthorizedOrgActions,
					AuthorizedCollectionActions: orgAuthorizedCollectionActions,
				},
			},
		},
		{
			name:    "Create a valid org with leading and trailing whitespace on name and description",
			scopeId: scope.Global.String(),
			req: &pbs.CreateScopeRequest{
				Item: &pb.Scope{
					ScopeId:     scope.Global.String(),
					Description: &wrapperspb.StringValue{Value: "  test description with whitespace      "},
					Type:        scope.Org.String(),
					Name:        &wrapperspb.StringValue{Value: "  test org name with whitespace     "},
				},
			},
			res: &pbs.CreateScopeResponse{
				Uri: "scopes/o_",
				Item: &pb.Scope{
					ScopeId:                     scope.Global.String(),
					Scope:                       &pb.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
					Description:                 &wrapperspb.StringValue{Value: "test description with whitespace"}, // assert the whitespace is trimmed
					Name:                        &wrapperspb.StringValue{Value: "test org name with whitespace"},    // assert the whitespace is trimmed
					Version:                     1,
					Type:                        scope.Org.String(),
					AuthorizedActions:           testAuthorizedOrgActions,
					AuthorizedCollectionActions: orgAuthorizedCollectionActions,
				},
			},
		},
		{
			name:    "Create a global type scope",
			scopeId: scope.Global.String(),
			req: &pbs.CreateScopeRequest{
				Item: &pb.Scope{
					ScopeId:     scope.Global.String(),
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        scope.Global.String(),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Create with a custom version number",
			scopeId: scope.Global.String(),
			req: &pbs.CreateScopeRequest{
				Item: &pb.Scope{
					ScopeId:     scope.Global.String(),
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        scope.Org.String(),
					Version:     5,
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Project with bad type specified",
			scopeId: defaultOrg.GetPublicId(),
			req: &pbs.CreateScopeRequest{
				Item: &pb.Scope{
					ScopeId:     defaultOrg.GetPublicId(),
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        scope.Org.String(),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Org with bad type specified",
			scopeId: scope.Global.String(),
			req: &pbs.CreateScopeRequest{
				Item: &pb.Scope{
					ScopeId:     scope.Global.String(),
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        scope.Project.String(),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Can't specify Id",
			scopeId: defaultOrg.GetPublicId(),
			req: &pbs.CreateScopeRequest{Item: &pb.Scope{
				Id: "not allowed to be set",
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Can't specify Created Time",
			scopeId: defaultOrg.GetPublicId(),
			req: &pbs.CreateScopeRequest{Item: &pb.Scope{
				CreatedTime: timestamppb.Now(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Can't specify Update Time",
			scopeId: defaultOrg.GetPublicId(),
			req: &pbs.CreateScopeRequest{Item: &pb.Scope{
				UpdatedTime: timestamppb.Now(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		for _, withUserId := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-userid-%t", tc.name, withUserId), func(t *testing.T) {
				assert, require := assert.New(t), require.New(t)
				var name string
				if tc.req != nil && tc.req.GetItem() != nil && tc.req.GetItem().GetName() != nil {
					name = tc.req.GetItem().GetName().GetValue()
					localName := name
					defer func() {
						tc.res.GetItem().GetName().Value = localName
					}()
				}
				req := proto.Clone(toMerge).(*pbs.CreateScopeRequest)
				proto.Merge(req, tc.req)

				s, err := scopes.NewServiceFn(context.Background(), repoFn, kms, 1000)
				require.NoError(err, "Error when getting new project service.")

				if name != "" {
					// Test cases can specify names with leading and trailing
					// whitespace to test for Boundary's whitespace removal.
					// Since we're adding to the name before we send the request
					// off, we need to make sure we keep it as we found it.

					// Find where leading whitespace ends, add withUserId there.
					idx := 0
					for i, r := range name {
						if !unicode.IsSpace(r) {
							idx = i
							break
						}
					}

					if idx == 0 {
						name = fmt.Sprintf("%t-%s", withUserId, name)
					} else {
						name = fmt.Sprintf("%s%t-%s", name[:idx], withUserId, name[idx:])
					}

					req.GetItem().GetName().Value = name
				}
				var userId string
				if withUserId {
					if tc.scopeId == scope.Global.String() {
						userId = globalUser.GetPublicId()
					} else {
						userId = orgUser.GetPublicId()
					}
					assert.NotEmpty(userId)
				}
				got, gErr := s.CreateScope(auth.DisabledAuthTestContext(repoFn, tc.scopeId, auth.WithUserId(userId)), req)
				if tc.err != nil {
					require.Error(gErr)
					assert.True(errors.Is(gErr, tc.err), "CreateScope(%+v) got error %v, wanted %v", req, gErr, tc.err)
				}
				if got != nil {
					assert.Contains(got.GetUri(), tc.res.Uri)
					switch tc.scopeId {
					case "global":
						assert.True(strings.HasPrefix(got.GetItem().GetId(), "o_"))
					default:
						assert.True(strings.HasPrefix(got.GetItem().GetId(), "p_"))
					}
					gotCreateTime := got.GetItem().GetCreatedTime().AsTime()
					gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
					// Verify it is a project created after the test setup's default project
					assert.True(gotCreateTime.After(defaultProjCreated), "New scope should have been created after default project. Was created %v, which is after %v", gotCreateTime, defaultProjCreated)
					assert.True(gotUpdateTime.After(defaultProjCreated), "New scope should have been updated after default project. Was updated %v, which is after %v", gotUpdateTime, defaultProjCreated)

					if withUserId {
						repo, err := repoFn()
						require.NoError(err)
						noopFilter := func(ctx context.Context, item *iam.Role) (bool, error) {
							return true, nil
						}
						roles, err := iam.ListRoles(ctx, []byte("test"), globals.DefaultMaxPageSize, noopFilter, repo, []string{got.GetItem().GetId()})
						require.NoError(err)
						switch tc.scopeId {
						case defaultOrg.PublicId:
							require.Len(roles.Items, 2)
						case "global":
							require.Len(roles.Items, 2)
						}
						for _, role := range roles.Items {
							switch role.GetName() {
							case "Administration":
								assert.Equal(fmt.Sprintf("Role created for administration of scope %s by user %s at its creation time", got.GetItem().GetId(), userId), role.GetDescription())
							case "Login and Default Grants":
								assert.Equal(fmt.Sprintf("Role created for login capability, account self-management, and other default grants for users of scope %s at its creation time", got.GetItem().GetId()), role.GetDescription())
							case "Default Grants":
								assert.Equal(fmt.Sprintf("Role created to provide default grants to users of scope %s at its creation time", got.GetItem().GetId()), role.GetDescription())
							default:
								t.Fatal("unexpected role name", role.GetName())
							}
						}
					}

					// Clear all values which are hard to compare against.
					assert.Equal(strings.TrimSpace(name), got.GetItem().GetName().GetValue())
					got.Item.Name = tc.res.GetItem().GetName()
					got.Uri, tc.res.Uri = "", ""
					got.Item.Id, tc.res.Item.Id = "", ""
					got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
				}
				assert.Empty(cmp.Diff(
					tc.res,
					got,
					protocmp.Transform(),
					cmpopts.SortSlices(func(a, b string) bool {
						return a < b
					}),
					cmpopts.SortSlices(func(a, b protocmp.Message) bool {
						return a.String() < b.String()
					}),
				), "CreateScope(%q) got response %q, wanted %q", req, got, tc.res)
			})
		}
	}
}

func TestUpdate(t *testing.T) {
	org, proj, repoFn, kms := createDefaultScopesRepoAndKms(t)
	tested, err := scopes.NewServiceFn(context.Background(), repoFn, kms, 1000)
	require.NoError(t, err, "Error when getting new project service.")

	iamRepo, err := repoFn()
	require.NoError(t, err)
	global, err := iamRepo.LookupScope(context.Background(), "global")
	require.NoError(t, err)

	var orgVersion uint32 = 2
	var projVersion uint32 = 2
	globalVersion := global.Version

	resetOrg := func() {
		orgVersion++
		repo, err := repoFn()
		require.NoError(t, err, "Couldn't get a new repo")
		org, _, err = repo.UpdateScope(context.Background(), org, orgVersion, []string{"Name", "Description"})
		require.NoError(t, err, "Failed to reset the org")
		orgVersion++
	}

	resetProject := func() {
		projVersion++
		repo, err := repoFn()
		require.NoError(t, err, "Couldn't get a new repo")
		proj, _, err = repo.UpdateScope(context.Background(), proj, projVersion, []string{"Name", "Description"})
		require.NoError(t, err, "Failed to reset the project")
		projVersion++
	}

	resetGlobal := func() {
		repo, err := repoFn()
		require.NoError(t, err, "Couldn't get a new repo")
		globalScope := iam.AllocScope()
		globalScope.PublicId = "global"
		global, _, err = repo.UpdateScope(context.Background(), &globalScope, globalVersion, []string{"Name", "Description"})
		require.NoError(t, err, "Failed to reset the global scope")
		globalVersion = global.Version
	}

	projCreated := proj.GetCreateTime().GetTimestamp().AsTime()
	projToMerge := &pbs.UpdateScopeRequest{
		Id: proj.GetPublicId(),
	}

	orgToMerge := &pbs.UpdateScopeRequest{
		Id: org.GetPublicId(),
	}

	globalToMerge := &pbs.UpdateScopeRequest{
		Id: "global",
	}

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.UpdateScopeRequest
		res     *pbs.UpdateScopeResponse
		err     error
	}{
		{
			name:    "Update an Existing Project",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.Scope{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        scope.Project.String(),
				},
			},
			res: &pbs.UpdateScopeResponse{
				Item: &pb.Scope{
					Id:                          proj.GetPublicId(),
					ScopeId:                     org.GetPublicId(),
					Scope:                       &pb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String(), Name: "defaultOrg", Description: "defaultOrg"},
					Name:                        &wrapperspb.StringValue{Value: "new"},
					Description:                 &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:                 proj.GetCreateTime().GetTimestamp(),
					Type:                        scope.Project.String(),
					AuthorizedActions:           testAuthorizedPrjActions,
					AuthorizedCollectionActions: projectAuthorizedCollectionActions,
				},
			},
		},
		{
			name:    "Update an Existing Org",
			scopeId: scope.Global.String(),
			req: &pbs.UpdateScopeRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.Scope{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        scope.Org.String(),
				},
			},
			res: &pbs.UpdateScopeResponse{
				Item: &pb.Scope{
					Id:                          org.GetPublicId(),
					ScopeId:                     scope.Global.String(),
					Scope:                       &pb.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
					Name:                        &wrapperspb.StringValue{Value: "new"},
					Description:                 &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:                 org.GetCreateTime().GetTimestamp(),
					Type:                        scope.Org.String(),
					AuthorizedActions:           testAuthorizedOrgActions,
					AuthorizedCollectionActions: orgAuthorizedCollectionActions,
				},
			},
		},
		{
			name:    "Update org name and description with whitespace",
			scopeId: scope.Global.String(),
			req: &pbs.UpdateScopeRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.Scope{
					Name:        &wrapperspb.StringValue{Value: "  new name     "},
					Description: &wrapperspb.StringValue{Value: "         new desc    "},
					Type:        scope.Org.String(),
				},
			},
			res: &pbs.UpdateScopeResponse{
				Item: &pb.Scope{
					Id:                          org.GetPublicId(),
					ScopeId:                     scope.Global.String(),
					Scope:                       &pb.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
					Name:                        &wrapperspb.StringValue{Value: "new name"},
					Description:                 &wrapperspb.StringValue{Value: "new desc"},
					CreatedTime:                 org.GetCreateTime().GetTimestamp(),
					Type:                        scope.Org.String(),
					AuthorizedActions:           testAuthorizedOrgActions,
					AuthorizedCollectionActions: orgAuthorizedCollectionActions,
				},
			},
		},
		{
			name:    "Update global",
			scopeId: scope.Global.String(),
			req: &pbs.UpdateScopeRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.Scope{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        scope.Global.String(),
				},
			},
			res: &pbs.UpdateScopeResponse{
				Item: &pb.Scope{
					Id:                          scope.Global.String(),
					Scope:                       &pb.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
					Name:                        &wrapperspb.StringValue{Value: "new"},
					Description:                 &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:                 global.GetCreateTime().GetTimestamp(),
					Type:                        scope.Global.String(),
					AuthorizedActions:           testAuthorizedGlobalActions,
					AuthorizedCollectionActions: globalAuthorizedCollectionActions,
				},
			},
		},
		{
			name:    "Multiple Paths in single string",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.Scope{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateScopeResponse{
				Item: &pb.Scope{
					Id:                          proj.GetPublicId(),
					ScopeId:                     org.GetPublicId(),
					Scope:                       &pb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String(), Name: "defaultOrg", Description: "defaultOrg"},
					Name:                        &wrapperspb.StringValue{Value: "new"},
					Description:                 &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:                 proj.GetCreateTime().GetTimestamp(),
					Type:                        scope.Project.String(),
					AuthorizedActions:           testAuthorizedPrjActions,
					AuthorizedCollectionActions: projectAuthorizedCollectionActions,
				},
			},
		},
		{
			name:    "No Update Mask",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				Item: &pb.Scope{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Cant modify type",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "type"},
				},
				Item: &pb.Scope{
					Name: &wrapperspb.StringValue{Value: "updated name"},
					Type: scope.Org.String(),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "No Paths in Mask",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Scope{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Invalidly formatted scope id - org scope",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				Id:         "o_!@£$*",
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Scope{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Invalidly formatted scope id - proj scope",
			scopeId: proj.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				Id:         "p_!@£$*",
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Scope{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Invalidly formatted scope id - unknown scope",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				Id:         "bla_123",
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Scope{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Unknown scope type - org scope",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				Id:         org.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Scope{
					Type:        "test",
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Unknown scope type - proj scope",
			scopeId: proj.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				Id:         proj.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Scope{
					Type:        "test",
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Unknown primary auth method id",
			scopeId: proj.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				Id:         proj.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Scope{
					Name:                &wrapperspb.StringValue{Value: "updated name"},
					Description:         &wrapperspb.StringValue{Value: "updated desc"},
					PrimaryAuthMethodId: &wrapperspb.StringValue{Value: "test_123"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Update org name and description with whitespace only",
			scopeId: scope.Global.String(),
			req: &pbs.UpdateScopeRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.Scope{
					Name:        &wrapperspb.StringValue{Value: "     "},
					Description: &wrapperspb.StringValue{Value: "     "},
					Type:        scope.Org.String(),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Update org name and description with non-printable characters",
			scopeId: scope.Global.String(),
			req: &pbs.UpdateScopeRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.Scope{
					Name:        &wrapperspb.StringValue{Value: "    na\u200Bme   "},
					Description: &wrapperspb.StringValue{Value: "   desc\u200Bription "},
					Type:        scope.Org.String(),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Only non-existent paths in Mask",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistent_field"}},
				Item: &pb.Scope{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Unset Name",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Scope{
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateScopeResponse{
				Item: &pb.Scope{
					Id:                          proj.GetPublicId(),
					ScopeId:                     org.GetPublicId(),
					Scope:                       &pb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String(), Name: "defaultOrg", Description: "defaultOrg"},
					Description:                 &wrapperspb.StringValue{Value: "defaultProj"},
					CreatedTime:                 proj.GetCreateTime().GetTimestamp(),
					Type:                        scope.Project.String(),
					AuthorizedActions:           testAuthorizedPrjActions,
					AuthorizedCollectionActions: projectAuthorizedCollectionActions,
				},
			},
		},
		{
			name:    "Unset Description",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Scope{
					Name: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateScopeResponse{
				Item: &pb.Scope{
					Id:                          proj.GetPublicId(),
					ScopeId:                     org.GetPublicId(),
					Scope:                       &pb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String(), Name: "defaultOrg", Description: "defaultOrg"},
					Name:                        &wrappers.StringValue{Value: "defaultProj"},
					CreatedTime:                 proj.GetCreateTime().GetTimestamp(),
					Type:                        scope.Project.String(),
					AuthorizedActions:           testAuthorizedPrjActions,
					AuthorizedCollectionActions: projectAuthorizedCollectionActions,
				},
			},
		},
		{
			name:    "Update Only Name",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Scope{
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateScopeResponse{
				Item: &pb.Scope{
					Id:                          proj.GetPublicId(),
					ScopeId:                     org.GetPublicId(),
					Scope:                       &pb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String(), Name: "defaultOrg", Description: "defaultOrg"},
					Name:                        &wrapperspb.StringValue{Value: "updated"},
					Description:                 &wrapperspb.StringValue{Value: "defaultProj"},
					CreatedTime:                 proj.GetCreateTime().GetTimestamp(),
					Type:                        scope.Project.String(),
					AuthorizedActions:           testAuthorizedPrjActions,
					AuthorizedCollectionActions: projectAuthorizedCollectionActions,
				},
			},
		},
		{
			name:    "Update Only Description",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Scope{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
				},
			},
			res: &pbs.UpdateScopeResponse{
				Item: &pb.Scope{
					Id:                          proj.GetPublicId(),
					ScopeId:                     org.GetPublicId(),
					Scope:                       &pb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String(), Name: "defaultOrg", Description: "defaultOrg"},
					Name:                        &wrapperspb.StringValue{Value: "defaultProj"},
					Description:                 &wrapperspb.StringValue{Value: "notignored"},
					CreatedTime:                 proj.GetCreateTime().GetTimestamp(),
					Type:                        scope.Project.String(),
					AuthorizedActions:           testAuthorizedPrjActions,
					AuthorizedCollectionActions: projectAuthorizedCollectionActions,
				},
			},
		},
		{
			name:    "Update a Non Existing Project",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				Id: "p_DoesntExist",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Scope{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Cant change Id",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				Id: proj.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.Scope{
					Id:          "p_somethinge",
					Scope:       &pb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String(), Name: "defaultOrg", Description: "defaultOrg"},
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "new desc"},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Cant specify Created Time",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.Scope{
					CreatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Cant specify Updated Time",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.Scope{
					UpdatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ver := orgVersion
			if tc.req.Id == proj.PublicId {
				ver = projVersion
			}
			tc.req.Item.Version = ver

			assert, require := assert.New(t), require.New(t)
			var req *pbs.UpdateScopeRequest
			switch {
			case tc.scopeId == scope.Global.String() && tc.req.Item.GetType() == scope.Global.String():
				tc.req.Item.Version = globalVersion
				ver = globalVersion
				req = proto.Clone(globalToMerge).(*pbs.UpdateScopeRequest)
				if tc.err == nil {
					defer resetGlobal()
				}
			case tc.scopeId == scope.Global.String():
				req = proto.Clone(orgToMerge).(*pbs.UpdateScopeRequest)
				if tc.err == nil {
					defer resetOrg()
				}
			default:
				ver = projVersion
				tc.req.Item.Version = ver
				req = proto.Clone(projToMerge).(*pbs.UpdateScopeRequest)
				if tc.err == nil {
					defer resetProject()
				}
			}
			proto.Merge(req, tc.req)

			got, gErr := tested.UpdateScope(auth.DisabledAuthTestContext(repoFn, tc.scopeId), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateScope(%+v) got error\n%v, wanted\n%v", req, gErr, tc.err)
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateScope response to be nil, but was %v", got)
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
				// Verify it is a project updated after it was created
				assert.True(gotUpdateTime.After(projCreated), "Updated project should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, projCreated)

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil

				assert.Equal(ver+1, got.GetItem().GetVersion())
				tc.res.Item.Version = ver + 1
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
			), "UpdateScope(%q) got response\n%q, wanted\n%q", req, got, tc.res)
		})
	}
}

func TestListKeys(t *testing.T) {
	tc := controller.NewTestController(t, nil)

	aToken := tc.Token()
	uToken := tc.UnprivilegedToken()

	iamRepoFn := func() (*iam.Repository, error) {
		return tc.IamRepo(), nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return tc.ServersRepo(), nil
	}
	authTokenRepoFn := func() (*authtoken.Repository, error) {
		return tc.AuthTokenRepo(), nil
	}

	privCtx := auth.NewVerifierContext(
		context.Background(),
		iamRepoFn,
		authTokenRepoFn,
		serversRepoFn,
		tc.Kms(),
		&authpb.RequestInfo{
			PublicId:       aToken.Id,
			EncryptedToken: strings.Split(aToken.Token, "_")[2],
			TokenFormat:    uint32(auth.AuthTokenTypeBearer),
		})

	unprivCtx := auth.NewVerifierContext(
		context.Background(),
		iamRepoFn,
		authTokenRepoFn,
		serversRepoFn,
		tc.Kms(),
		&authpb.RequestInfo{
			PublicId:       uToken.Id,
			EncryptedToken: strings.Split(uToken.Token, "_")[2],
			TokenFormat:    uint32(auth.AuthTokenTypeBearer),
		})

	org, proj := iam.TestScopes(t, tc.IamRepo())

	org.Name = "defaultOrg"
	org.Description = "defaultOrg"
	org, _, err := tc.IamRepo().UpdateScope(context.Background(), org, 1, []string{"Name", "Description"})
	require.NoError(t, err)

	// Add new role for listing keys in org
	listKeysRole := iam.TestRole(t, tc.DbConn(), org.PublicId)
	_, err = tc.IamRepo().AddRoleGrants(context.Background(), listKeysRole.PublicId, 1, []string{"ids=*;type=*;actions=list-keys"})
	require.NoError(t, err)
	_, err = tc.IamRepo().AddPrincipalRoles(context.Background(), listKeysRole.PublicId, 2, []string{aToken.UserId})
	require.NoError(t, err)

	proj.Name = "defaultProj"
	proj.Description = "defaultProj"
	proj, _, err = tc.IamRepo().UpdateScope(context.Background(), proj, 1, []string{"Name", "Description"})
	require.NoError(t, err)

	// Add new role for listing keys in project
	listKeysRole = iam.TestRole(t, tc.DbConn(), proj.PublicId)
	_, err = tc.IamRepo().AddRoleGrants(context.Background(), listKeysRole.PublicId, 1, []string{"ids=*;type=*;actions=list-keys"})
	require.NoError(t, err)
	_, err = tc.IamRepo().AddPrincipalRoles(context.Background(), listKeysRole.PublicId, 2, []string{aToken.UserId})
	require.NoError(t, err)

	cases := []struct {
		name    string
		req     *pbs.ListKeysRequest
		res     *pbs.ListKeysResponse
		authCtx context.Context
		err     error
	}{
		{
			name: "List keys in the global scope",
			req:  &pbs.ListKeysRequest{Id: "global"},
			res: &pbs.ListKeysResponse{
				Items: []*pb.Key{
					{
						Scope: &pb.ScopeInfo{
							Id:          "global",
							Type:        "global",
							Name:        "global",
							Description: "Global Scope",
						},
						Purpose: "tokens",
						Type:    "dek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
					{
						Scope: &pb.ScopeInfo{
							Id:          "global",
							Type:        "global",
							Name:        "global",
							Description: "Global Scope",
						},
						Purpose: "oplog",
						Type:    "dek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
					{
						Scope: &pb.ScopeInfo{
							Id:          "global",
							Type:        "global",
							Name:        "global",
							Description: "Global Scope",
						},
						Purpose: "database",
						Type:    "dek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
					{
						Scope: &pb.ScopeInfo{
							Id:          "global",
							Type:        "global",
							Name:        "global",
							Description: "Global Scope",
						},
						Purpose: "audit",
						Type:    "dek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
					{
						Scope: &pb.ScopeInfo{
							Id:          "global",
							Type:        "global",
							Name:        "global",
							Description: "Global Scope",
						},
						Purpose: "oidc",
						Type:    "dek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
					{
						Scope: &pb.ScopeInfo{
							Id:          "global",
							Type:        "global",
							Name:        "global",
							Description: "Global Scope",
						},
						Purpose: "sessions",
						Type:    "dek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
					{
						Scope: &pb.ScopeInfo{
							Id:          "global",
							Type:        "global",
							Name:        "global",
							Description: "Global Scope",
						},
						Purpose: "rootKey",
						Type:    "kek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
				},
			},
			authCtx: privCtx,
		},
		{
			name: "List keys in an existing org",
			req:  &pbs.ListKeysRequest{Id: org.GetPublicId()},
			res: &pbs.ListKeysResponse{
				Items: []*pb.Key{
					{
						Scope: &pb.ScopeInfo{
							Id:            org.PublicId,
							ParentScopeId: "global",
							Type:          "org",
							Name:          org.Name,
							Description:   org.Description,
						},
						Purpose: "tokens",
						Type:    "dek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
					{
						Scope: &pb.ScopeInfo{
							Id:            org.PublicId,
							ParentScopeId: "global",
							Type:          "org",
							Name:          org.Name,
							Description:   org.Description,
						},
						Purpose: "oplog",
						Type:    "dek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
					{
						Scope: &pb.ScopeInfo{
							Id:            org.PublicId,
							ParentScopeId: "global",
							Type:          "org",
							Name:          org.Name,
							Description:   org.Description,
						},
						Purpose: "database",
						Type:    "dek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
					{
						Scope: &pb.ScopeInfo{
							Id:            org.PublicId,
							ParentScopeId: "global",
							Type:          "org",
							Name:          org.Name,
							Description:   org.Description,
						},
						Purpose: "audit",
						Type:    "dek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
					{
						Scope: &pb.ScopeInfo{
							Id:            org.PublicId,
							ParentScopeId: "global",
							Type:          "org",
							Name:          org.Name,
							Description:   org.Description,
						},
						Purpose: "oidc",
						Type:    "dek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
					{
						Scope: &pb.ScopeInfo{
							Id:            org.PublicId,
							ParentScopeId: "global",
							Type:          "org",
							Name:          org.Name,
							Description:   org.Description,
						},
						Purpose: "sessions",
						Type:    "dek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
					{
						Scope: &pb.ScopeInfo{
							Id:            org.PublicId,
							ParentScopeId: "global",
							Type:          "org",
							Name:          org.Name,
							Description:   org.Description,
						},
						Purpose: "rootKey",
						Type:    "kek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
				},
			},
			authCtx: privCtx,
		},
		{
			name:    "List keys in a non existing org",
			req:     &pbs.ListKeysRequest{Id: "o_DoesntExis"},
			authCtx: privCtx,
			err:     handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "List keys in an existing project",
			req:  &pbs.ListKeysRequest{Id: proj.GetPublicId()},
			res: &pbs.ListKeysResponse{
				Items: []*pb.Key{
					{
						Scope: &pb.ScopeInfo{
							Id:            proj.PublicId,
							ParentScopeId: org.PublicId,
							Type:          "project",
							Name:          proj.Name,
							Description:   proj.Description,
						},
						Purpose: "tokens",
						Type:    "dek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
					{
						Scope: &pb.ScopeInfo{
							Id:            proj.PublicId,
							ParentScopeId: org.PublicId,
							Type:          "project",
							Name:          proj.Name,
							Description:   proj.Description,
						},
						Purpose: "oplog",
						Type:    "dek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
					{
						Scope: &pb.ScopeInfo{
							Id:            proj.PublicId,
							ParentScopeId: org.PublicId,
							Type:          "project",
							Name:          proj.Name,
							Description:   proj.Description,
						},
						Purpose: "database",
						Type:    "dek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
					{
						Scope: &pb.ScopeInfo{
							Id:            proj.PublicId,
							ParentScopeId: org.PublicId,
							Type:          "project",
							Name:          proj.Name,
							Description:   proj.Description,
						},
						Purpose: "audit",
						Type:    "dek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
					{
						Scope: &pb.ScopeInfo{
							Id:            proj.PublicId,
							ParentScopeId: org.PublicId,
							Type:          "project",
							Name:          proj.Name,
							Description:   proj.Description,
						},
						Purpose: "oidc",
						Type:    "dek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
					{
						Scope: &pb.ScopeInfo{
							Id:            proj.PublicId,
							ParentScopeId: org.PublicId,
							Type:          "project",
							Name:          proj.Name,
							Description:   proj.Description,
						},
						Purpose: "sessions",
						Type:    "dek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
					{
						Scope: &pb.ScopeInfo{
							Id:            proj.PublicId,
							ParentScopeId: org.PublicId,
							Type:          "project",
							Name:          proj.Name,
							Description:   proj.Description,
						},
						Purpose: "rootKey",
						Type:    "kek",
						Versions: []*pb.KeyVersion{
							{
								Version: 1,
							},
						},
					},
				},
			},
			authCtx: privCtx,
		},
		{
			name:    "List keys in a non existing project",
			req:     &pbs.ListKeysRequest{Id: "p_DoesntExist"},
			err:     handlers.ApiErrorWithCode(codes.NotFound),
			authCtx: privCtx,
		},
		{
			name:    "Wrong id prefix",
			req:     &pbs.ListKeysRequest{Id: "j_1234567890"},
			err:     handlers.ApiErrorWithCode(codes.InvalidArgument),
			authCtx: privCtx,
		},
		{
			name:    "space in id",
			req:     &pbs.ListKeysRequest{Id: "p_1 23456789"},
			err:     handlers.ApiErrorWithCode(codes.InvalidArgument),
			authCtx: privCtx,
		},
		{
			name:    "unauthorized",
			req:     &pbs.ListKeysRequest{Id: "global"},
			err:     handlers.ApiErrorWithCode(codes.PermissionDenied),
			authCtx: unprivCtx,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := scopes.NewServiceFn(context.Background(), iamRepoFn, tc.Kms(), 1000)
			require.NoError(err, "Couldn't create new project service.")

			got, gErr := s.ListKeys(tt.authCtx, tt.req)
			if tt.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tt.err), "ListKeys(%+v) got error\n%v, wanted\n%v", tt.req, gErr, tt.err)
			} else {
				require.NoError(gErr)
			}
			assert.Empty(
				cmp.Diff(
					tt.res,
					got,
					protocmp.Transform(),
					// Sort by purpose for comparison since it is the only unique and predictable field
					protocmp.SortRepeated(func(i, j *pb.Key) bool { return i.GetPurpose() < j.GetPurpose() }),
					protocmp.IgnoreFields(&pb.Key{}, "id", "created_time"),
					protocmp.IgnoreFields(&pb.KeyVersion{}, "id", "created_time"),
					cmpopts.SortSlices(func(a, b string) bool {
						return a < b
					}),
				),
				"ListKeys(%q) got response\n%q, wanted\n%q", tt.req, got, tt.res,
			)
		})
	}
}

func TestRotateKeys(t *testing.T) {
	tc := controller.NewTestController(t, nil)

	aToken := tc.Token()
	uToken := tc.UnprivilegedToken()

	iamRepoFn := func() (*iam.Repository, error) {
		return tc.IamRepo(), nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return tc.ServersRepo(), nil
	}
	authTokenRepoFn := func() (*authtoken.Repository, error) {
		return tc.AuthTokenRepo(), nil
	}

	privCtx := auth.NewVerifierContext(
		context.Background(),
		iamRepoFn,
		authTokenRepoFn,
		serversRepoFn,
		tc.Kms(),
		&authpb.RequestInfo{
			PublicId:       aToken.Id,
			EncryptedToken: strings.Split(aToken.Token, "_")[2],
			TokenFormat:    uint32(auth.AuthTokenTypeBearer),
		})

	unprivCtx := auth.NewVerifierContext(
		context.Background(),
		iamRepoFn,
		authTokenRepoFn,
		serversRepoFn,
		tc.Kms(),
		&authpb.RequestInfo{
			PublicId:       uToken.Id,
			EncryptedToken: strings.Split(uToken.Token, "_")[2],
			TokenFormat:    uint32(auth.AuthTokenTypeBearer),
		})

	org, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(aToken.UserId))

	// Add new role for listing+rotating keys in org
	rotateKeysRole := iam.TestRole(t, tc.DbConn(), org.PublicId)
	iam.TestRoleGrant(t, tc.DbConn(), rotateKeysRole.PublicId, "ids=*;type=*;actions=rotate-keys,list-keys")
	_ = iam.TestUserRole(t, tc.DbConn(), rotateKeysRole.PublicId, aToken.UserId)

	// Add new role for listing+rotating keys in project
	rotateKeysRole = iam.TestRole(t, tc.DbConn(), proj.PublicId)
	iam.TestRoleGrant(t, tc.DbConn(), rotateKeysRole.PublicId, "ids=*;type=*;actions=rotate-keys,list-keys")
	_ = iam.TestUserRole(t, tc.DbConn(), rotateKeysRole.PublicId, aToken.UserId)

	cases := []struct {
		name    string
		req     *pbs.RotateKeysRequest
		res     *pbs.RotateKeysResponse
		authCtx context.Context
		err     error
	}{
		{
			name:    "unauthorized",
			req:     &pbs.RotateKeysRequest{ScopeId: "global", Rewrap: false},
			err:     handlers.ApiErrorWithCode(codes.PermissionDenied),
			authCtx: unprivCtx,
		},
		{
			name:    "Rotate keys in a non existing org",
			req:     &pbs.RotateKeysRequest{ScopeId: "o_DoesntExis", Rewrap: false},
			authCtx: privCtx,
			err:     handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "successfully Rotate keys in org",
			req:     &pbs.RotateKeysRequest{ScopeId: org.GetPublicId(), Rewrap: false},
			authCtx: privCtx,
		},
		{
			name:    "successfully Rotate and rewrap keys in org",
			req:     &pbs.RotateKeysRequest{ScopeId: org.GetPublicId(), Rewrap: true},
			authCtx: privCtx,
		},
		{
			name:    "successfully Rotate keys in project",
			req:     &pbs.RotateKeysRequest{ScopeId: proj.GetPublicId(), Rewrap: false},
			authCtx: privCtx,
		},
		{
			name:    "successfully Rotate and rewrap keys in project",
			req:     &pbs.RotateKeysRequest{ScopeId: proj.GetPublicId(), Rewrap: true},
			authCtx: privCtx,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := scopes.NewServiceFn(context.Background(), iamRepoFn, tc.Kms(), 1000)
			require.NoError(err, "Couldn't create new project service.")

			prevKeyVersions := map[uint32]int{}
			var prevLatest uint32 = 0

			// checking key versions before rotation
			if tt.err == nil {
				keys, gErr := s.ListKeys(privCtx, &pbs.ListKeysRequest{Id: tt.req.ScopeId})
				require.NoError(gErr)

				for _, key := range keys.Items {
					for _, keyVersion := range key.Versions {
						if keyVersion.Version > prevLatest {
							prevLatest = keyVersion.Version
						}
						_, ok := prevKeyVersions[keyVersion.Version]
						if !ok {
							prevKeyVersions[keyVersion.Version] = 0
						}
						prevKeyVersions[keyVersion.Version]++
					}
				}
			}

			// RotateKeys returns nocontent response
			_, kErr := s.RotateKeys(tt.authCtx, tt.req)

			if tt.err != nil {
				require.Error(kErr)
				assert.True(errors.Is(kErr, tt.err), "RotateKeys(%+v) got error\n%v, wanted\n%v", tt.req, kErr, tt.err)
			} else {
				require.NoError(kErr)
				keys, gErr := s.ListKeys(privCtx, &pbs.ListKeysRequest{Id: tt.req.ScopeId})
				require.NoError(gErr)

				keyVersions := map[uint32]int{}
				var latest uint32 = 0

				for _, key := range keys.Items {
					for _, keyVersion := range key.Versions {
						if keyVersion.Version > latest {
							latest = keyVersion.Version
						}
						_, ok := keyVersions[keyVersion.Version]
						if !ok {
							keyVersions[keyVersion.Version] = 0
						}
						keyVersions[keyVersion.Version]++
					}
				}

				// there should only be one new key version
				assert.Equal(len(prevKeyVersions)+1, len(keyVersions))
				// since we just rotated them, there should be the same number of version 1 and version 2
				assert.Equal(prevKeyVersions[prevLatest], keyVersions[latest])
			}
		})
	}
}

func TestListKeyVersionDestructionJobs(t *testing.T) {
	tc := controller.NewTestController(t, nil)

	aToken := tc.Token()
	uToken := tc.UnprivilegedToken()

	iamRepoFn := func() (*iam.Repository, error) {
		return tc.IamRepo(), nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return tc.ServersRepo(), nil
	}
	authTokenRepoFn := func() (*authtoken.Repository, error) {
		return tc.AuthTokenRepo(), nil
	}

	privCtx := auth.NewVerifierContext(
		tc.Context(),
		iamRepoFn,
		authTokenRepoFn,
		serversRepoFn,
		tc.Kms(),
		&authpb.RequestInfo{
			PublicId:       aToken.Id,
			EncryptedToken: strings.Split(aToken.Token, "_")[2],
			TokenFormat:    uint32(auth.AuthTokenTypeBearer),
		},
	)

	unprivCtx := auth.NewVerifierContext(
		tc.Context(),
		iamRepoFn,
		authTokenRepoFn,
		serversRepoFn,
		tc.Kms(),
		&authpb.RequestInfo{
			PublicId:       uToken.Id,
			EncryptedToken: strings.Split(uToken.Token, "_")[2],
			TokenFormat:    uint32(auth.AuthTokenTypeBearer),
		},
	)

	sqldb, err := tc.DbConn().SqlDB(tc.Context())
	require.NoError(t, err)

	org, proj := iam.TestScopes(t, tc.IamRepo())

	org.Name = "defaultOrg"
	org.Description = "defaultOrg"
	org, _, err = tc.IamRepo().UpdateScope(tc.Context(), org, 1, []string{"Name", "Description"})
	require.NoError(t, err)

	// Add new role for listing key version destructions in org
	listKeysRole := iam.TestRole(t, tc.DbConn(), org.PublicId)
	_ = iam.TestRoleGrant(t, tc.DbConn(), listKeysRole.PublicId, "ids=*;type=*;actions=list-key-version-destruction-jobs")
	_ = iam.TestUserRole(t, tc.DbConn(), listKeysRole.PublicId, aToken.UserId)
	// Create a oidc auth method to create an encrypted value in this scope
	databaseWrapper, err := tc.Kms().GetWrapper(tc.Context(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	_ = oidc.TestAuthMethod(t, tc.DbConn(), databaseWrapper, org.PublicId, oidc.InactiveState, "noAccounts", "fido")

	proj.Name = "defaultProj"
	proj.Description = "defaultProj"
	proj, _, err = tc.IamRepo().UpdateScope(tc.Context(), proj, 1, []string{"Name", "Description"})
	require.NoError(t, err)

	// Add new role for listing key version destructions in project
	listKeysRole = iam.TestRole(t, tc.DbConn(), proj.PublicId)
	_ = iam.TestRoleGrant(t, tc.DbConn(), listKeysRole.PublicId, "ids=*;type=*;actions=list-key-version-destruction-jobs")
	_ = iam.TestUserRole(t, tc.DbConn(), listKeysRole.PublicId, aToken.UserId)
	// Create a oidc auth method to create an encrypted value in this scope
	databaseWrapper, err = tc.Kms().GetWrapper(tc.Context(), proj.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	_ = oidc.TestAuthMethod(t, tc.DbConn(), databaseWrapper, proj.PublicId, oidc.InactiveState, "noAccounts", "fido")

	for _, scope := range []string{"global", org.PublicId, proj.PublicId} {
		err = tc.Kms().RotateKeys(tc.Context(), scope)
		require.NoError(t, err)
		keys, err := tc.Kms().ListKeys(tc.Context(), scope)
		require.NoError(t, err)

		var kvToDestroy wrappingKms.KeyVersion
		for _, key := range keys {
			if key.Purpose == wrappingKms.KeyPurpose(kms.KeyPurposeDatabase.String()) {
				kvToDestroy = key.Versions[0]
			}
		}
		destroyed, err := tc.Kms().DestroyKeyVersion(tc.Context(), scope, kvToDestroy.Id)
		require.NoError(t, err)
		assert.False(t, destroyed)
		t.Cleanup(func() {
			_, err = sqldb.ExecContext(tc.Context(), "delete from kms_data_key_version_destruction_job where key_id=$1", kvToDestroy.Id)
			require.NoError(t, err)
		})
	}

	cases := []struct {
		name    string
		req     *pbs.ListKeyVersionDestructionJobsRequest
		res     *pbs.ListKeyVersionDestructionJobsResponse
		authCtx context.Context
		err     error
	}{
		{
			name: "List key version destruction jobs in the global scope",
			req:  &pbs.ListKeyVersionDestructionJobsRequest{ScopeId: "global"},
			res: &pbs.ListKeyVersionDestructionJobsResponse{
				Items: []*pb.KeyVersionDestructionJob{
					{
						Scope: &pb.ScopeInfo{
							Id:          "global",
							Type:        "global",
							Name:        "global",
							Description: "Global Scope",
						},
						Status:         "pending",
						CompletedCount: 0,
						TotalCount:     7,
					},
				},
			},
			authCtx: privCtx,
		},
		{
			name: "List key version destruction jobs in an existing org",
			req:  &pbs.ListKeyVersionDestructionJobsRequest{ScopeId: org.GetPublicId()},
			res: &pbs.ListKeyVersionDestructionJobsResponse{
				Items: []*pb.KeyVersionDestructionJob{
					{
						Scope: &pb.ScopeInfo{
							Id:            org.GetPublicId(),
							ParentScopeId: "global",
							Type:          "org",
							Name:          org.GetName(),
							Description:   org.GetDescription(),
						},
						Status:         "pending",
						CompletedCount: 0,
						TotalCount:     1,
					},
				},
			},
			authCtx: privCtx,
		},
		{
			name:    "List key version destruction jobs in a non existing org",
			req:     &pbs.ListKeyVersionDestructionJobsRequest{ScopeId: "o_DoesntExis"},
			authCtx: privCtx,
			err:     handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "List key version destruction jobs in an existing project",
			req:  &pbs.ListKeyVersionDestructionJobsRequest{ScopeId: proj.GetPublicId()},
			res: &pbs.ListKeyVersionDestructionJobsResponse{
				Items: []*pb.KeyVersionDestructionJob{
					{
						Scope: &pb.ScopeInfo{
							Id:            proj.GetPublicId(),
							ParentScopeId: org.GetPublicId(),
							Type:          "project",
							Name:          proj.GetName(),
							Description:   proj.GetDescription(),
						},
						Status:         "pending",
						CompletedCount: 0,
						TotalCount:     1,
					},
				},
			},
			authCtx: privCtx,
		},
		{
			name:    "List key version destruction jobs in a non existing project",
			req:     &pbs.ListKeyVersionDestructionJobsRequest{ScopeId: "p_DoesntExist"},
			authCtx: privCtx,
			err:     handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Wrong id prefix",
			req:     &pbs.ListKeyVersionDestructionJobsRequest{ScopeId: "j_1234567890"},
			authCtx: privCtx,
			err:     handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "space in id",
			req:     &pbs.ListKeyVersionDestructionJobsRequest{ScopeId: "p_1 23456789"},
			authCtx: privCtx,
			err:     handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "unauthorized",
			req:     &pbs.ListKeyVersionDestructionJobsRequest{ScopeId: "global"},
			authCtx: unprivCtx,
			err:     handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := scopes.NewServiceFn(context.Background(), iamRepoFn, tc.Kms(), 1000)
			require.NoError(err, "Couldn't create new project service.")

			got, gErr := s.ListKeyVersionDestructionJobs(tt.authCtx, tt.req)
			if tt.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tt.err), "ListKeyVersionDestructionJobs(%+v) got error\n%v, wanted\n%v", tt.req, gErr, tt.err)
			} else {
				require.NoError(gErr)
			}
			assert.Empty(
				cmp.Diff(
					tt.res,
					got,
					protocmp.Transform(),
					protocmp.SortRepeated(func(i, j *pb.KeyVersionDestructionJob) bool { return i.GetTotalCount() < j.GetTotalCount() }),
					protocmp.IgnoreFields(&pb.KeyVersionDestructionJob{}, "key_version_id", "created_time"),
					cmpopts.SortSlices(func(a, b string) bool {
						return a < b
					}),
					cmpopts.SortSlices(func(a, b protocmp.Message) bool {
						return a.String() < b.String()
					}),
				),
				"ListKeyVersionDestructionJobs(%q) got response\n%q, wanted\n%q", tt.req, got, tt.res,
			)
		})
	}
}

func TestDestroyKeyVersion(t *testing.T) {
	tc := controller.NewTestController(t, nil)

	aToken := tc.Token()
	uToken := tc.UnprivilegedToken()

	iamRepoFn := func() (*iam.Repository, error) {
		return tc.IamRepo(), nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return tc.ServersRepo(), nil
	}
	authTokenRepoFn := func() (*authtoken.Repository, error) {
		return tc.AuthTokenRepo(), nil
	}

	privCtx := auth.NewVerifierContext(
		tc.Context(),
		iamRepoFn,
		authTokenRepoFn,
		serversRepoFn,
		tc.Kms(),
		&authpb.RequestInfo{
			PublicId:       aToken.Id,
			EncryptedToken: strings.Split(aToken.Token, "_")[2],
			TokenFormat:    uint32(auth.AuthTokenTypeBearer),
		},
	)

	unprivCtx := auth.NewVerifierContext(
		tc.Context(),
		iamRepoFn,
		authTokenRepoFn,
		serversRepoFn,
		tc.Kms(),
		&authpb.RequestInfo{
			PublicId:       uToken.Id,
			EncryptedToken: strings.Split(uToken.Token, "_")[2],
			TokenFormat:    uint32(auth.AuthTokenTypeBearer),
		},
	)

	org, proj := iam.TestScopes(t, tc.IamRepo())

	org.Name = "defaultOrg"
	org.Description = "defaultOrg"
	org, _, err := tc.IamRepo().UpdateScope(tc.Context(), org, 1, []string{"Name", "Description"})
	require.NoError(t, err)

	// Add new role for destroying key versions in org
	listKeysRole := iam.TestRole(t, tc.DbConn(), org.PublicId)
	_ = iam.TestRoleGrant(t, tc.DbConn(), listKeysRole.PublicId, "ids=*;type=*;actions=destroy-key-version")
	_ = iam.TestUserRole(t, tc.DbConn(), listKeysRole.PublicId, aToken.UserId)
	// Create a oidc auth method to create an encrypted value in this scope
	databaseWrapper, err := tc.Kms().GetWrapper(tc.Context(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	_ = oidc.TestAuthMethod(t, tc.DbConn(), databaseWrapper, org.PublicId, oidc.InactiveState, "noAccounts", "fido")

	proj.Name = "defaultProj"
	proj.Description = "defaultProj"
	proj, _, err = tc.IamRepo().UpdateScope(tc.Context(), proj, 1, []string{"Name", "Description"})
	require.NoError(t, err)

	// Add new role for destroying key versions in project
	listKeysRole = iam.TestRole(t, tc.DbConn(), proj.PublicId)
	_ = iam.TestRoleGrant(t, tc.DbConn(), listKeysRole.PublicId, "ids=*;type=*;actions=destroy-key-version")
	_ = iam.TestUserRole(t, tc.DbConn(), listKeysRole.PublicId, aToken.UserId)
	// Create a oidc auth method to create an encrypted value in this scope
	databaseWrapper, err = tc.Kms().GetWrapper(tc.Context(), proj.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	_ = oidc.TestAuthMethod(t, tc.DbConn(), databaseWrapper, proj.PublicId, oidc.InactiveState, "noAccounts", "fido")

	scopeToImmediatelyDestroyedKeyVersionId := map[string]string{}
	scopeToPendingDestructionKeyVersionId := map[string]string{}
	for _, scope := range []string{"global", org.PublicId, proj.PublicId} {
		err = tc.Kms().RotateKeys(tc.Context(), scope)
		require.NoError(t, err)

		keys, err := tc.Kms().ListKeys(tc.Context(), scope)
		require.NoError(t, err)

		for _, key := range keys {
			switch key.Purpose {
			case wrappingKms.KeyPurpose(kms.KeyPurposeDatabase.String()):
				scopeToPendingDestructionKeyVersionId[scope] = key.Versions[0].Id
			case wrappingKms.KeyPurpose(kms.KeyPurposeRootKey.String()):
				scopeToImmediatelyDestroyedKeyVersionId[scope] = key.Versions[0].Id
			}
		}
	}

	cases := []struct {
		name    string
		req     *pbs.DestroyKeyVersionRequest
		res     *pbs.DestroyKeyVersionResponse
		authCtx context.Context
		err     error
	}{
		{
			name: "Errors when specifying a non existing key version Id",
			req: &pbs.DestroyKeyVersionRequest{
				ScopeId:      "global",
				KeyVersionId: "krkv_DoesntExist",
			},
			authCtx: privCtx,
			err:     handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Creates a key version destruction job in the global scope",
			req: &pbs.DestroyKeyVersionRequest{
				ScopeId:      "global",
				KeyVersionId: scopeToPendingDestructionKeyVersionId["global"],
			},
			res: &pbs.DestroyKeyVersionResponse{
				State: "pending",
			},
			authCtx: privCtx,
		},
		{
			name: "Immediately destroys a root key version in the global scope",
			req: &pbs.DestroyKeyVersionRequest{
				ScopeId:      "global",
				KeyVersionId: scopeToImmediatelyDestroyedKeyVersionId["global"],
			},
			res: &pbs.DestroyKeyVersionResponse{
				State: "completed",
			},
			authCtx: privCtx,
		},
		{
			name: "Creates a key version destruction job in an existing org",
			req: &pbs.DestroyKeyVersionRequest{
				ScopeId:      org.GetPublicId(),
				KeyVersionId: scopeToPendingDestructionKeyVersionId[org.GetPublicId()],
			},
			res: &pbs.DestroyKeyVersionResponse{
				State: "pending",
			},
			authCtx: privCtx,
		},
		{
			name: "Immediately destroys a root key version in an existing org",
			req: &pbs.DestroyKeyVersionRequest{
				ScopeId:      org.GetPublicId(),
				KeyVersionId: scopeToImmediatelyDestroyedKeyVersionId[org.GetPublicId()],
			},
			res: &pbs.DestroyKeyVersionResponse{
				State: "completed",
			},
			authCtx: privCtx,
		},
		{
			name: "Creates a key version destruction job in an existing project",
			req: &pbs.DestroyKeyVersionRequest{
				ScopeId:      proj.GetPublicId(),
				KeyVersionId: scopeToPendingDestructionKeyVersionId[proj.GetPublicId()],
			},
			res: &pbs.DestroyKeyVersionResponse{
				State: "pending",
			},
			authCtx: privCtx,
		},
		{
			name: "Immediately destroys a root key version in an existing project",
			req: &pbs.DestroyKeyVersionRequest{
				ScopeId:      proj.GetPublicId(),
				KeyVersionId: scopeToImmediatelyDestroyedKeyVersionId[proj.GetPublicId()],
			},
			res: &pbs.DestroyKeyVersionResponse{
				State: "completed",
			},
			authCtx: privCtx,
		},
		{
			name: "Errors when specifying a key version that doesn't exist in the scope",
			req: &pbs.DestroyKeyVersionRequest{
				ScopeId:      org.GetPublicId(),
				KeyVersionId: scopeToPendingDestructionKeyVersionId[proj.GetPublicId()],
			},
			authCtx: privCtx,
			err:     handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Errors when specifying a non existing org",
			req: &pbs.DestroyKeyVersionRequest{
				ScopeId:      "o_DoesntExist",
				KeyVersionId: scopeToImmediatelyDestroyedKeyVersionId[org.GetPublicId()],
			},
			authCtx: privCtx,
			err:     handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Errors when specifying a non existing project",
			req: &pbs.DestroyKeyVersionRequest{
				ScopeId:      "p_DoesntExist",
				KeyVersionId: scopeToImmediatelyDestroyedKeyVersionId[proj.GetPublicId()],
			},
			authCtx: privCtx,
			err:     handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Wrong id prefix",
			req: &pbs.DestroyKeyVersionRequest{
				ScopeId:      "j_1234567890",
				KeyVersionId: scopeToImmediatelyDestroyedKeyVersionId["global"],
			},
			authCtx: privCtx,
			err:     handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "space in id",
			req: &pbs.DestroyKeyVersionRequest{
				ScopeId:      "p_1 23456789",
				KeyVersionId: scopeToImmediatelyDestroyedKeyVersionId["global"],
			},
			authCtx: privCtx,
			err:     handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "unauthorized",
			req: &pbs.DestroyKeyVersionRequest{
				ScopeId:      "global",
				KeyVersionId: scopeToImmediatelyDestroyedKeyVersionId["global"],
			},
			authCtx: unprivCtx,
			err:     handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := scopes.NewServiceFn(context.Background(), iamRepoFn, tc.Kms(), 1000)
			require.NoError(err, "Couldn't create new project service.")

			got, gErr := s.DestroyKeyVersion(tt.authCtx, tt.req)
			if tt.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tt.err), "DestroyKeyVersion(%+v) got error\n%v, wanted\n%v", tt.req, gErr, tt.err)
			} else {
				require.NoError(gErr)
			}

			assert.Empty(cmp.Diff(
				tt.res,
				got,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				cmpopts.SortSlices(func(a, b protocmp.Message) bool {
					return a.String() < b.String()
				}),
			), "DestroyKeyVersion(%q) got response\n%q, wanted\n%q", tt.req, got, tt.res)
		})
	}
}

func TestAttachStoragePolicy(t *testing.T) {
	t.Run("unimplemented", func(t *testing.T) {
		service := &scopes.Service{}
		_, err := service.AttachStoragePolicy(context.Background(), &pbs.AttachStoragePolicyRequest{})
		require.Error(t, err)
		gotStatus, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, gotStatus.Code(), codes.Unimplemented)
		assert.Equal(t, gotStatus.Message(), "Policies are an Enterprise-only feature")
	})
}

func TestDetachStoragePolicy(t *testing.T) {
	t.Run("unimplemented", func(t *testing.T) {
		service := &scopes.Service{}
		_, err := service.DetachStoragePolicy(context.Background(), &pbs.DetachStoragePolicyRequest{})
		require.Error(t, err)
		gotStatus, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, gotStatus.Code(), codes.Unimplemented)
		assert.Equal(t, gotStatus.Message(), "Policies are an Enterprise-only feature")
	})
}
