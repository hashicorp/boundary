package scopes_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/scopes"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	wrappingKms "github.com/hashicorp/go-kms-wrapping/extras/kms/v2"
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

var testAuthorizedActions = []string{"no-op", "read", "update", "delete"}

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
	"roles": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"scopes": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
			structpb.NewStringValue("list-keys"),
			structpb.NewStringValue("rotate-keys"),
			structpb.NewStringValue("revoke-keys"),
			structpb.NewStringValue("list-key-version-destruction-jobs"),
			structpb.NewStringValue("destroy-key-version"),
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
	"roles": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"scopes": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
			structpb.NewStringValue("list-keys"),
			structpb.NewStringValue("rotate-keys"),
			structpb.NewStringValue("revoke-keys"),
			structpb.NewStringValue("list-key-version-destruction-jobs"),
			structpb.NewStringValue("destroy-key-version"),
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
			structpb.NewStringValue("list-keys"),
			structpb.NewStringValue("rotate-keys"),
			structpb.NewStringValue("revoke-keys"),
			structpb.NewStringValue("list-key-version-destruction-jobs"),
			structpb.NewStringValue("destroy-key-version"),
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
		AuthorizedActions:           testAuthorizedActions,
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
		AuthorizedActions:           testAuthorizedActions,
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

			s, err := scopes.NewService(repoFn, kms)
			require.NoError(err, "Couldn't create new project service.")

			got, gErr := s.GetScope(auth.DisabledAuthTestContext(repoFn, tc.scopeId), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetScope(%+v) got error\n%v, wanted\n%v", req, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(tc.res, got, protocmp.Transform()), "GetScope(%q) got response\n%q, wanted\n%q", req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
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

	outputFields := perms.OutputFieldsMap(nil).SelfOrDefaults("u_auth")
	var initialOrgs []*pb.Scope
	globalScope := &pb.ScopeInfo{Id: "global", Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"}
	oNoProjectsProto, err := scopes.ToProto(context.Background(), oNoProjects, handlers.WithOutputFields(&outputFields))
	require.NoError(t, err)
	oNoProjectsProto.Scope = globalScope
	oNoProjectsProto.AuthorizedActions = testAuthorizedActions
	oNoProjectsProto.AuthorizedCollectionActions = orgAuthorizedCollectionActions
	oWithProjectsProto, err := scopes.ToProto(context.Background(), oWithProjects, handlers.WithOutputFields(&outputFields))
	require.NoError(t, err)
	oWithProjectsProto.Scope = globalScope
	oWithProjectsProto.AuthorizedActions = testAuthorizedActions
	oWithProjectsProto.AuthorizedCollectionActions = orgAuthorizedCollectionActions
	initialOrgs = append(initialOrgs, oNoProjectsProto, oWithProjectsProto)
	scopes.SortScopes(initialOrgs)

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
			res:     &pbs.ListScopesResponse{Items: initialOrgs},
		},
		{
			name:    "List No Projects",
			scopeId: oNoProjects.GetPublicId(),
			req:     &pbs.ListScopesRequest{ScopeId: oNoProjects.GetPublicId()},
			res:     &pbs.ListScopesResponse{},
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
			res:     &pbs.ListScopesResponse{Items: initialOrgs[1:2]},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := scopes.NewService(repoFn, kms)
			require.NoError(err, "Couldn't create new role service.")

			// Test with non-anonymous listing first
			got, gErr := s.ListScopes(auth.DisabledAuthTestContext(repoFn, tc.scopeId), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListScopes(%+v) got error\n%v, wanted\n%v", tc.req, gErr, tc.err)
				return
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListScopes(%q) got response\n%q\nwanted\n%q", tc.req, got, tc.res)

			// Now test with anonymous listing
			got, gErr = s.ListScopes(auth.DisabledAuthTestContext(repoFn, tc.scopeId, auth.WithUserId(auth.AnonymousUserId)), tc.req)
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
		newO, err := iam.NewOrg()
		require.NoError(t, err)
		o, err := repo.CreateScope(context.Background(), newO, "")
		require.NoError(t, err)
		wantOrgs = append(wantOrgs, &pb.Scope{
			Id:                          o.GetPublicId(),
			ScopeId:                     globalScope.GetId(),
			Scope:                       globalScope,
			CreatedTime:                 o.GetCreateTime().GetTimestamp(),
			UpdatedTime:                 o.GetUpdateTime().GetTimestamp(),
			Version:                     1,
			Type:                        scope.Org.String(),
			AuthorizedActions:           testAuthorizedActions,
			AuthorizedCollectionActions: orgAuthorizedCollectionActions,
		})
	}
	wantOrgs = append(wantOrgs, initialOrgs...)
	scopes.SortScopes(wantOrgs)

	var wantProjects []*pb.Scope
	for i := 0; i < 10; i++ {
		newP, err := iam.NewProject(oWithProjects.GetPublicId())
		require.NoError(t, err)
		p, err := repo.CreateScope(context.Background(), newP, "")
		require.NoError(t, err)
		wantProjects = append(wantProjects, &pb.Scope{
			Id:                          p.GetPublicId(),
			ScopeId:                     oWithProjects.GetPublicId(),
			Scope:                       &pb.ScopeInfo{Id: oWithProjects.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			CreatedTime:                 p.GetCreateTime().GetTimestamp(),
			UpdatedTime:                 p.GetUpdateTime().GetTimestamp(),
			Version:                     1,
			Type:                        scope.Project.String(),
			AuthorizedActions:           testAuthorizedActions,
			AuthorizedCollectionActions: projectAuthorizedCollectionActions,
		})
	}
	scopes.SortScopes(wantProjects)

	totalScopes := append(wantOrgs, wantProjects...)
	scopes.SortScopes(totalScopes)

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
			res:     &pbs.ListScopesResponse{Items: wantOrgs},
		},
		{
			name:    "List Many Projects",
			scopeId: oWithProjects.GetPublicId(),
			req:     &pbs.ListScopesRequest{ScopeId: oWithProjects.GetPublicId()},
			res:     &pbs.ListScopesResponse{Items: wantProjects},
		},
		{
			name:    "List Global Recursively",
			scopeId: scope.Global.String(),
			req:     &pbs.ListScopesRequest{ScopeId: scope.Global.String(), Recursive: true},
			res:     &pbs.ListScopesResponse{Items: totalScopes},
		},
		{
			name:    "Filter To Orgs",
			scopeId: scope.Global.String(),
			req:     &pbs.ListScopesRequest{ScopeId: scope.Global.String(), Recursive: true, Filter: fmt.Sprintf(`"/item/scope/type"==%q`, scope.Global.String())},
			res:     &pbs.ListScopesResponse{Items: wantOrgs},
		},
		{
			name:    "Filter To Projects",
			scopeId: scope.Global.String(),
			req:     &pbs.ListScopesRequest{ScopeId: scope.Global.String(), Recursive: true, Filter: fmt.Sprintf(`"/item/scope/type"==%q`, scope.Org.String())},
			res:     &pbs.ListScopesResponse{Items: wantProjects},
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
			s, err := scopes.NewService(repoFn, kms)
			require.NoError(err, "Couldn't create new role service.")

			// Test with non-anonymous listing first
			got, gErr := s.ListScopes(auth.DisabledAuthTestContext(repoFn, tc.scopeId), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListScopes(%+v) got error\n%v, wanted\n%v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListScopes(%q) got response\n%q, wanted\n%q", tc.req, got, tc.res)

			// Now test with anonymous listing
			got, gErr = s.ListScopes(auth.DisabledAuthTestContext(repoFn, tc.scopeId, auth.WithUserId(auth.AnonymousUserId)), tc.req)
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

func TestDelete(t *testing.T) {
	org, proj, repoFn, kms := createDefaultScopesRepoAndKms(t)

	s, err := scopes.NewService(repoFn, kms)
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

	s, err := scopes.NewService(repoFn, kms)
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
	globalUser, err := iam.NewUser(scope.Global.String())
	require.NoError(t, err)
	globalUser, err = repo.CreateUser(ctx, globalUser)
	require.NoError(t, err)
	orgUser, err := iam.NewUser(defaultOrg.GetPublicId())
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
					AuthorizedActions:           testAuthorizedActions,
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
					AuthorizedActions:           testAuthorizedActions,
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
					AuthorizedActions:           testAuthorizedActions,
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
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: orgAuthorizedCollectionActions,
				},
			},
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

				s, err := scopes.NewService(repoFn, kms)
				require.NoError(err, "Error when getting new project service.")

				if name != "" {
					name = fmt.Sprintf("%s-%t", name, withUserId)
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
						roles, err := repo.ListRoles(ctx, []string{got.GetItem().GetId()})
						require.NoError(err)
						switch tc.scopeId {
						case defaultOrg.PublicId:
							require.Len(roles, 2)
						case "global":
							require.Len(roles, 2)
						}
						for _, role := range roles {
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
					assert.Equal(name, got.GetItem().GetName().GetValue())
					got.Item.Name = tc.res.GetItem().GetName()
					got.Uri, tc.res.Uri = "", ""
					got.Item.Id, tc.res.Item.Id = "", ""
					got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
				}
				assert.Empty(cmp.Diff(tc.res, got, protocmp.Transform()), "CreateScope(%q) got response %q, wanted %q", req, got, tc.res)
			})
		}
	}
}

func TestUpdate(t *testing.T) {
	org, proj, repoFn, kms := createDefaultScopesRepoAndKms(t)
	tested, err := scopes.NewService(repoFn, kms)
	require.NoError(t, err, "Error when getting new project service.")

	iamRepo, err := repoFn()
	require.NoError(t, err)
	global, err := iamRepo.LookupScope(context.Background(), "global")
	require.NoError(t, err)

	var orgVersion uint32 = 2
	var projVersion uint32 = 2
	var globalVersion uint32 = global.Version

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
					AuthorizedActions:           testAuthorizedActions,
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
					AuthorizedActions:           testAuthorizedActions,
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
					AuthorizedActions:           testAuthorizedActions,
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
					AuthorizedActions:           testAuthorizedActions,
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
			name:    "Only non-existant paths in Mask",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
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
					AuthorizedActions:           testAuthorizedActions,
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
					AuthorizedActions:           testAuthorizedActions,
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
					AuthorizedActions:           testAuthorizedActions,
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
					AuthorizedActions:           testAuthorizedActions,
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
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "UpdateScope(%q) got response\n%q, wanted\n%q", req, got, tc.res)
		})
	}
}

func TestListKeys(t *testing.T) {
	tc := controller.NewTestController(t, nil)
	t.Cleanup(tc.Shutdown)

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
	_, err = tc.IamRepo().AddRoleGrants(context.Background(), listKeysRole.PublicId, 1, []string{"id=*;type=*;actions=list-keys"})
	require.NoError(t, err)
	_, err = tc.IamRepo().AddPrincipalRoles(context.Background(), listKeysRole.PublicId, 2, []string{aToken.UserId})
	require.NoError(t, err)

	proj.Name = "defaultProj"
	proj.Description = "defaultProj"
	proj, _, err = tc.IamRepo().UpdateScope(context.Background(), proj, 1, []string{"Name", "Description"})
	require.NoError(t, err)

	// Add new role for listing keys in project
	listKeysRole = iam.TestRole(t, tc.DbConn(), proj.PublicId)
	_, err = tc.IamRepo().AddRoleGrants(context.Background(), listKeysRole.PublicId, 1, []string{"id=*;type=*;actions=list-keys"})
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

			s, err := scopes.NewService(iamRepoFn, tc.Kms())
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
				),
				"ListKeys(%q) got response\n%q, wanted\n%q", tt.req, got, tt.res,
			)
		})
	}
}

func TestRotateKeys(t *testing.T) {
	tc := controller.NewTestController(t, nil)
	t.Cleanup(tc.Shutdown)

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
	iam.TestRoleGrant(t, tc.DbConn(), rotateKeysRole.PublicId, "id=*;type=*;actions=rotate-keys,list-keys")
	_ = iam.TestUserRole(t, tc.DbConn(), rotateKeysRole.PublicId, aToken.UserId)

	// Add new role for listing+rotating keys in project
	rotateKeysRole = iam.TestRole(t, tc.DbConn(), proj.PublicId)
	iam.TestRoleGrant(t, tc.DbConn(), rotateKeysRole.PublicId, "id=*;type=*;actions=rotate-keys,list-keys")
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

			s, err := scopes.NewService(iamRepoFn, tc.Kms())
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
	t.Cleanup(tc.Shutdown)

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
	_ = iam.TestRoleGrant(t, tc.DbConn(), listKeysRole.PublicId, "id=*;type=*;actions=list-key-version-destruction-jobs")
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
	_ = iam.TestRoleGrant(t, tc.DbConn(), listKeysRole.PublicId, "id=*;type=*;actions=list-key-version-destruction-jobs")
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

			s, err := scopes.NewService(iamRepoFn, tc.Kms())
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
				),
				"ListKeyVersionDestructionJobs(%q) got response\n%q, wanted\n%q", tt.req, got, tt.res,
			)
		})
	}
}

func TestDestroyKeyVersion(t *testing.T) {
	tc := controller.NewTestController(t, nil)
	t.Cleanup(tc.Shutdown)

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
	_ = iam.TestRoleGrant(t, tc.DbConn(), listKeysRole.PublicId, "id=*;type=*;actions=destroy-key-version")
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
	_ = iam.TestRoleGrant(t, tc.DbConn(), listKeysRole.PublicId, "id=*;type=*;actions=destroy-key-version")
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

			s, err := scopes.NewService(iamRepoFn, tc.Kms())
			require.NoError(err, "Couldn't create new project service.")

			got, gErr := s.DestroyKeyVersion(tt.authCtx, tt.req)
			if tt.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tt.err), "DestroyKeyVersion(%+v) got error\n%v, wanted\n%v", tt.req, gErr, tt.err)
			} else {
				require.NoError(gErr)
			}

			assert.Empty(cmp.Diff(tt.res, got, protocmp.Transform()), "DestroyKeyVersion(%q) got response\n%q, wanted\n%q", tt.req, got, tt.res)
		})
	}
}
