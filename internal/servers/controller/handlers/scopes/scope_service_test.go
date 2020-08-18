package scopes_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/scopes"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createDefaultScopesAndRepo(t *testing.T) (*iam.Scope, *iam.Scope, func() (*iam.Repository, error)) {
	t.Helper()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	oRes, pRes := iam.TestScopes(t, iamRepo)

	oRes.Name = "defaultProj"
	oRes.Description = "defaultProj"
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
	return oRes, pRes, repoFn
}

func TestGet(t *testing.T) {
	org, proj, repo := createDefaultScopesAndRepo(t)
	toMerge := &pbs.GetScopeRequest{
		Id: proj.GetPublicId(),
	}

	oScope := &pb.Scope{
		Id:          org.GetPublicId(),
		Scope:       &pb.ScopeInfo{Id: "global", Type: scope.Global.String()},
		Name:        &wrapperspb.StringValue{Value: org.GetName()},
		Description: &wrapperspb.StringValue{Value: org.GetDescription()},
		CreatedTime: org.CreateTime.GetTimestamp(),
		UpdatedTime: org.UpdateTime.GetTimestamp(),
		Version:     2,
	}

	pScope := &pb.Scope{
		Id:          proj.GetPublicId(),
		Scope:       &pb.ScopeInfo{Id: oScope.Id, Type: scope.Org.String()},
		Name:        &wrapperspb.StringValue{Value: proj.GetName()},
		Description: &wrapperspb.StringValue{Value: proj.GetDescription()},
		CreatedTime: proj.CreateTime.GetTimestamp(),
		UpdatedTime: proj.UpdateTime.GetTimestamp(),
		Version:     2,
	}

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.GetScopeRequest
		res     *pbs.GetScopeResponse
		errCode codes.Code
	}{
		{
			name:    "Get an existing org",
			scopeId: "global",
			req:     &pbs.GetScopeRequest{Id: org.GetPublicId()},
			res:     &pbs.GetScopeResponse{Item: oScope},
			errCode: codes.OK,
		},
		{
			name:    "Get a non existing org",
			scopeId: "global",
			req:     &pbs.GetScopeRequest{Id: "o_DoesntExis"},
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Get an existing project",
			scopeId: org.GetPublicId(),
			req:     &pbs.GetScopeRequest{Id: proj.GetPublicId()},
			res:     &pbs.GetScopeResponse{Item: pScope},
			errCode: codes.OK,
		},
		{
			name:    "Get a non existing project",
			scopeId: org.GetPublicId(),
			req:     &pbs.GetScopeRequest{Id: "p_DoesntExis"},
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Wrong id prefix",
			scopeId: org.GetPublicId(),
			req:     &pbs.GetScopeRequest{Id: "j_1234567890"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "space in id",
			scopeId: org.GetPublicId(),
			req:     &pbs.GetScopeRequest{Id: "p_1 23456789"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			req := proto.Clone(toMerge).(*pbs.GetScopeRequest)
			proto.Merge(req, tc.req)

			s, err := scopes.NewService(repo)
			require.NoError(err, "Couldn't create new project service.")

			got, gErr := s.GetScope(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetScope(%+v) got error\n%v, wanted\n%v", req, gErr, tc.errCode)
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

	oNoProjects, p1 := iam.TestScopes(t, repo)
	_, err = repo.DeleteScope(context.Background(), p1.GetPublicId())
	require.NoError(t, err)
	oWithProjects, p2 := iam.TestScopes(t, repo)
	_, err = repo.DeleteScope(context.Background(), p2.GetPublicId())
	require.NoError(t, err)

	var initialOrgs []*pb.Scope
	globalScope := &pb.ScopeInfo{Id: "global", Type: scope.Global.String()}
	oNoProjectsProto := scopes.ToProto(oNoProjects)
	oNoProjectsProto.Scope = globalScope
	oWithProjectsProto := scopes.ToProto(oWithProjects)
	oWithProjectsProto.Scope = globalScope
	initialOrgs = append(initialOrgs, oNoProjectsProto, oWithProjectsProto)
	scopes.SortScopes(initialOrgs)

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.ListScopesRequest
		res     *pbs.ListScopesResponse
		errCode codes.Code
	}{
		{
			name:    "List initial orgs",
			scopeId: scope.Global.String(),
			req:     &pbs.ListScopesRequest{ScopeId: "global"},
			res:     &pbs.ListScopesResponse{Items: initialOrgs},
			errCode: codes.OK,
		},
		{
			name:    "List No Projects",
			scopeId: oNoProjects.GetPublicId(),
			req:     &pbs.ListScopesRequest{ScopeId: oNoProjects.GetPublicId()},
			res:     &pbs.ListScopesResponse{},
			errCode: codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := scopes.NewService(repoFn)
			require.NoError(err, "Couldn't create new role service.")

			got, gErr := s.ListScopes(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "ListScopes(%+v) got error\n%v, wanted\n%v", tc.req, gErr, tc.errCode)
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListScopes(%q) got response\n%q\nwanted\n%q", tc.req, got, tc.res)
		})
	}

	var wantOrgs []*pb.Scope
	for i := 0; i < 10; i++ {
		newO, err := iam.NewOrg()
		require.NoError(t, err)
		o, err := repo.CreateScope(context.Background(), newO, "")
		require.NoError(t, err)
		wantOrgs = append(wantOrgs, &pb.Scope{
			Id:          o.GetPublicId(),
			Scope:       globalScope,
			CreatedTime: o.GetCreateTime().GetTimestamp(),
			UpdatedTime: o.GetUpdateTime().GetTimestamp(),
			Version:     1,
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
			Id:          p.GetPublicId(),
			Scope:       &pb.ScopeInfo{Id: oWithProjects.GetPublicId(), Type: scope.Org.String()},
			CreatedTime: p.GetCreateTime().GetTimestamp(),
			UpdatedTime: p.GetUpdateTime().GetTimestamp(),
			Version:     1,
		})
	}
	scopes.SortScopes(wantProjects)

	cases = []struct {
		name    string
		scopeId string
		req     *pbs.ListScopesRequest
		res     *pbs.ListScopesResponse
		errCode codes.Code
	}{
		{
			name:    "List Many Orgs",
			scopeId: scope.Global.String(),
			req:     &pbs.ListScopesRequest{ScopeId: "global"},
			res:     &pbs.ListScopesResponse{Items: wantOrgs},
			errCode: codes.OK,
		},
		{
			name:    "List Many Projects",
			scopeId: oWithProjects.GetPublicId(),
			req:     &pbs.ListScopesRequest{ScopeId: oWithProjects.GetPublicId()},
			res:     &pbs.ListScopesResponse{Items: wantProjects},
			errCode: codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := scopes.NewService(repoFn)
			require.NoError(err, "Couldn't create new role service.")

			got, gErr := s.ListScopes(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "ListScopes(%+v) got error\n%v, wanted\n%v", tc.req, gErr, tc.errCode)
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListScopes(%q) got response\n%q, wanted\n%q", tc.req, got, tc.res)
		})
	}
}

func TestDelete(t *testing.T) {
	require := require.New(t)
	org, proj, repo := createDefaultScopesAndRepo(t)

	s, err := scopes.NewService(repo)
	require.NoError(err, "Error when getting new project service.")

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.DeleteScopeRequest
		res     *pbs.DeleteScopeResponse
		errCode codes.Code
	}{
		{
			name:    "Delete an Existing Project",
			scopeId: org.GetPublicId(),
			req: &pbs.DeleteScopeRequest{
				Id: proj.GetPublicId(),
			},
			res: &pbs.DeleteScopeResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name:    "Delete bad project id Project",
			scopeId: org.GetPublicId(),
			req: &pbs.DeleteScopeRequest{
				Id: "p_doesntexis",
			},
			res: &pbs.DeleteScopeResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name:    "Bad Project Id formatting",
			scopeId: org.GetPublicId(),
			req: &pbs.DeleteScopeRequest{
				Id: "bad_format",
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "Delete an Existing Org",
			scopeId: scope.Global.String(),
			req: &pbs.DeleteScopeRequest{
				Id: org.GetPublicId(),
			},
			res: &pbs.DeleteScopeResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name:    "Delete bad org id Org",
			scopeId: scope.Global.String(),
			req: &pbs.DeleteScopeRequest{
				Id: "p_doesntexis",
			},
			res: &pbs.DeleteScopeResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name:    "Bad Org Id formatting",
			scopeId: scope.Global.String(),
			req: &pbs.DeleteScopeRequest{
				Id: "bad_format",
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.DeleteScope(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "DeleteScope(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.EqualValuesf(tc.res, got, "DeleteScope(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	org, proj, repo := createDefaultScopesAndRepo(t)

	s, err := scopes.NewService(repo)
	require.NoError(err, "Error when getting new scopes service")
	ctx := auth.DisabledAuthTestContext(auth.WithScopeId(org.GetPublicId()))
	req := &pbs.DeleteScopeRequest{
		Id: proj.GetPublicId(),
	}
	got, gErr := s.DeleteScope(ctx, req)
	assert.NoError(gErr, "First attempt")
	assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	got, gErr = s.DeleteScope(ctx, req)
	assert.NoError(gErr, "Second attempt")
	assert.False(got.GetExisted(), "Expected existed to be false for the second delete.")

	ctx = auth.DisabledAuthTestContext(auth.WithScopeId(scope.Global.String()))
	req = &pbs.DeleteScopeRequest{
		Id: org.GetPublicId(),
	}
	got, gErr = s.DeleteScope(ctx, req)
	assert.NoError(gErr, "First attempt")
	assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	got, gErr = s.DeleteScope(ctx, req)
	assert.NoError(gErr, "Second attempt")
	assert.False(got.GetExisted(), "Expected existed to be false for the second delete.")
}

func TestCreate(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)
	defaultOrg, defaultProj, repoFn := createDefaultScopesAndRepo(t)
	defaultProjCreated, err := ptypes.Timestamp(defaultProj.GetCreateTime().GetTimestamp())
	require.NoError(err, "Error converting proto to timestamp.")
	toMerge := &pbs.CreateScopeRequest{}

	repo, err := repoFn()
	require.NoError(err)
	globalUser, err := iam.NewUser(scope.Global.String())
	require.NoError(err)
	globalUser, err = repo.CreateUser(ctx, globalUser)
	require.NoError(err)
	orgUser, err := iam.NewUser(defaultOrg.GetPublicId())
	require.NoError(err)
	orgUser, err = repo.CreateUser(ctx, orgUser)
	require.NoError(err)

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.CreateScopeRequest
		res     *pbs.CreateScopeResponse
		errCode codes.Code
	}{
		{
			name:    "Create a valid Project",
			scopeId: defaultOrg.GetPublicId(),
			req: &pbs.CreateScopeRequest{
				ScopeId: defaultOrg.GetPublicId(),
				Item: &pb.Scope{
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.CreateScopeResponse{
				Uri: "scopes/p_",
				Item: &pb.Scope{
					Scope:       &pb.ScopeInfo{Id: defaultOrg.GetPublicId(), Type: scope.Org.String()},
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Version:     1,
				},
			},
			errCode: codes.OK,
		},
		{
			name:    "Create a valid Org",
			scopeId: scope.Global.String(),
			req: &pbs.CreateScopeRequest{
				ScopeId: scope.Global.String(),
				Item: &pb.Scope{
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.CreateScopeResponse{
				Uri: "scopes/o_",
				Item: &pb.Scope{
					Scope:       &pb.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String()},
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Version:     1,
				},
			},
			errCode: codes.OK,
		},
		{
			name:    "Can't specify Id",
			scopeId: defaultOrg.GetPublicId(),
			req: &pbs.CreateScopeRequest{Item: &pb.Scope{
				Id: "not allowed to be set",
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "Can't specify Created Time",
			scopeId: defaultOrg.GetPublicId(),
			req: &pbs.CreateScopeRequest{Item: &pb.Scope{
				CreatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "Can't specify Update Time",
			scopeId: defaultOrg.GetPublicId(),
			req: &pbs.CreateScopeRequest{Item: &pb.Scope{
				UpdatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		for _, withUserId := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-userid-%t", tc.name, withUserId), func(t *testing.T) {
				var name string
				if tc.req != nil && tc.req.GetItem() != nil && tc.req.GetItem().GetName() != nil {
					name = tc.req.GetItem().GetName().GetValue()
					localName := name
					defer func() {
						tc.res.GetItem().GetName().Value = localName
					}()
				}
				assert := assert.New(t)
				req := proto.Clone(toMerge).(*pbs.CreateScopeRequest)
				proto.Merge(req, tc.req)

				s, err := scopes.NewService(repoFn)
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
				got, gErr := s.CreateScope(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId), auth.WithUserId(userId)), req)
				assert.Equal(tc.errCode, status.Code(gErr), "CreateScope(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
				if got != nil {
					assert.Contains(got.GetUri(), tc.res.Uri)
					switch tc.scopeId {
					case "global":
						assert.True(strings.HasPrefix(got.GetItem().GetId(), "o_"))
					default:
						assert.True(strings.HasPrefix(got.GetItem().GetId(), "p_"))
					}
					gotCreateTime, err := ptypes.Timestamp(got.GetItem().GetCreatedTime())
					require.NoError(err, "Error converting proto to timestamp.")
					gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
					require.NoError(err, "Error converting proto to timestamp.")
					// Verify it is a project created after the test setup's default project
					assert.True(gotCreateTime.After(defaultProjCreated), "New scope should have been created after default project. Was created %v, which is after %v", gotCreateTime, defaultProjCreated)
					assert.True(gotUpdateTime.After(defaultProjCreated), "New scope should have been updated after default project. Was updated %v, which is after %v", gotUpdateTime, defaultProjCreated)

					if withUserId {
						repo, err := repoFn()
						require.NoError(err)
						roles, err := repo.ListRoles(ctx, got.GetItem().GetId())
						require.NoError(err)
						require.Len(roles, 1)
						role := roles[0]
						assert.Equal("on-scope-creation", role.GetName())
						assert.Equal(fmt.Sprintf("Role created for administration of scope %s at its creation time", got.GetItem().GetId()), role.GetDescription())
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
	require := require.New(t)
	org, proj, repoFn := createDefaultScopesAndRepo(t)
	tested, err := scopes.NewService(repoFn)
	require.NoError(err, "Error when getting new project service.")

	var orgVersion uint32 = 2
	var projVersion uint32 = 2

	resetOrg := func() {
		orgVersion++
		repo, err := repoFn()
		require.NoError(err, "Couldn't get a new repo")
		org, _, err = repo.UpdateScope(context.Background(), org, orgVersion, []string{"Name", "Description"})
		require.NoError(err, "Failed to reset the org")
		orgVersion++
	}

	resetProject := func() {
		projVersion++
		repo, err := repoFn()
		require.NoError(err, "Couldn't get a new repo")
		proj, _, err = repo.UpdateScope(context.Background(), proj, projVersion, []string{"Name", "Description"})
		require.NoError(err, "Failed to reset the project")
		projVersion++
	}

	projCreated, err := ptypes.Timestamp(proj.GetCreateTime().GetTimestamp())
	require.NoError(err, "Error converting proto to timestamp")
	projToMerge := &pbs.UpdateScopeRequest{
		Id: proj.GetPublicId(),
	}

	orgToMerge := &pbs.UpdateScopeRequest{
		Id: org.GetPublicId(),
	}

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.UpdateScopeRequest
		res     *pbs.UpdateScopeResponse
		errCode codes.Code
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
				},
			},
			res: &pbs.UpdateScopeResponse{
				Item: &pb.Scope{
					Id:          proj.GetPublicId(),
					Scope:       &pb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String()},
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: proj.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
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
				},
			},
			res: &pbs.UpdateScopeResponse{
				Item: &pb.Scope{
					Id:          org.GetPublicId(),
					Scope:       &pb.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String()},
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: org.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
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
					Id:          proj.GetPublicId(),
					Scope:       &pb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String()},
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: proj.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
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
			errCode: codes.InvalidArgument,
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
			errCode: codes.InvalidArgument,
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
			errCode: codes.InvalidArgument,
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
					Id:          proj.GetPublicId(),
					Scope:       &pb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String()},
					Description: &wrapperspb.StringValue{Value: "defaultProj"},
					CreatedTime: proj.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
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
					Id:          proj.GetPublicId(),
					Scope:       &pb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String()},
					Name:        &wrappers.StringValue{Value: "defaultProj"},
					CreatedTime: proj.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
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
					Id:          proj.GetPublicId(),
					Scope:       &pb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String()},
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "defaultProj"},
					CreatedTime: proj.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
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
					Id:          proj.GetPublicId(),
					Scope:       &pb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String()},
					Name:        &wrapperspb.StringValue{Value: "defaultProj"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
					CreatedTime: proj.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		// TODO: Updating a non existant project should result in a NotFound exception but currently results in
		// the repoFn returning an internal error.
		{
			name:    "Update a Non Existing Project",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				Id: "p_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Scope{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			errCode: codes.Internal,
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
					Scope:       &pb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String()},
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "new desc"},
				}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "Cant specify Created Time",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.Scope{
					CreatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "Cant specify Updated Time",
			scopeId: org.GetPublicId(),
			req: &pbs.UpdateScopeRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.Scope{
					UpdatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ver := orgVersion
			if tc.req.Id == proj.PublicId {
				ver = projVersion
			}
			tc.req.Version = ver

			assert := assert.New(t)
			var req *pbs.UpdateScopeRequest
			switch tc.scopeId {
			case scope.Global.String():
				req = proto.Clone(orgToMerge).(*pbs.UpdateScopeRequest)
				if tc.errCode == codes.OK {
					defer resetOrg()
				}
			default:
				ver = projVersion
				tc.req.Version = ver
				req = proto.Clone(projToMerge).(*pbs.UpdateScopeRequest)
				if tc.errCode == codes.OK {
					defer resetProject()
				}
			}
			proto.Merge(req, tc.req)

			got, gErr := tested.UpdateScope(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), req)
			assert.Equal(tc.errCode, status.Code(gErr), "UpdateScope(%+v) got error\n%v, wanted\n%v", req, gErr, tc.errCode)

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateScope response to be nil, but was %v", got)
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp")
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
