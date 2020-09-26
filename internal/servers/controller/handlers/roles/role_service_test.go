package roles_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/roles"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/roles"
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

func createDefaultRolesAndRepo(t *testing.T) (*iam.Role, *iam.Role, func() (*iam.Repository, error)) {
	t.Helper()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	o, p := iam.TestScopes(t, iamRepo)
	or := iam.TestRole(t, conn, o.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"), iam.WithGrantScopeId(p.GetPublicId()))
	pr := iam.TestRole(t, conn, p.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	return or, pr, repoFn
}

func equalPrincipals(role *pb.Role, principals []string) bool {
	if len(role.Principals) != len(principals) {
		return false
	}
	for _, principal := range principals {
		var foundInPrincipals bool
		var foundInPrincipalIds bool
		for _, v := range role.Principals {
			if v.Id == principal {
				foundInPrincipals = true
			}
		}
		for _, v := range role.PrincipalIds {
			if v == principal {
				foundInPrincipalIds = true
			}
		}
		if !foundInPrincipals || !foundInPrincipalIds {
			return false
		}
	}
	return true
}

func TestGet(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	or, pr, repo := createDefaultRolesAndRepo(t)
	toMerge := &pbs.GetRoleRequest{
		Id: or.GetPublicId(),
	}

	wantOrgRole := &pb.Role{
		Id:           or.GetPublicId(),
		ScopeId:      or.GetScopeId(),
		Scope:        &scopes.ScopeInfo{Id: or.GetScopeId(), Type: scope.Org.String()},
		Name:         &wrapperspb.StringValue{Value: or.GetName()},
		Description:  &wrapperspb.StringValue{Value: or.GetDescription()},
		GrantScopeId: &wrapperspb.StringValue{Value: pr.GetGrantScopeId()},
		CreatedTime:  or.CreateTime.GetTimestamp(),
		UpdatedTime:  or.UpdateTime.GetTimestamp(),
		Version:      or.GetVersion(),
	}

	wantProjRole := &pb.Role{
		Id:           pr.GetPublicId(),
		ScopeId:      pr.GetScopeId(),
		Scope:        &scopes.ScopeInfo{Id: pr.GetScopeId(), Type: scope.Project.String()},
		Name:         &wrapperspb.StringValue{Value: pr.GetName()},
		Description:  &wrapperspb.StringValue{Value: pr.GetDescription()},
		GrantScopeId: &wrapperspb.StringValue{Value: pr.GetGrantScopeId()},
		CreatedTime:  pr.CreateTime.GetTimestamp(),
		UpdatedTime:  pr.UpdateTime.GetTimestamp(),
		Version:      pr.GetVersion(),
	}

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.GetRoleRequest
		res     *pbs.GetRoleResponse
		err     error
	}{
		{
			name:    "Get an Existing Role",
			scopeId: or.GetScopeId(),
			req:     &pbs.GetRoleRequest{Id: or.GetPublicId()},
			res:     &pbs.GetRoleResponse{Item: wantOrgRole},
		},
		{
			name: "Get a non existant Role",
			req:  &pbs.GetRoleRequest{Id: iam.RolePrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Wrong id prefix",
			req:  &pbs.GetRoleRequest{Id: "j_1234567890"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "space in id",
			req:  &pbs.GetRoleRequest{Id: iam.RolePrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Project Scoped Get an Existing Role",
			scopeId: pr.GetScopeId(),
			req:     &pbs.GetRoleRequest{Id: pr.GetPublicId()},
			res:     &pbs.GetRoleResponse{Item: wantProjRole},
		},
		{
			name:    "Project Scoped Get a non existant Role",
			scopeId: pr.GetScopeId(),
			req:     &pbs.GetRoleRequest{Id: iam.RolePrefix + "_DoesntExis"},
			res:     nil,
			err:     handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Project Scoped Wrong id prefix",
			scopeId: pr.GetScopeId(),
			req:     &pbs.GetRoleRequest{Id: "j_1234567890"},
			res:     nil,
			err:     handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Project Scoped space in id",
			scopeId: pr.GetScopeId(),
			req:     &pbs.GetRoleRequest{Id: iam.RolePrefix + "_1 23456789"},
			res:     nil,
			err:     handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.GetRoleRequest)
			proto.Merge(req, tc.req)

			s, err := roles.NewService(repo)
			require.NoError(err, "Couldn't create new role service.")

			got, gErr := s.GetRole(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetRole(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetRole(%q) got response\n%q, wanted\n%q", req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	oNoRoles, pWithRoles := iam.TestScopes(t, iamRepo)
	oWithRoles, pNoRoles := iam.TestScopes(t, iamRepo)
	var wantOrgRoles []*pb.Role
	var wantProjRoles []*pb.Role
	for i := 0; i < 10; i++ {
		or := iam.TestRole(t, conn, oWithRoles.GetPublicId())
		wantOrgRoles = append(wantOrgRoles, &pb.Role{
			Id:           or.GetPublicId(),
			ScopeId:      or.GetScopeId(),
			Scope:        &scopes.ScopeInfo{Id: or.GetScopeId(), Type: scope.Org.String()},
			CreatedTime:  or.GetCreateTime().GetTimestamp(),
			UpdatedTime:  or.GetUpdateTime().GetTimestamp(),
			GrantScopeId: &wrapperspb.StringValue{Value: or.GetGrantScopeId()},
			Version:      or.GetVersion(),
		})
		pr := iam.TestRole(t, conn, pWithRoles.GetPublicId())
		wantProjRoles = append(wantProjRoles, &pb.Role{
			Id:           pr.GetPublicId(),
			ScopeId:      pr.GetScopeId(),
			Scope:        &scopes.ScopeInfo{Id: pr.GetScopeId(), Type: scope.Project.String()},
			CreatedTime:  pr.GetCreateTime().GetTimestamp(),
			UpdatedTime:  pr.GetUpdateTime().GetTimestamp(),
			GrantScopeId: &wrapperspb.StringValue{Value: pr.GetGrantScopeId()},
			Version:      pr.GetVersion(),
		})
	}

	cases := []struct {
		name string
		req  *pbs.ListRolesRequest
		res  *pbs.ListRolesResponse
	}{
		{
			name: "List Many Role",
			req:  &pbs.ListRolesRequest{ScopeId: oWithRoles.GetPublicId()},
			res:  &pbs.ListRolesResponse{Items: wantOrgRoles},
		},
		{
			name: "List No Roles",
			req:  &pbs.ListRolesRequest{ScopeId: oNoRoles.GetPublicId()},
			res:  &pbs.ListRolesResponse{},
		},
		{
			name: "List Many Project Role",
			req:  &pbs.ListRolesRequest{ScopeId: pWithRoles.GetPublicId()},
			res:  &pbs.ListRolesResponse{Items: wantProjRoles},
		},
		{
			name: "List No Project Roles",
			req:  &pbs.ListRolesRequest{ScopeId: pNoRoles.GetPublicId()},
			res:  &pbs.ListRolesResponse{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := roles.NewService(repoFn)
			require.NoError(err, "Couldn't create new role service.")

			got, gErr := s.ListRoles(auth.DisabledAuthTestContext(auth.WithScopeId(tc.req.GetScopeId())), tc.req)
			assert.NoError(gErr)
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListRoles(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete(t *testing.T) {
	or, pr, repo := createDefaultRolesAndRepo(t)

	s, err := roles.NewService(repo)
	require.NoError(t, err, "Error when getting new role service.")

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.DeleteRoleRequest
		res     *pbs.DeleteRoleResponse
		err     error
	}{
		{
			name:    "Delete an Existing Role",
			scopeId: or.GetPublicId(),
			req: &pbs.DeleteRoleRequest{
				Id: or.GetPublicId(),
			},
			res: &pbs.DeleteRoleResponse{},
		},
		{
			name:    "Delete bad role id",
			scopeId: or.GetPublicId(),
			req: &pbs.DeleteRoleRequest{
				Id: iam.RolePrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Delete default role",
			scopeId: "global",
			req: &pbs.DeleteRoleRequest{
				Id: "r_default",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Bad Role Id formatting",
			scopeId: or.GetPublicId(),
			req: &pbs.DeleteRoleRequest{
				Id: "bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Project Scoped Delete an Existing Role",
			scopeId: pr.GetPublicId(),
			req: &pbs.DeleteRoleRequest{
				Id: pr.GetPublicId(),
			},
			res: &pbs.DeleteRoleResponse{},
		},
		{
			name:    "Project Scoped Delete bad Role id",
			scopeId: pr.GetPublicId(),
			req: &pbs.DeleteRoleRequest{
				Id: iam.RolePrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteRole(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), tc.req)
			if tc.err != nil {
				require.NotNil(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteRole(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.EqualValuesf(tc.res, got, "DeleteRole(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	or, pr, repo := createDefaultRolesAndRepo(t)

	s, err := roles.NewService(repo)
	require.NoError(err, "Error when getting new role service")
	req := &pbs.DeleteRoleRequest{
		Id: or.GetPublicId(),
	}
	ctx := auth.DisabledAuthTestContext(auth.WithScopeId(or.GetPublicId()))
	_, gErr := s.DeleteRole(ctx, req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteRole(ctx, req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")

	projReq := &pbs.DeleteRoleRequest{
		Id: pr.GetPublicId(),
	}
	ctx = auth.DisabledAuthTestContext(auth.WithScopeId(pr.GetPublicId()))
	_, gErr = s.DeleteRole(ctx, projReq)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteRole(ctx, projReq)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")

}

func TestCreate(t *testing.T) {
	defaultOrgRole, defaultProjRole, repo := createDefaultRolesAndRepo(t)
	defaultCreated, err := ptypes.Timestamp(defaultOrgRole.GetCreateTime().GetTimestamp())
	require.NoError(t, err, "Error converting proto to timestamp.")
	toMerge := &pbs.CreateRoleRequest{}

	cases := []struct {
		name string
		req  *pbs.CreateRoleRequest
		res  *pbs.CreateRoleResponse
		err  error
	}{
		{
			name: "Create a valid Role",
			req: &pbs.CreateRoleRequest{Item: &pb.Role{
				ScopeId:      defaultOrgRole.GetScopeId(),
				Name:         &wrapperspb.StringValue{Value: "name"},
				Description:  &wrapperspb.StringValue{Value: "desc"},
				GrantScopeId: &wrapperspb.StringValue{Value: defaultProjRole.ScopeId},
			}},
			res: &pbs.CreateRoleResponse{
				Uri: fmt.Sprintf("roles/%s_", iam.RolePrefix),
				Item: &pb.Role{
					ScopeId:      defaultOrgRole.GetScopeId(),
					Scope:        &scopes.ScopeInfo{Id: defaultOrgRole.GetScopeId(), Type: scope.Org.String()},
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					GrantScopeId: &wrapperspb.StringValue{Value: defaultProjRole.ScopeId},
					Version:      1,
				},
			},
		},
		{
			name: "Create a valid Global Role",
			req: &pbs.CreateRoleRequest{Item: &pb.Role{
				ScopeId:      scope.Global.String(),
				Name:         &wrapperspb.StringValue{Value: "name"},
				Description:  &wrapperspb.StringValue{Value: "desc"},
				GrantScopeId: &wrapperspb.StringValue{Value: defaultProjRole.ScopeId},
			}},
			res: &pbs.CreateRoleResponse{
				Uri: fmt.Sprintf("roles/%s_", iam.RolePrefix),
				Item: &pb.Role{
					ScopeId:      scope.Global.String(),
					Scope:        &scopes.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String()},
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					GrantScopeId: &wrapperspb.StringValue{Value: defaultProjRole.ScopeId},
					Version:      1,
				},
			},
		},
		{
			name: "Create a valid Project Scoped Role",
			req: &pbs.CreateRoleRequest{
				Item: &pb.Role{
					ScopeId:     defaultProjRole.GetScopeId(),
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.CreateRoleResponse{
				Uri: fmt.Sprintf("roles/%s_", iam.RolePrefix),
				Item: &pb.Role{
					ScopeId:      defaultProjRole.GetScopeId(),
					Scope:        &scopes.ScopeInfo{Id: defaultProjRole.GetScopeId(), Type: scope.Project.String()},
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					GrantScopeId: &wrapperspb.StringValue{Value: defaultProjRole.ScopeId},
					Version:      1,
				},
			},
		},
		{
			name: "Invalid grant scope ID",
			req: &pbs.CreateRoleRequest{
				Item: &pb.Role{
					ScopeId:      defaultProjRole.GetScopeId(),
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					GrantScopeId: &wrapperspb.StringValue{Value: defaultOrgRole.GetScopeId()},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateRoleRequest{Item: &pb.Role{
				ScopeId: defaultProjRole.GetScopeId(),
				Id:      iam.RolePrefix + "_notallowed",
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateRoleRequest{Item: &pb.Role{
				ScopeId:     defaultProjRole.GetScopeId(),
				CreatedTime: ptypes.TimestampNow(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateRoleRequest{Item: &pb.Role{
				ScopeId:     defaultProjRole.GetScopeId(),
				UpdatedTime: ptypes.TimestampNow(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.CreateRoleRequest)
			proto.Merge(req, tc.req)

			s, err := roles.NewService(repo)
			require.NoError(err, "Error when getting new role service.")

			got, gErr := s.CreateRole(auth.DisabledAuthTestContext(auth.WithScopeId(tc.req.GetItem().GetScopeId())), req)
			if tc.err != nil {
				require.NotNil(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateRole(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				assert.True(strings.HasPrefix(got.GetItem().GetId(), iam.RolePrefix+"_"), "Expected %q to have the prefix %q", got.GetItem().GetId(), iam.RolePrefix+"_")
				gotCreateTime, err := ptypes.Timestamp(got.GetItem().GetCreatedTime())
				require.NoError(err, "Error converting proto to timestamp.")
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp.")
				// Verify it is a role created after the test setup's default role
				assert.True(gotCreateTime.After(defaultCreated), "New role should have been created after default role. Was created %v, which is after %v", gotCreateTime, defaultCreated)
				assert.True(gotUpdateTime.After(defaultCreated), "New role should have been updated after default role. Was updated %v, which is after %v", gotUpdateTime, defaultCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateRole(%q) got response\n%q, wanted\n%q", req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	grantString := "id=*;actions=*"
	g, err := perms.Parse("global", "", grantString)
	require.NoError(t, err)
	_, actions := g.Actions()
	grant := &pb.Grant{
		Raw:       grantString,
		Canonical: g.CanonicalString(),
		Json: &pb.GrantJson{
			Id:      g.Id(),
			Type:    g.Type().String(),
			Actions: actions,
		},
	}
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	o, p := iam.TestScopes(t, iamRepo)
	u := iam.TestUser(t, iamRepo, o.GetPublicId())

	or := iam.TestRole(t, conn, o.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"), iam.WithGrantScopeId(p.GetPublicId()))
	_ = iam.TestRoleGrant(t, conn, or.GetPublicId(), grantString)
	_ = iam.TestUserRole(t, conn, or.GetPublicId(), u.GetPublicId())

	pr := iam.TestRole(t, conn, p.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	_ = iam.TestRoleGrant(t, conn, pr.GetPublicId(), grantString)
	_ = iam.TestUserRole(t, conn, pr.GetPublicId(), u.GetPublicId())

	principal := &pb.Principal{
		Id:      u.GetPublicId(),
		Type:    iam.UserRoleType.String(),
		ScopeId: u.GetScopeId(),
	}

	var orVersion uint32 = 1
	var prVersion uint32 = 1

	tested, err := roles.NewService(repoFn)
	require.NoError(t, err, "Error when getting new role service.")

	resetRoles := func(proj bool) {
		repo, err := repoFn()
		require.NoError(t, err, "Couldn't get a new repo")
		if proj {
			prVersion++
			pr, _, _, _, err = repo.UpdateRole(context.Background(), pr, prVersion, []string{"Name", "Description"})
			require.NoError(t, err, "Failed to reset the role")
			prVersion++
		} else {
			orVersion++
			or, _, _, _, err = repo.UpdateRole(context.Background(), or, orVersion, []string{"Name", "Description"})
			require.NoError(t, err, "Failed to reset the role")
			orVersion++
		}
	}

	created, err := ptypes.Timestamp(or.GetCreateTime().GetTimestamp())
	require.NoError(t, err, "Error converting proto to timestamp")
	toMerge := &pbs.UpdateRoleRequest{
		Id: or.GetPublicId(),
	}

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.UpdateRoleRequest
		res     *pbs.UpdateRoleResponse
		err     error
	}{
		{
			name:    "Update an Existing Role",
			scopeId: or.GetScopeId(),
			req: &pbs.UpdateRoleRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description", "grant_scope_id"},
				},
				Item: &pb.Role{
					Name:         &wrapperspb.StringValue{Value: "new"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					GrantScopeId: &wrapperspb.StringValue{Value: or.GetScopeId()},
				},
			},
			res: &pbs.UpdateRoleResponse{
				Item: &pb.Role{
					Id:           or.GetPublicId(),
					ScopeId:      or.GetScopeId(),
					Scope:        &scopes.ScopeInfo{Id: or.GetScopeId(), Type: scope.Org.String()},
					Name:         &wrapperspb.StringValue{Value: "new"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:  or.GetCreateTime().GetTimestamp(),
					GrantScopeId: &wrapperspb.StringValue{Value: or.GetScopeId()},
					GrantStrings: []string{grant.GetRaw()},
					Grants:       []*pb.Grant{grant},
					PrincipalIds: []string{u.GetPublicId()},
					Principals:   []*pb.Principal{principal},
				},
			},
		},
		{
			name:    "Multiple Paths in single string",
			scopeId: or.GetScopeId(),
			req: &pbs.UpdateRoleRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.Role{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateRoleResponse{
				Item: &pb.Role{
					Id:           or.GetPublicId(),
					ScopeId:      or.GetScopeId(),
					Scope:        &scopes.ScopeInfo{Id: or.GetScopeId(), Type: scope.Org.String()},
					Name:         &wrapperspb.StringValue{Value: "new"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:  or.GetCreateTime().GetTimestamp(),
					GrantScopeId: &wrapperspb.StringValue{Value: or.GetScopeId()},
					GrantStrings: []string{grant.GetRaw()},
					Grants:       []*pb.Grant{grant},
					PrincipalIds: []string{u.GetPublicId()},
					Principals:   []*pb.Principal{principal},
				},
			},
		},
		{
			name:    "Update an Existing Project Scoped Role",
			scopeId: pr.GetScopeId(),
			req: &pbs.UpdateRoleRequest{
				Id: pr.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.Role{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateRoleResponse{
				Item: &pb.Role{
					Id:           pr.GetPublicId(),
					ScopeId:      pr.GetScopeId(),
					Scope:        &scopes.ScopeInfo{Id: pr.GetScopeId(), Type: scope.Project.String()},
					Name:         &wrapperspb.StringValue{Value: "new"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:  pr.GetCreateTime().GetTimestamp(),
					GrantScopeId: &wrapperspb.StringValue{Value: pr.GetScopeId()},
					GrantStrings: []string{grant.GetRaw()},
					Grants:       []*pb.Grant{grant},
					PrincipalIds: []string{u.GetPublicId()},
					Principals:   []*pb.Principal{principal},
				},
			},
		},
		{
			name:    "Multiple Paths in single string",
			scopeId: pr.GetScopeId(),
			req: &pbs.UpdateRoleRequest{
				Id: pr.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.Role{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateRoleResponse{
				Item: &pb.Role{
					Id:           pr.GetPublicId(),
					ScopeId:      pr.GetScopeId(),
					Scope:        &scopes.ScopeInfo{Id: pr.GetScopeId(), Type: scope.Project.String()},
					Name:         &wrapperspb.StringValue{Value: "new"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:  pr.GetCreateTime().GetTimestamp(),
					GrantScopeId: &wrapperspb.StringValue{Value: pr.GetScopeId()},
					GrantStrings: []string{grant.GetRaw()},
					Grants:       []*pb.Grant{grant},
					PrincipalIds: []string{u.GetPublicId()},
					Principals:   []*pb.Principal{principal},
				},
			},
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateRoleRequest{
				Item: &pb.Role{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "No Paths in Mask",
			scopeId: or.GetScopeId(),
			req: &pbs.UpdateRoleRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Role{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Only non-existant paths in Mask",
			scopeId: or.GetScopeId(),
			req: &pbs.UpdateRoleRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
				Item: &pb.Role{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Unset Name",
			scopeId: or.GetScopeId(),
			req: &pbs.UpdateRoleRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Role{
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateRoleResponse{
				Item: &pb.Role{
					Id:           or.GetPublicId(),
					ScopeId:      or.GetScopeId(),
					Scope:        &scopes.ScopeInfo{Id: or.GetScopeId(), Type: scope.Org.String()},
					Description:  &wrapperspb.StringValue{Value: "default"},
					CreatedTime:  or.GetCreateTime().GetTimestamp(),
					GrantScopeId: &wrapperspb.StringValue{Value: or.GetScopeId()},
					GrantStrings: []string{grant.GetRaw()},
					Grants:       []*pb.Grant{grant},
					PrincipalIds: []string{u.GetPublicId()},
					Principals:   []*pb.Principal{principal},
				},
			},
		},
		{
			name:    "Update Only Name",
			scopeId: or.GetScopeId(),
			req: &pbs.UpdateRoleRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Role{
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateRoleResponse{
				Item: &pb.Role{
					Id:           or.GetPublicId(),
					ScopeId:      or.GetScopeId(),
					Scope:        &scopes.ScopeInfo{Id: or.GetScopeId(), Type: scope.Org.String()},
					Name:         &wrapperspb.StringValue{Value: "updated"},
					Description:  &wrapperspb.StringValue{Value: "default"},
					CreatedTime:  or.GetCreateTime().GetTimestamp(),
					GrantScopeId: &wrapperspb.StringValue{Value: or.GetScopeId()},
					GrantStrings: []string{grant.GetRaw()},
					Grants:       []*pb.Grant{grant},
					PrincipalIds: []string{u.GetPublicId()},
					Principals:   []*pb.Principal{principal},
				},
			},
		},
		{
			name:    "Update Only Description",
			scopeId: or.GetScopeId(),
			req: &pbs.UpdateRoleRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Role{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
				},
			},
			res: &pbs.UpdateRoleResponse{
				Item: &pb.Role{
					Id:           or.GetPublicId(),
					ScopeId:      or.GetScopeId(),
					Scope:        &scopes.ScopeInfo{Id: or.GetScopeId(), Type: scope.Org.String()},
					Name:         &wrapperspb.StringValue{Value: "default"},
					Description:  &wrapperspb.StringValue{Value: "notignored"},
					CreatedTime:  or.GetCreateTime().GetTimestamp(),
					GrantScopeId: &wrapperspb.StringValue{Value: or.GetScopeId()},
					GrantStrings: []string{grant.GetRaw()},
					Grants:       []*pb.Grant{grant},
					PrincipalIds: []string{u.GetPublicId()},
					Principals:   []*pb.Principal{principal},
				},
			},
		},
		{
			name: "Update a Non Existing Role",
			req: &pbs.UpdateRoleRequest{
				Id: iam.RolePrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Role{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateRoleRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.Role{
					Id:          iam.RolePrefix + "_somethinge",
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "new desc"},
				}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateRoleRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.Role{
					CreatedTime: ptypes.TimestampNow(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateRoleRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.Role{
					UpdatedTime: ptypes.TimestampNow(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify grants",
			req: &pbs.UpdateRoleRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"grants"},
				},
				Item: &pb.Role{
					GrantStrings: []string{"anything"},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify principals",
			req: &pbs.UpdateRoleRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"principal_ids"},
				},
				Item: &pb.Role{
					PrincipalIds: []string{"u_0987654321"},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ver := orVersion
			if tc.req.Id == pr.PublicId {
				ver = prVersion
			}
			tc.req.Item.Version = ver

			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.UpdateRoleRequest)
			proto.Merge(req, tc.req)

			// Test with bad version (too high, too low)
			req.Item.Version = ver + 2
			_, gErr := tested.UpdateRole(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), req)
			require.Error(gErr)
			req.Item.Version = ver - 1
			_, gErr = tested.UpdateRole(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), req)
			require.Error(gErr)
			req.Item.Version = ver

			got, gErr := tested.UpdateRole(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateRole(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}

			if tc.err == nil {
				defer resetRoles(req.Id == pr.PublicId)
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateRole response to be nil, but was %v", got)
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp")
				// Verify it is a role updated after it was created
				assert.True(gotUpdateTime.After(created), "Updated role should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil

				assert.Equal(ver+1, got.GetItem().GetVersion())
				tc.res.Item.Version = ver + 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "UpdateRole(%q) got response\n%q,\nwanted\n%q", req, got, tc.res)
		})
	}
}

func TestAddPrincipal(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := roles.NewService(repoFn)
	require.NoError(t, err, "Error when getting new role service.")

	o, p := iam.TestScopes(t, iamRepo)
	users := []*iam.User{
		iam.TestUser(t, iamRepo, o.GetPublicId()),
		iam.TestUser(t, iamRepo, o.GetPublicId()),
		iam.TestUser(t, iamRepo, o.GetPublicId()),
	}
	groups := []*iam.Group{
		iam.TestGroup(t, conn, o.GetPublicId()),
		iam.TestGroup(t, conn, o.GetPublicId()),
		iam.TestGroup(t, conn, o.GetPublicId()),
	}

	addCases := []struct {
		name         string
		setup        func(*iam.Role)
		addUsers     []string
		addGroups    []string
		resultUsers  []string
		resultGroups []string
		wantErr      bool
	}{
		{
			name:        "Add user on empty role",
			setup:       func(r *iam.Role) {},
			addUsers:    []string{users[1].GetPublicId()},
			resultUsers: []string{users[1].GetPublicId()},
		},
		{
			name: "Add user on populated role",
			setup: func(r *iam.Role) {
				iam.TestUserRole(t, conn, r.GetPublicId(), users[0].GetPublicId())
			},
			addUsers:    []string{users[1].GetPublicId()},
			resultUsers: []string{users[0].GetPublicId(), users[1].GetPublicId()},
		},
		{
			name: "Add empty on populated role",
			setup: func(r *iam.Role) {
				iam.TestUserRole(t, conn, r.GetPublicId(), users[0].GetPublicId())
				iam.TestUserRole(t, conn, r.GetPublicId(), users[1].GetPublicId())
			},
			wantErr: true,
		},
		{
			name:         "Add group on empty role",
			setup:        func(r *iam.Role) {},
			addGroups:    []string{groups[1].GetPublicId()},
			resultGroups: []string{groups[1].GetPublicId()},
		},
		{
			name: "Add group on populated role",
			setup: func(r *iam.Role) {
				iam.TestGroupRole(t, conn, r.GetPublicId(), groups[0].GetPublicId())
			},
			addGroups:    []string{groups[1].GetPublicId()},
			resultGroups: []string{groups[0].GetPublicId(), groups[1].GetPublicId()},
		},
		{
			name:     "Add invalid u_recovery on role",
			setup:    func(r *iam.Role) {},
			addUsers: []string{"u_recovery"},
			wantErr:  true,
		},
	}

	for _, tc := range addCases {
		for _, scope := range []*iam.Scope{o, p} {
			t.Run(tc.name+"_"+scope.GetType(), func(t *testing.T) {
				role := iam.TestRole(t, conn, scope.GetPublicId())
				tc.setup(role)
				req := &pbs.AddRolePrincipalsRequest{
					Id:           role.GetPublicId(),
					Version:      role.GetVersion(),
					PrincipalIds: append(tc.addUsers, tc.addGroups...),
				}

				got, err := s.AddRolePrincipals(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), req)
				if tc.wantErr {
					assert.Error(t, err)
					return
				}
				s, ok := status.FromError(err)
				require.True(t, ok)
				require.NoError(t, err, "Got error: %v", s)

				assert.True(t, equalPrincipals(got.GetItem(), append(tc.resultUsers, tc.resultGroups...)))
			})
		}
	}

	role := iam.TestRole(t, conn, p.GetPublicId())

	failCases := []struct {
		name string
		req  *pbs.AddRolePrincipalsRequest
		err  error
	}{
		{
			name: "Bad Role Id",
			req: &pbs.AddRolePrincipalsRequest{
				Id:      "bad id",
				Version: role.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.AddRolePrincipals(auth.DisabledAuthTestContext(auth.WithScopeId(p.GetPublicId())), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "AddRolePrincipals(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestSetPrincipal(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := roles.NewService(repoFn)
	require.NoError(t, err, "Error when getting new role service.")

	o, p := iam.TestScopes(t, iamRepo)
	users := []*iam.User{
		iam.TestUser(t, iamRepo, o.GetPublicId()),
		iam.TestUser(t, iamRepo, o.GetPublicId()),
		iam.TestUser(t, iamRepo, o.GetPublicId()),
	}
	groups := []*iam.Group{
		iam.TestGroup(t, conn, o.GetPublicId()),
		iam.TestGroup(t, conn, o.GetPublicId()),
		iam.TestGroup(t, conn, o.GetPublicId()),
	}

	setCases := []struct {
		name         string
		setup        func(*iam.Role)
		setUsers     []string
		setGroups    []string
		resultUsers  []string
		resultGroups []string
		wantErr      bool
	}{
		{
			name:        "Set user on empty role",
			setup:       func(r *iam.Role) {},
			setUsers:    []string{users[1].GetPublicId()},
			resultUsers: []string{users[1].GetPublicId()},
		},
		{
			name: "Set user on populated role",
			setup: func(r *iam.Role) {
				iam.TestUserRole(t, conn, r.GetPublicId(), users[0].GetPublicId())
			},
			setUsers:    []string{users[1].GetPublicId()},
			resultUsers: []string{users[1].GetPublicId()},
		},
		{
			name: "Set empty on populated role",
			setup: func(r *iam.Role) {
				iam.TestUserRole(t, conn, r.GetPublicId(), users[0].GetPublicId())
				iam.TestUserRole(t, conn, r.GetPublicId(), users[1].GetPublicId())
			},
			setUsers:    []string{},
			resultUsers: nil,
		},
		{
			name:         "Set group on empty role",
			setup:        func(r *iam.Role) {},
			setGroups:    []string{groups[1].GetPublicId()},
			resultGroups: []string{groups[1].GetPublicId()},
		},
		{
			name: "Set group on populated role",
			setup: func(r *iam.Role) {
				iam.TestGroupRole(t, conn, r.GetPublicId(), groups[0].GetPublicId())
			},
			setGroups:    []string{groups[1].GetPublicId()},
			resultGroups: []string{groups[1].GetPublicId()},
		},
		{
			name:     "Set invalid u_recovery on role",
			setup:    func(r *iam.Role) {},
			setUsers: []string{"u_recovery"},
			wantErr:  true,
		},
	}

	for _, tc := range setCases {
		for _, scope := range []*iam.Scope{o, p} {
			t.Run(tc.name+"_"+scope.GetType(), func(t *testing.T) {
				role := iam.TestRole(t, conn, scope.GetPublicId())
				tc.setup(role)
				req := &pbs.SetRolePrincipalsRequest{
					Id:           role.GetPublicId(),
					Version:      role.GetVersion(),
					PrincipalIds: append(tc.setUsers, tc.setGroups...),
				}

				got, err := s.SetRolePrincipals(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), req)
				if tc.wantErr {
					assert.Error(t, err)
					return
				}
				s, ok := status.FromError(err)
				require.True(t, ok)
				require.NoError(t, err, "Got error: %v", s)

				assert.True(t, equalPrincipals(got.GetItem(), append(tc.resultUsers, tc.resultGroups...)))
			})
		}
	}

	role := iam.TestRole(t, conn, p.GetPublicId())

	failCases := []struct {
		name string
		req  *pbs.SetRolePrincipalsRequest
		err  error
	}{
		{
			name: "Bad Role Id",
			req: &pbs.SetRolePrincipalsRequest{
				Id:      "bad id",
				Version: role.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.SetRolePrincipals(auth.DisabledAuthTestContext(auth.WithScopeId(p.GetPublicId())), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "SetRolePrincipals(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestRemovePrincipal(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := roles.NewService(repoFn)
	require.NoError(t, err, "Error when getting new role service.")

	o, p := iam.TestScopes(t, iamRepo)
	users := []*iam.User{
		iam.TestUser(t, iamRepo, o.GetPublicId()),
		iam.TestUser(t, iamRepo, o.GetPublicId()),
		iam.TestUser(t, iamRepo, o.GetPublicId()),
	}
	groups := []*iam.Group{
		iam.TestGroup(t, conn, o.GetPublicId()),
		iam.TestGroup(t, conn, o.GetPublicId()),
		iam.TestGroup(t, conn, o.GetPublicId()),
	}

	addCases := []struct {
		name         string
		setup        func(*iam.Role)
		removeUsers  []string
		removeGroups []string
		resultUsers  []string
		resultGroups []string
		wantErr      bool
	}{
		{
			name:        "Remove user on empty role",
			setup:       func(r *iam.Role) {},
			removeUsers: []string{users[1].GetPublicId()},
			wantErr:     true,
		},
		{
			name: "Remove 1 of 2 users from role",
			setup: func(r *iam.Role) {
				iam.TestUserRole(t, conn, r.GetPublicId(), users[0].GetPublicId())
				iam.TestUserRole(t, conn, r.GetPublicId(), users[1].GetPublicId())
			},
			removeUsers: []string{users[1].GetPublicId()},
			resultUsers: []string{users[0].GetPublicId()},
		},
		{
			name: "Remove all users from role",
			setup: func(r *iam.Role) {
				iam.TestUserRole(t, conn, r.GetPublicId(), users[0].GetPublicId())
				iam.TestUserRole(t, conn, r.GetPublicId(), users[1].GetPublicId())
			},
			removeUsers: []string{users[0].GetPublicId(), users[1].GetPublicId()},
			resultUsers: []string{},
		},
		{
			name: "Remove empty on populated role",
			setup: func(r *iam.Role) {
				iam.TestUserRole(t, conn, r.GetPublicId(), users[0].GetPublicId())
			},
			wantErr: true,
		},
		{
			name:         "Remove group on empty role",
			setup:        func(r *iam.Role) {},
			removeGroups: []string{groups[1].GetPublicId()},
			wantErr:      true,
		},
		{
			name: "Remove 1 of 2 groups from role",
			setup: func(r *iam.Role) {
				iam.TestGroupRole(t, conn, r.GetPublicId(), groups[0].GetPublicId())
				iam.TestGroupRole(t, conn, r.GetPublicId(), groups[1].GetPublicId())
			},
			removeGroups: []string{groups[1].GetPublicId()},
			resultGroups: []string{groups[0].GetPublicId()},
		},
		{
			name: "Remove all groups from role",
			setup: func(r *iam.Role) {
				iam.TestGroupRole(t, conn, r.GetPublicId(), groups[0].GetPublicId())
				iam.TestGroupRole(t, conn, r.GetPublicId(), groups[1].GetPublicId())
			},
			removeGroups: []string{groups[0].GetPublicId(), groups[1].GetPublicId()},
			resultGroups: []string{},
		},
	}

	for _, tc := range addCases {
		for _, scope := range []*iam.Scope{o, p} {
			t.Run(tc.name+"_"+scope.GetType(), func(t *testing.T) {
				role := iam.TestRole(t, conn, scope.GetPublicId())
				tc.setup(role)
				req := &pbs.RemoveRolePrincipalsRequest{
					Id:           role.GetPublicId(),
					Version:      role.GetVersion(),
					PrincipalIds: append(tc.removeUsers, tc.removeGroups...),
				}

				got, err := s.RemoveRolePrincipals(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), req)
				if tc.wantErr {
					assert.Error(t, err)
					return
				}
				s, ok := status.FromError(err)
				require.True(t, ok)
				require.NoError(t, err, "Got error: %v", s)

				assert.True(t, equalPrincipals(got.GetItem(), append(tc.resultUsers, tc.resultGroups...)))
			})
		}
	}

	role := iam.TestRole(t, conn, p.GetPublicId())

	failCases := []struct {
		name string
		req  *pbs.AddRolePrincipalsRequest
		err  error
	}{
		{
			name: "Bad Role Id",
			req: &pbs.AddRolePrincipalsRequest{
				Id:      "bad id",
				Version: role.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.AddRolePrincipals(auth.DisabledAuthTestContext(auth.WithScopeId(p.GetPublicId())), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "AddRolePrincipals(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func checkEqualGrants(t *testing.T, expected []string, got *pb.Role) {
	require, assert := require.New(t), assert.New(t)
	require.Equal(len(expected), len(got.GrantStrings))
	require.Equal(len(expected), len(got.Grants))
	for i, v := range expected {
		parsed, err := perms.Parse("o_abc123", "", v)
		require.NoError(err)
		assert.Equal(expected[i], got.GrantStrings[i])
		assert.Equal(expected[i], got.Grants[i].GetRaw())
		assert.Equal(parsed.CanonicalString(), got.Grants[i].GetCanonical())
		j := got.Grants[i].GetJson()
		require.NotNil(j)
		assert.Equal(parsed.Id(), j.GetId())
		assert.Equal(parsed.Type().String(), j.GetType())
		_, acts := parsed.Actions()
		assert.Equal(acts, j.GetActions())
	}
}

func TestAddGrants(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := roles.NewService(repoFn)
	require.NoError(t, err, "Error when getting new role service.")

	addCases := []struct {
		name     string
		existing []string
		add      []string
		result   []string
		wantErr  bool
	}{
		{
			name:   "Add grant on empty role",
			add:    []string{"id=*;actions=delete"},
			result: []string{"id=*;actions=delete"},
		},
		{
			name:     "Add grant on role with grant",
			existing: []string{"id=1;actions=read"},
			add:      []string{"id=*;actions=delete"},
			result:   []string{"id=1;actions=read", "id=*;actions=delete"},
		},
		{
			name:     "Add grant matching existing grant",
			existing: []string{"id=1;actions=read", "id=*;actions=delete"},
			add:      []string{"id=*;actions=delete"},
			wantErr:  true,
		},
	}

	for _, tc := range addCases {
		o, p := iam.TestScopes(t, iamRepo)
		for _, scope := range []*iam.Scope{o, p} {
			t.Run(tc.name+"_"+scope.Type, func(t *testing.T) {
				assert, require := assert.New(t), require.New(t)
				role := iam.TestRole(t, conn, scope.GetPublicId())
				for _, e := range tc.existing {
					_ = iam.TestRoleGrant(t, conn, role.GetPublicId(), e)
				}
				req := &pbs.AddRoleGrantsRequest{
					Id:      role.GetPublicId(),
					Version: role.GetVersion(),
				}
				scopeId := o.GetPublicId()
				if o != scope {
					scopeId = p.GetPublicId()
				}
				req.GrantStrings = tc.add
				got, err := s.AddRoleGrants(auth.DisabledAuthTestContext(auth.WithScopeId(scopeId)), req)
				if tc.wantErr {
					assert.Error(err)
					return
				}
				require.NoError(err)
				checkEqualGrants(t, tc.result, got.GetItem())
			})
		}
	}

	_, p := iam.TestScopes(t, iamRepo)
	role := iam.TestRole(t, conn, p.GetPublicId())
	failCases := []struct {
		name string
		req  *pbs.AddRoleGrantsRequest
		err  error
	}{
		{
			name: "Bad Version",
			req: &pbs.AddRoleGrantsRequest{
				Id:           role.GetPublicId(),
				GrantStrings: []string{"id=*;actions=create"},
				Version:      role.GetVersion() + 2,
			},
			err: handlers.ApiErrorWithCode(codes.Internal),
		},
		{
			name: "Bad Role Id",
			req: &pbs.AddRoleGrantsRequest{
				Id:           "bad id",
				GrantStrings: []string{"id=*;actions=create"},
				Version:      role.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.AddRoleGrants(auth.DisabledAuthTestContext(auth.WithScopeId(p.GetPublicId())), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "AddRoleGrants(%+v) got error %#v, wanted %#v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestSetGrants(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	s, err := roles.NewService(repoFn)
	require.NoError(t, err, "Error when getting new role service.")

	setCases := []struct {
		name     string
		existing []string
		set      []string
		result   []string
		wantErr  bool
	}{
		{
			name:   "Set grant on empty role",
			set:    []string{"id=*;actions=delete"},
			result: []string{"id=*;actions=delete"},
		},
		{
			name:     "Set grant on role with grant",
			existing: []string{"id=1;actions=read"},
			set:      []string{"id=*;actions=delete"},
			result:   []string{"id=*;actions=delete"},
		},
		{
			name:     "Set grant matching existing grant",
			existing: []string{"id=1;actions=read", "id=*;actions=delete"},
			set:      []string{"id=*;actions=delete"},
			result:   []string{"id=*;actions=delete"},
		},
		{
			name:     "Set empty on role",
			existing: []string{"id=1;actions=read", "id=*;actions=delete"},
			set:      nil,
			result:   nil,
		},
	}

	for _, tc := range setCases {
		o, p := iam.TestScopes(t, iamRepo)
		for _, scope := range []*iam.Scope{o, p} {
			t.Run(tc.name+"_"+scope.Type, func(t *testing.T) {
				assert, require := assert.New(t), require.New(t)
				role := iam.TestRole(t, conn, scope.GetPublicId())
				for _, e := range tc.existing {
					_ = iam.TestRoleGrant(t, conn, role.GetPublicId(), e)
				}
				req := &pbs.SetRoleGrantsRequest{
					Id:      role.GetPublicId(),
					Version: role.GetVersion(),
				}
				scopeId := o.GetPublicId()
				if o != scope {
					scopeId = p.GetPublicId()
				}
				req.GrantStrings = tc.set
				got, err := s.SetRoleGrants(auth.DisabledAuthTestContext(auth.WithScopeId(scopeId)), req)
				if tc.wantErr {
					assert.Error(err)
					return
				}
				s, _ := status.FromError(err)
				require.NoError(err, "Got error %v", s)
				checkEqualGrants(t, tc.result, got.GetItem())
			})
		}
	}

	_, p := iam.TestScopes(t, iamRepo)
	role := iam.TestRole(t, conn, p.GetPublicId())

	failCases := []struct {
		name string
		req  *pbs.SetRoleGrantsRequest
		err  error
	}{
		{
			name: "Bad Version",
			req: &pbs.SetRoleGrantsRequest{
				Id:           role.GetPublicId(),
				GrantStrings: []string{"id=*;actions=create"},
				Version:      role.GetVersion() + 2,
			},
			err: handlers.ApiErrorWithCode(codes.Internal),
		},
		{
			name: "Bad Role Id",
			req: &pbs.SetRoleGrantsRequest{
				Id:           "bad id",
				GrantStrings: []string{"id=*;actions=create"},
				Version:      role.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.SetRoleGrants(auth.DisabledAuthTestContext(auth.WithScopeId(p.GetPublicId())), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "SetRoleGrants(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestRemoveGrants(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := roles.NewService(repoFn)
	require.NoError(t, err, "Error when getting new role service.")

	removeCases := []struct {
		name     string
		existing []string
		remove   []string
		result   []string
		wantErr  bool
	}{
		{
			name:     "Remove all",
			existing: []string{"id=1;actions=read"},
			remove:   []string{"id=1;actions=read"},
		},
		{
			name:     "Remove partial",
			existing: []string{"id=1;actions=read", "id=2;actions=delete"},
			remove:   []string{"id=1;actions=read"},
			result:   []string{"id=2;actions=delete"},
		},
		{
			name:     "Remove non existant",
			existing: []string{"id=2;actions=delete"},
			remove:   []string{"id=1;actions=read"},
			result:   []string{"id=2;actions=delete"},
		},
		{
			name:     "Remove from empty role",
			existing: []string{},
			remove:   []string{"id=1;actions=read"},
			result:   nil,
		},
	}

	for _, tc := range removeCases {
		o, p := iam.TestScopes(t, iamRepo)
		for _, scope := range []*iam.Scope{o, p} {
			t.Run(tc.name+"_"+scope.Type, func(t *testing.T) {
				assert, require := assert.New(t), require.New(t)
				role := iam.TestRole(t, conn, scope.GetPublicId())
				for _, e := range tc.existing {
					_ = iam.TestRoleGrant(t, conn, role.GetPublicId(), e)
				}
				req := &pbs.RemoveRoleGrantsRequest{
					Id:      role.GetPublicId(),
					Version: role.GetVersion(),
				}
				scopeId := o.GetPublicId()
				if o != scope {
					scopeId = p.GetPublicId()
				}
				req.GrantStrings = tc.remove
				got, err := s.RemoveRoleGrants(auth.DisabledAuthTestContext(auth.WithScopeId(scopeId)), req)
				if tc.wantErr {
					assert.Error(err)
					return
				}
				s, ok := status.FromError(err)
				assert.True(ok)
				require.NoError(err, "Got error %v", s)
				checkEqualGrants(t, tc.result, got.GetItem())
			})
		}
	}

	_, p := iam.TestScopes(t, iamRepo)
	role := iam.TestRole(t, conn, p.GetPublicId())
	failCases := []struct {
		name string
		req  *pbs.RemoveRoleGrantsRequest

		err error
	}{
		{
			name: "Bad Version",
			req: &pbs.RemoveRoleGrantsRequest{
				Id:           role.GetPublicId(),
				GrantStrings: []string{"id=*;actions=create"},
				Version:      role.GetVersion() + 2,
			},
			err: handlers.ApiErrorWithCode(codes.Internal),
		},
		{
			name: "Bad Role Id",
			req: &pbs.RemoveRoleGrantsRequest{
				Id:           "bad id",
				GrantStrings: []string{"id=*;actions=create"},
				Version:      role.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.RemoveRoleGrants(auth.DisabledAuthTestContext(auth.WithScopeId(p.GetPublicId())), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "RemoveRoleGrants(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}
