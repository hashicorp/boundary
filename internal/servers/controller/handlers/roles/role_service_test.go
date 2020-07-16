package roles_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/watchtower/internal/db"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/roles"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/perms"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/roles"
	"github.com/hashicorp/watchtower/internal/types/scope"
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
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
	}

	o, p := iam.TestScopes(t, conn)
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
	assert := assert.New(t)
	require := require.New(t)
	or, pr, repo := createDefaultRolesAndRepo(t)
	toMerge := &pbs.GetRoleRequest{
		OrgId: or.GetScopeId(),
		Id:    or.GetPublicId(),
	}

	wantOrgRole := &pb.Role{
		Id:           or.GetPublicId(),
		Name:         &wrapperspb.StringValue{Value: or.GetName()},
		Description:  &wrapperspb.StringValue{Value: or.GetDescription()},
		GrantScopeId: &wrapperspb.StringValue{Value: pr.GetGrantScopeId()},
		CreatedTime:  or.CreateTime.GetTimestamp(),
		UpdatedTime:  or.UpdateTime.GetTimestamp(),
		Version:      or.GetVersion(),
	}

	wantProjRole := &pb.Role{
		Id:           pr.GetPublicId(),
		Name:         &wrapperspb.StringValue{Value: pr.GetName()},
		Description:  &wrapperspb.StringValue{Value: pr.GetDescription()},
		GrantScopeId: &wrapperspb.StringValue{Value: pr.GetGrantScopeId()},
		CreatedTime:  pr.CreateTime.GetTimestamp(),
		UpdatedTime:  pr.UpdateTime.GetTimestamp(),
		Version:      pr.GetVersion(),
	}

	cases := []struct {
		name    string
		req     *pbs.GetRoleRequest
		res     *pbs.GetRoleResponse
		errCode codes.Code
	}{
		{
			name:    "Get an Existing Role",
			req:     &pbs.GetRoleRequest{Id: or.GetPublicId()},
			res:     &pbs.GetRoleResponse{Item: wantOrgRole},
			errCode: codes.OK,
		},
		{
			name:    "Get a non existant Role",
			req:     &pbs.GetRoleRequest{Id: iam.RolePrefix + "_DoesntExis"},
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Wrong id prefix",
			req:     &pbs.GetRoleRequest{Id: "j_1234567890"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "space in id",
			req:     &pbs.GetRoleRequest{Id: iam.RolePrefix + "_1 23456789"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "Project Scoped Get an Existing Role",
			req:     &pbs.GetRoleRequest{Id: pr.GetPublicId(), ProjectId: pr.GetScopeId()},
			res:     &pbs.GetRoleResponse{Item: wantProjRole},
			errCode: codes.OK,
		},
		{
			name:    "Project Scoped Get a non existant Role",
			req:     &pbs.GetRoleRequest{Id: iam.RolePrefix + "_DoesntExis", ProjectId: pr.GetScopeId()},
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Project Scoped Wrong id prefix",
			req:     &pbs.GetRoleRequest{Id: "j_1234567890", ProjectId: pr.GetScopeId()},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "Project Scoped space in id",
			req:     &pbs.GetRoleRequest{Id: iam.RolePrefix + "_1 23456789", ProjectId: pr.GetScopeId()},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.GetRoleRequest)
			proto.Merge(req, tc.req)

			s, err := roles.NewService(repo)
			require.NoError(err, "Couldn't create new role service.")

			got, gErr := s.GetRole(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetRole(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			assert.True(proto.Equal(got, tc.res), "GetRole(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
	}
	oNoRoles, pWithRoles := iam.TestScopes(t, conn)
	oWithRoles, pNoRoles := iam.TestScopes(t, conn)
	var wantOrgRoles []*pb.Role
	var wantProjRoles []*pb.Role
	for i := 0; i < 10; i++ {
		or := iam.TestRole(t, conn, oWithRoles.GetPublicId())
		wantOrgRoles = append(wantOrgRoles, &pb.Role{
			Id:           or.GetPublicId(),
			CreatedTime:  or.GetCreateTime().GetTimestamp(),
			UpdatedTime:  or.GetUpdateTime().GetTimestamp(),
			GrantScopeId: &wrapperspb.StringValue{Value: or.GetGrantScopeId()},
			Version:      or.GetVersion(),
		})
		pr := iam.TestRole(t, conn, pWithRoles.GetPublicId())
		wantProjRoles = append(wantProjRoles, &pb.Role{
			Id:           pr.GetPublicId(),
			CreatedTime:  pr.GetCreateTime().GetTimestamp(),
			UpdatedTime:  pr.GetUpdateTime().GetTimestamp(),
			GrantScopeId: &wrapperspb.StringValue{Value: pr.GetGrantScopeId()},
			Version:      pr.GetVersion(),
		})
	}

	cases := []struct {
		name    string
		req     *pbs.ListRolesRequest
		res     *pbs.ListRolesResponse
		errCode codes.Code
	}{
		{
			name:    "List Many Role",
			req:     &pbs.ListRolesRequest{OrgId: oWithRoles.GetPublicId()},
			res:     &pbs.ListRolesResponse{Items: wantOrgRoles},
			errCode: codes.OK,
		},
		{
			name:    "List No Roles",
			req:     &pbs.ListRolesRequest{OrgId: oNoRoles.GetPublicId()},
			res:     &pbs.ListRolesResponse{},
			errCode: codes.OK,
		},
		{
			name:    "Invalid Org Id",
			req:     &pbs.ListRolesRequest{OrgId: scope.Org.Prefix() + "_this is invalid"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		// TODO: When an org doesn't exist, we should return a 404 instead of an empty list.
		{
			name:    "Unfound Org",
			req:     &pbs.ListRolesRequest{OrgId: scope.Org.Prefix() + "_DoesntExis"},
			res:     &pbs.ListRolesResponse{},
			errCode: codes.OK,
		},
		{
			name:    "List Many Project Role",
			req:     &pbs.ListRolesRequest{OrgId: pWithRoles.GetParentId(), ProjectId: pWithRoles.GetPublicId()},
			res:     &pbs.ListRolesResponse{Items: wantProjRoles},
			errCode: codes.OK,
		},
		{
			name:    "List No Project Roles",
			req:     &pbs.ListRolesRequest{OrgId: pNoRoles.GetParentId(), ProjectId: pNoRoles.GetPublicId()},
			res:     &pbs.ListRolesResponse{},
			errCode: codes.OK,
		},
		{
			name:    "Invalid Project Id",
			req:     &pbs.ListRolesRequest{OrgId: oWithRoles.GetPublicId(), ProjectId: scope.Project.Prefix() + "_this is invalid"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		// TODO: When an org doesn't exist, we should return a 404 instead of an empty list.
		{
			name:    "Unfound Project",
			req:     &pbs.ListRolesRequest{OrgId: oWithRoles.GetPublicId(), ProjectId: scope.Project.Prefix() + "_DoesntExis"},
			res:     &pbs.ListRolesResponse{},
			errCode: codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := roles.NewService(repoFn)
			require.NoError(err, "Couldn't create new role service.")

			got, gErr := s.ListRoles(context.Background(), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "ListRoles(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.True(proto.Equal(got, tc.res), "ListRoles(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete(t *testing.T) {
	require := require.New(t)
	or, pr, repo := createDefaultRolesAndRepo(t)

	s, err := roles.NewService(repo)
	require.NoError(err, "Error when getting new role service.")

	cases := []struct {
		name    string
		req     *pbs.DeleteRoleRequest
		res     *pbs.DeleteRoleResponse
		errCode codes.Code
	}{
		{
			name: "Delete an Existing Role",
			req: &pbs.DeleteRoleRequest{
				OrgId: or.GetScopeId(),
				Id:    or.GetPublicId(),
			},
			res: &pbs.DeleteRoleResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name: "Delete bad role id",
			req: &pbs.DeleteRoleRequest{
				OrgId: or.GetScopeId(),
				Id:    iam.RolePrefix + "_doesntexis",
			},
			res: &pbs.DeleteRoleResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Delete bad org id",
			req: &pbs.DeleteRoleRequest{
				OrgId: "o_doesntexis",
				Id:    or.GetPublicId(),
			},
			res: &pbs.DeleteRoleResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Bad org formatting",
			req: &pbs.DeleteRoleRequest{
				OrgId: "bad_format",
				Id:    or.GetPublicId(),
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad Role Id formatting",
			req: &pbs.DeleteRoleRequest{
				OrgId: or.GetScopeId(),
				Id:    "bad_format",
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Project Scoped Delete an Existing Role",
			req: &pbs.DeleteRoleRequest{
				OrgId:     or.GetScopeId(),
				ProjectId: pr.GetScopeId(),
				Id:        pr.GetPublicId(),
			},
			res: &pbs.DeleteRoleResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name: "Project Scoped Delete bad Role id",
			req: &pbs.DeleteRoleRequest{
				OrgId:     or.GetScopeId(),
				ProjectId: pr.GetScopeId(),
				Id:        iam.RolePrefix + "_doesntexis",
			},
			res: &pbs.DeleteRoleResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Project Scoped Delete bad project id",
			req: &pbs.DeleteRoleRequest{
				OrgId:     or.GetScopeId(),
				ProjectId: scope.Project.Prefix() + "_doesntexis",
				Id:        pr.GetPublicId(),
			},
			res: &pbs.DeleteRoleResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Bad project formatting",
			req: &pbs.DeleteRoleRequest{
				OrgId:     or.GetScopeId(),
				ProjectId: "bad_format",
				Id:        pr.GetPublicId(),
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.DeleteRole(context.Background(), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "DeleteRole(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.EqualValuesf(tc.res, got, "DeleteRole(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	or, pr, repo := createDefaultRolesAndRepo(t)

	s, err := roles.NewService(repo)
	require.NoError(err, "Error when getting new role service")
	req := &pbs.DeleteRoleRequest{
		OrgId: or.GetScopeId(),
		Id:    or.GetPublicId(),
	}
	got, gErr := s.DeleteRole(context.Background(), req)
	assert.NoError(gErr, "First attempt")
	assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	got, gErr = s.DeleteRole(context.Background(), req)
	assert.NoError(gErr, "Second attempt")
	assert.False(got.GetExisted(), "Expected existed to be false for the second delete.")

	projReq := &pbs.DeleteRoleRequest{
		OrgId:     or.GetScopeId(),
		ProjectId: pr.GetScopeId(),
		Id:        pr.GetPublicId(),
	}
	got, gErr = s.DeleteRole(context.Background(), projReq)
	assert.NoError(gErr, "First attempt")
	assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	got, gErr = s.DeleteRole(context.Background(), projReq)
	assert.NoError(gErr, "Second attempt")
	assert.False(got.GetExisted(), "Expected existed to be false for the second delete.")

}

func TestCreate(t *testing.T) {
	require := require.New(t)
	defaultOrgRole, defaultProjRole, repo := createDefaultRolesAndRepo(t)
	defaultCreated, err := ptypes.Timestamp(defaultOrgRole.GetCreateTime().GetTimestamp())
	require.NoError(err, "Error converting proto to timestamp.")
	toMerge := &pbs.CreateRoleRequest{
		OrgId: defaultOrgRole.GetScopeId(),
	}

	cases := []struct {
		name    string
		req     *pbs.CreateRoleRequest
		res     *pbs.CreateRoleResponse
		errCode codes.Code
	}{
		{
			name: "Create a valid Role",
			req: &pbs.CreateRoleRequest{Item: &pb.Role{
				Name:         &wrapperspb.StringValue{Value: "name"},
				Description:  &wrapperspb.StringValue{Value: "desc"},
				GrantScopeId: &wrapperspb.StringValue{Value: defaultProjRole.ScopeId},
			}},
			res: &pbs.CreateRoleResponse{
				Uri: fmt.Sprintf("orgs/%s/roles/%s_", defaultOrgRole.GetScopeId(), iam.RolePrefix),
				Item: &pb.Role{
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					GrantScopeId: &wrapperspb.StringValue{Value: defaultProjRole.ScopeId},
					Version:      1,
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Create a valid Project Scoped Role",
			req: &pbs.CreateRoleRequest{
				ProjectId: defaultProjRole.GetScopeId(),
				Item: &pb.Role{
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.CreateRoleResponse{
				Uri: fmt.Sprintf("orgs/%s/projects/%s/roles/%s_", defaultOrgRole.GetScopeId(), defaultProjRole.GetScopeId(), iam.RolePrefix),
				Item: &pb.Role{
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					GrantScopeId: &wrapperspb.StringValue{Value: defaultProjRole.ScopeId},
					Version:      1,
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Invalid grant scope ID",
			req: &pbs.CreateRoleRequest{
				ProjectId: defaultProjRole.GetScopeId(),
				Item: &pb.Role{
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					GrantScopeId: &wrapperspb.StringValue{Value: defaultOrgRole.GetScopeId()},
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateRoleRequest{Item: &pb.Role{
				Id: iam.RolePrefix + "_notallowed",
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateRoleRequest{Item: &pb.Role{
				CreatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateRoleRequest{Item: &pb.Role{
				UpdatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			req := proto.Clone(toMerge).(*pbs.CreateRoleRequest)
			proto.Merge(req, tc.req)

			s, err := roles.NewService(repo)
			require.NoError(err, "Error when getting new role service.")

			got, gErr := s.CreateRole(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "CreateRole(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			if got != nil {
				assert.True(strings.HasPrefix(got.GetUri(), tc.res.Uri), "Expected %q to have the prefix %q", got.GetUri(), tc.res.GetUri())
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
			assert.True(proto.Equal(got, tc.res), "CreateRole(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	grantString := "id=*;actions=*"
	parsedGrant, err := perms.Parse("global", "", grantString)
	require.NoError(t, err)
	jsonGrant, err := parsedGrant.MarshalJSON()
	require.NoError(t, err)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
	}

	o, p := iam.TestScopes(t, conn)
	u := iam.TestUser(t, conn, o.GetPublicId())

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

	tested, err := roles.NewService(repoFn)
	require.NoError(t, err, "Error when getting new role service.")

	resetRoles := func() {
		repo, err := repoFn()
		require.NoError(t, err, "Couldn't get a new repo")
		or, _, _, _, err = repo.UpdateRole(context.Background(), or, []string{"Name", "Description"})
		require.NoError(t, err, "Failed to reset the role")
		pr, _, _, _, err = repo.UpdateRole(context.Background(), pr, []string{"Name", "Description"})
		require.NoError(t, err, "Failed to reset the role")
	}

	created, err := ptypes.Timestamp(or.GetCreateTime().GetTimestamp())
	require.NoError(t, err, "Error converting proto to timestamp")
	toMerge := &pbs.UpdateRoleRequest{
		OrgId: or.GetScopeId(),
		Id:    or.GetPublicId(),
	}

	cases := []struct {
		name    string
		req     *pbs.UpdateRoleRequest
		res     *pbs.UpdateRoleResponse
		errCode codes.Code
	}{
		{
			name: "Update an Existing Role",
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
					Id:              or.GetPublicId(),
					Name:            &wrapperspb.StringValue{Value: "new"},
					Description:     &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:     or.GetCreateTime().GetTimestamp(),
					GrantScopeId:    &wrapperspb.StringValue{Value: or.GetScopeId()},
					Grants:          []string{grantString},
					GrantsCanonical: []string{grantString},
					GrantsJson:      []string{string(jsonGrant)},
					PrincipalIds:    []string{u.GetPublicId()},
					Principals:      []*pb.Principal{principal},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Multiple Paths in single string",
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
					Id:              or.GetPublicId(),
					Name:            &wrapperspb.StringValue{Value: "new"},
					Description:     &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:     or.GetCreateTime().GetTimestamp(),
					GrantScopeId:    &wrapperspb.StringValue{Value: or.GetScopeId()},
					Grants:          []string{grantString},
					GrantsCanonical: []string{grantString},
					GrantsJson:      []string{string(jsonGrant)},
					PrincipalIds:    []string{u.GetPublicId()},
					Principals:      []*pb.Principal{principal},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update an Existing Project Scoped Role",
			req: &pbs.UpdateRoleRequest{
				ProjectId: pr.GetScopeId(),
				Id:        pr.GetPublicId(),
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
					Id:              pr.GetPublicId(),
					Name:            &wrapperspb.StringValue{Value: "new"},
					Description:     &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:     pr.GetCreateTime().GetTimestamp(),
					GrantScopeId:    &wrapperspb.StringValue{Value: pr.GetScopeId()},
					Grants:          []string{grantString},
					GrantsCanonical: []string{grantString},
					GrantsJson:      []string{string(jsonGrant)},
					PrincipalIds:    []string{u.GetPublicId()},
					Principals:      []*pb.Principal{principal},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateRoleRequest{
				ProjectId: pr.GetScopeId(),
				Id:        pr.GetPublicId(),
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
					Id:              pr.GetPublicId(),
					Name:            &wrapperspb.StringValue{Value: "new"},
					Description:     &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:     pr.GetCreateTime().GetTimestamp(),
					GrantScopeId:    &wrapperspb.StringValue{Value: pr.GetScopeId()},
					Grants:          []string{grantString},
					GrantsCanonical: []string{grantString},
					GrantsJson:      []string{string(jsonGrant)},
					PrincipalIds:    []string{u.GetPublicId()},
					Principals:      []*pb.Principal{principal},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateRoleRequest{
				Item: &pb.Role{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "No Paths in Mask",
			req: &pbs.UpdateRoleRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Role{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Only non-existant paths in Mask",
			req: &pbs.UpdateRoleRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
				Item: &pb.Role{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Unset Name",
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
					Id:              or.GetPublicId(),
					Description:     &wrapperspb.StringValue{Value: "default"},
					CreatedTime:     or.GetCreateTime().GetTimestamp(),
					GrantScopeId:    &wrapperspb.StringValue{Value: or.GetScopeId()},
					Grants:          []string{grantString},
					GrantsCanonical: []string{grantString},
					GrantsJson:      []string{string(jsonGrant)},
					PrincipalIds:    []string{u.GetPublicId()},
					Principals:      []*pb.Principal{principal},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Name",
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
					Id:              or.GetPublicId(),
					Name:            &wrapperspb.StringValue{Value: "updated"},
					Description:     &wrapperspb.StringValue{Value: "default"},
					CreatedTime:     or.GetCreateTime().GetTimestamp(),
					GrantScopeId:    &wrapperspb.StringValue{Value: or.GetScopeId()},
					Grants:          []string{grantString},
					GrantsCanonical: []string{grantString},
					GrantsJson:      []string{string(jsonGrant)},
					PrincipalIds:    []string{u.GetPublicId()},
					Principals:      []*pb.Principal{principal},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Description",
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
					Id:              or.GetPublicId(),
					Name:            &wrapperspb.StringValue{Value: "default"},
					Description:     &wrapperspb.StringValue{Value: "notignored"},
					CreatedTime:     or.GetCreateTime().GetTimestamp(),
					GrantScopeId:    &wrapperspb.StringValue{Value: or.GetScopeId()},
					Grants:          []string{grantString},
					GrantsCanonical: []string{grantString},
					GrantsJson:      []string{string(jsonGrant)},
					PrincipalIds:    []string{u.GetPublicId()},
					Principals:      []*pb.Principal{principal},
				},
			},
			errCode: codes.OK,
		},
		// TODO: Updating a non existant role should result in a NotFound exception but currently results in
		// the repoFn returning an internal error.
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
			errCode: codes.Internal,
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateRoleRequest{
				Id: or.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.Role{
					Id:          iam.RolePrefix + "_somethinge",
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "new desc"},
				}},
			res:     nil,
			errCode: codes.InvalidArgument,
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
			res:     nil,
			errCode: codes.InvalidArgument,
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
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify grants",
			req: &pbs.UpdateRoleRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"grants"},
				},
				Item: &pb.Role{
					Grants: []string{"anything"},
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
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
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer resetRoles()
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.UpdateRoleRequest)
			proto.Merge(req, tc.req)

			got, gErr := tested.UpdateRole(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "UpdateRole(%+v) got error %v, wanted %v", req, gErr, tc.errCode)

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateRole response to be nil, but was %v", got)
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp")
				// Verify it is a role updated after it was created
				assert.True(gotUpdateTime.After(created), "Updated role should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil

				// TODO: Figure out the best way to test versions when updating roles
				got.GetItem().Version = 0
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "UpdateRole(%q) got response\n%q,\nwanted\n%q", req, got, tc.res)
		})
	}
}

func TestAddPrincipal(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
	}
	s, err := roles.NewService(repoFn)
	require.NoError(t, err, "Error when getting new role service.")

	o, p := iam.TestScopes(t, conn)
	users := []*iam.User{
		iam.TestUser(t, conn, o.GetPublicId()),
		iam.TestUser(t, conn, o.GetPublicId()),
		iam.TestUser(t, conn, o.GetPublicId()),
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
	}

	for _, tc := range addCases {
		for _, scope := range []*iam.Scope{o, p} {
			t.Run(tc.name+"_"+scope.GetType(), func(t *testing.T) {
				role := iam.TestRole(t, conn, scope.GetPublicId())
				tc.setup(role)
				req := &pbs.AddRolePrincipalsRequest{
					OrgId:        o.GetPublicId(),
					RoleId:       role.GetPublicId(),
					Version:      &wrapperspb.UInt32Value{Value: role.GetVersion()},
					PrincipalIds: append(tc.addUsers, tc.addGroups...),
				}

				got, err := s.AddRolePrincipals(context.Background(), req)
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
		name    string
		req     *pbs.AddRolePrincipalsRequest
		errCode codes.Code
	}{
		{
			name: "Bad Org Id",
			req: &pbs.AddRolePrincipalsRequest{
				OrgId:     "",
				ProjectId: role.GetScopeId(),
				RoleId:    role.GetPublicId(),
				Version:   &wrapperspb.UInt32Value{Value: role.GetVersion()},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad Project Id",
			req: &pbs.AddRolePrincipalsRequest{
				OrgId:     o.GetPublicId(),
				ProjectId: "bad id",
				RoleId:    role.GetPublicId(),
				Version:   &wrapperspb.UInt32Value{Value: role.GetVersion()},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad Role Id",
			req: &pbs.AddRolePrincipalsRequest{
				OrgId:     o.GetPublicId(),
				ProjectId: role.GetScopeId(),
				RoleId:    "bad id",
				Version:   &wrapperspb.UInt32Value{Value: role.GetVersion()},
			},
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			_, gErr := s.AddRolePrincipals(context.Background(), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "AddRolePrincipals(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
		})
	}
}

func TestSetPrincipal(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
	}
	s, err := roles.NewService(repoFn)
	require.NoError(t, err, "Error when getting new role service.")

	o, p := iam.TestScopes(t, conn)
	users := []*iam.User{
		iam.TestUser(t, conn, o.GetPublicId()),
		iam.TestUser(t, conn, o.GetPublicId()),
		iam.TestUser(t, conn, o.GetPublicId()),
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
	}

	for _, tc := range setCases {
		for _, scope := range []*iam.Scope{o, p} {
			t.Run(tc.name+"_"+scope.GetType(), func(t *testing.T) {
				role := iam.TestRole(t, conn, scope.GetPublicId())
				tc.setup(role)
				req := &pbs.SetRolePrincipalsRequest{
					OrgId:        o.GetPublicId(),
					RoleId:       role.GetPublicId(),
					Version:      &wrapperspb.UInt32Value{Value: role.GetVersion()},
					PrincipalIds: append(tc.setUsers, tc.setGroups...),
				}

				got, err := s.SetRolePrincipals(context.Background(), req)
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
		name    string
		req     *pbs.SetRolePrincipalsRequest
		errCode codes.Code
	}{
		{
			name: "Bad Org Id",
			req: &pbs.SetRolePrincipalsRequest{
				OrgId:     "",
				ProjectId: role.GetScopeId(),
				RoleId:    role.GetPublicId(),
				Version:   &wrapperspb.UInt32Value{Value: role.GetVersion()},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad Project Id",
			req: &pbs.SetRolePrincipalsRequest{
				OrgId:     o.GetPublicId(),
				ProjectId: "bad id",
				RoleId:    role.GetPublicId(),
				Version:   &wrapperspb.UInt32Value{Value: role.GetVersion()},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad Role Id",
			req: &pbs.SetRolePrincipalsRequest{
				OrgId:     o.GetPublicId(),
				ProjectId: role.GetScopeId(),
				RoleId:    "bad id",
				Version:   &wrapperspb.UInt32Value{Value: role.GetVersion()},
			},
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			_, gErr := s.SetRolePrincipals(context.Background(), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "SetRolePrincipals(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
		})
	}
}

func TestRemovePrincipal(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
	}
	s, err := roles.NewService(repoFn)
	require.NoError(t, err, "Error when getting new role service.")

	o, p := iam.TestScopes(t, conn)
	users := []*iam.User{
		iam.TestUser(t, conn, o.GetPublicId()),
		iam.TestUser(t, conn, o.GetPublicId()),
		iam.TestUser(t, conn, o.GetPublicId()),
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
					OrgId:        o.GetPublicId(),
					RoleId:       role.GetPublicId(),
					Version:      &wrapperspb.UInt32Value{Value: role.GetVersion()},
					PrincipalIds: append(tc.removeUsers, tc.removeGroups...),
				}

				got, err := s.RemoveRolePrincipals(context.Background(), req)
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
		name    string
		req     *pbs.AddRolePrincipalsRequest
		errCode codes.Code
	}{
		{
			name: "Bad Org Id",
			req: &pbs.AddRolePrincipalsRequest{
				OrgId:     "",
				ProjectId: role.GetScopeId(),
				RoleId:    role.GetPublicId(),
				Version:   &wrapperspb.UInt32Value{Value: role.GetVersion()},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad Project Id",
			req: &pbs.AddRolePrincipalsRequest{
				OrgId:     o.GetPublicId(),
				ProjectId: "bad id",
				RoleId:    role.GetPublicId(),
				Version:   &wrapperspb.UInt32Value{Value: role.GetVersion()},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad Role Id",
			req: &pbs.AddRolePrincipalsRequest{
				OrgId:     o.GetPublicId(),
				ProjectId: role.GetScopeId(),
				RoleId:    "bad id",
				Version:   &wrapperspb.UInt32Value{Value: role.GetVersion()},
			},
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			_, gErr := s.AddRolePrincipals(context.Background(), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "AddRolePrincipals(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
		})
	}
}

func TestAddGrants(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
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
		o, p := iam.TestScopes(t, conn)
		for _, scope := range []*iam.Scope{o, p} {
			t.Run(tc.name+"_"+scope.Type, func(t *testing.T) {
				assert := assert.New(t)
				role := iam.TestRole(t, conn, scope.GetPublicId())
				for _, e := range tc.existing {
					_ = iam.TestRoleGrant(t, conn, role.GetPublicId(), e)
				}
				req := &pbs.AddRoleGrantsRequest{
					OrgId:   o.GetPublicId(),
					RoleId:  role.GetPublicId(),
					Version: &wrapperspb.UInt32Value{Value: role.GetVersion()},
				}
				if o != scope {
					req.ProjectId = scope.GetPublicId()
				}
				req.Grants = append(req.Grants, tc.add...)
				got, err := s.AddRoleGrants(context.Background(), req)
				if tc.wantErr {
					assert.Error(err)
					return
				}
				s, _ := status.FromError(err)
				require.NoError(t, err, "Got error %v", s)
				assert.Equal(tc.result, got.GetItem().GetGrants())
			})
		}
	}

	o, p := iam.TestScopes(t, conn)
	role := iam.TestRole(t, conn, p.GetPublicId())
	failCases := []struct {
		name    string
		req     *pbs.AddRoleGrantsRequest
		errCode codes.Code
	}{
		{
			name: "Bad Org Id",
			req: &pbs.AddRoleGrantsRequest{
				OrgId:     "",
				ProjectId: role.GetScopeId(),
				RoleId:    role.GetPublicId(),
				Grants:    []string{"id=*;actions=create"},
				Version:   &wrapperspb.UInt32Value{Value: role.GetVersion()},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad Project Id",
			req: &pbs.AddRoleGrantsRequest{
				OrgId:     o.GetPublicId(),
				ProjectId: "bad id",
				RoleId:    role.GetPublicId(),
				Grants:    []string{"id=*;actions=create"},
				Version:   &wrapperspb.UInt32Value{Value: role.GetVersion()},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad Role Id",
			req: &pbs.AddRoleGrantsRequest{
				OrgId:     o.GetPublicId(),
				ProjectId: role.GetScopeId(),
				RoleId:    "bad id",
				Grants:    []string{"id=*;actions=create"},
				Version:   &wrapperspb.UInt32Value{Value: role.GetVersion()},
			},
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			_, gErr := s.AddRoleGrants(context.Background(), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "AddRoleGrants(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
		})
	}
}

func TestSetGrants(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
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
		o, p := iam.TestScopes(t, conn)
		for _, scope := range []*iam.Scope{o, p} {
			t.Run(tc.name+"_"+scope.Type, func(t *testing.T) {
				assert := assert.New(t)
				role := iam.TestRole(t, conn, scope.GetPublicId())
				for _, e := range tc.existing {
					_ = iam.TestRoleGrant(t, conn, role.GetPublicId(), e)
				}
				req := &pbs.SetRoleGrantsRequest{
					OrgId:   o.GetPublicId(),
					RoleId:  role.GetPublicId(),
					Version: &wrapperspb.UInt32Value{Value: role.GetVersion()},
				}
				if o != scope {
					req.ProjectId = scope.GetPublicId()
				}
				req.Grants = append(req.Grants, tc.set...)
				got, err := s.SetRoleGrants(context.Background(), req)
				if tc.wantErr {
					assert.Error(err)
					return
				}
				s, _ := status.FromError(err)
				require.NoError(t, err, "Got error %v", s)
				assert.Equal(tc.result, got.GetItem().GetGrants())
			})
		}
	}

	o, p := iam.TestScopes(t, conn)
	role := iam.TestRole(t, conn, p.GetPublicId())

	failCases := []struct {
		name    string
		req     *pbs.SetRoleGrantsRequest
		errCode codes.Code
	}{
		{
			name: "Bad Org Id",
			req: &pbs.SetRoleGrantsRequest{
				OrgId:     "",
				ProjectId: role.GetScopeId(),
				RoleId:    role.GetPublicId(),
				Grants:    []string{"id=*;actions=create"},
				Version:   &wrapperspb.UInt32Value{Value: role.GetVersion()},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad Project Id",
			req: &pbs.SetRoleGrantsRequest{
				OrgId:     o.GetPublicId(),
				ProjectId: "bad id",
				RoleId:    role.GetPublicId(),
				Grants:    []string{"id=*;actions=create"},
				Version:   &wrapperspb.UInt32Value{Value: role.GetVersion()},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad Role Id",
			req: &pbs.SetRoleGrantsRequest{
				OrgId:     o.GetPublicId(),
				ProjectId: role.GetScopeId(),
				RoleId:    "bad id",
				Grants:    []string{"id=*;actions=create"},
				Version:   &wrapperspb.UInt32Value{Value: role.GetVersion()},
			},
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			_, gErr := s.SetRoleGrants(context.Background(), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "SetRoleGrants(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
		})
	}
}

func TestRemoveGrants(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
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
		o, p := iam.TestScopes(t, conn)
		for _, scope := range []*iam.Scope{o, p} {
			t.Run(tc.name+"_"+scope.Type, func(t *testing.T) {
				assert := assert.New(t)
				role := iam.TestRole(t, conn, scope.GetPublicId())
				for _, e := range tc.existing {
					_ = iam.TestRoleGrant(t, conn, role.GetPublicId(), e)
				}
				req := &pbs.RemoveRoleGrantsRequest{
					OrgId:   o.GetPublicId(),
					RoleId:  role.GetPublicId(),
					Version: &wrapperspb.UInt32Value{Value: role.GetVersion()},
				}
				if o != scope {
					req.ProjectId = scope.GetPublicId()
				}
				req.Grants = append(req.Grants, tc.remove...)
				got, err := s.RemoveRoleGrants(context.Background(), req)
				if tc.wantErr {
					assert.Error(err)
					return
				}
				s, ok := status.FromError(err)
				assert.True(ok)
				require.NoError(t, err, "Got error %v", s)
				assert.Equal(tc.result, got.GetItem().GetGrants())
			})
		}
	}

	o, p := iam.TestScopes(t, conn)
	role := iam.TestRole(t, conn, p.GetPublicId())
	failCases := []struct {
		name string
		req  *pbs.RemoveRoleGrantsRequest

		errCode codes.Code
	}{
		{
			name: "Bad Org Id",
			req: &pbs.RemoveRoleGrantsRequest{
				OrgId:     "",
				ProjectId: role.GetScopeId(),
				RoleId:    role.GetPublicId(),
				Grants:    []string{"id=*;actions=create"},
				Version:   &wrapperspb.UInt32Value{Value: role.GetVersion()},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad Project Id",
			req: &pbs.RemoveRoleGrantsRequest{
				OrgId:     o.GetPublicId(),
				ProjectId: "bad id",
				RoleId:    role.GetPublicId(),
				Grants:    []string{"id=*;actions=create"},
				Version:   &wrapperspb.UInt32Value{Value: role.GetVersion()},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad Role Id",
			req: &pbs.RemoveRoleGrantsRequest{
				OrgId:     o.GetPublicId(),
				ProjectId: role.GetScopeId(),
				RoleId:    "bad id",
				Grants:    []string{"id=*;actions=create"},
				Version:   &wrapperspb.UInt32Value{Value: role.GetVersion()},
			},
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			_, gErr := s.RemoveRoleGrants(context.Background(), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "RemoveRoleGrants(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
		})
	}
}
