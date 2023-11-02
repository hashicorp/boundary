// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package roles_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/roles"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/roles"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/version"
	"github.com/kr/pretty"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testAuthorizedActions = []string{"no-op", "read", "update", "delete", "add-principals", "set-principals", "remove-principals", "add-grants", "set-grants", "remove-grants"}

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
	or, pr, repoFn := createDefaultRolesAndRepo(t)
	toMerge := &pbs.GetRoleRequest{
		Id: or.GetPublicId(),
	}

	wantOrgRole := &pb.Role{
		Id:                or.GetPublicId(),
		ScopeId:           or.GetScopeId(),
		Scope:             &scopes.ScopeInfo{Id: or.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
		Name:              &wrapperspb.StringValue{Value: or.GetName()},
		Description:       &wrapperspb.StringValue{Value: or.GetDescription()},
		GrantScopeId:      &wrapperspb.StringValue{Value: pr.GetGrantScopeId()},
		CreatedTime:       or.CreateTime.GetTimestamp(),
		UpdatedTime:       or.UpdateTime.GetTimestamp(),
		Version:           or.GetVersion(),
		AuthorizedActions: testAuthorizedActions,
	}

	wantProjRole := &pb.Role{
		Id:                pr.GetPublicId(),
		ScopeId:           pr.GetScopeId(),
		Scope:             &scopes.ScopeInfo{Id: pr.GetScopeId(), Type: scope.Project.String(), ParentScopeId: or.GetScopeId()},
		Name:              &wrapperspb.StringValue{Value: pr.GetName()},
		Description:       &wrapperspb.StringValue{Value: pr.GetDescription()},
		GrantScopeId:      &wrapperspb.StringValue{Value: pr.GetGrantScopeId()},
		CreatedTime:       pr.CreateTime.GetTimestamp(),
		UpdatedTime:       pr.UpdateTime.GetTimestamp(),
		Version:           pr.GetVersion(),
		AuthorizedActions: testAuthorizedActions,
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
			req:  &pbs.GetRoleRequest{Id: globals.RolePrefix + "_DoesntExis"},
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
			req:  &pbs.GetRoleRequest{Id: globals.RolePrefix + "_1 23456789"},
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
			req:     &pbs.GetRoleRequest{Id: globals.RolePrefix + "_DoesntExis"},
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
			req:     &pbs.GetRoleRequest{Id: globals.RolePrefix + "_1 23456789"},
			res:     nil,
			err:     handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.GetRoleRequest)
			proto.Merge(req, tc.req)

			s, err := roles.NewService(context.Background(), repoFn, 1000)
			require.NoError(err, "Couldn't create new role service.")

			got, gErr := s.GetRole(auth.DisabledAuthTestContext(repoFn, tc.scopeId), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetRole(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetRole(%q) got response\n%q, wanted\n%q", req, got, tc.res)
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
	oNoRoles, pWithRoles := iam.TestScopes(t, iamRepo, iam.WithSkipDefaultRoleCreation(true))
	oWithRoles, pNoRoles := iam.TestScopes(t, iamRepo, iam.WithSkipDefaultRoleCreation(true))
	var wantOrgRoles []*pb.Role
	var wantProjRoles []*pb.Role
	var totalRoles []*pb.Role
	for i := 0; i < 10; i++ {
		or := iam.TestRole(t, conn, oWithRoles.GetPublicId())
		wantOrgRoles = append(wantOrgRoles, &pb.Role{
			Id:                or.GetPublicId(),
			ScopeId:           or.GetScopeId(),
			Scope:             &scopes.ScopeInfo{Id: or.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			CreatedTime:       or.GetCreateTime().GetTimestamp(),
			UpdatedTime:       or.GetUpdateTime().GetTimestamp(),
			GrantScopeId:      &wrapperspb.StringValue{Value: or.GetGrantScopeId()},
			Version:           or.GetVersion(),
			AuthorizedActions: testAuthorizedActions,
		})
		totalRoles = append(totalRoles, wantOrgRoles[i])
		pr := iam.TestRole(t, conn, pWithRoles.GetPublicId())
		wantProjRoles = append(wantProjRoles, &pb.Role{
			Id:                pr.GetPublicId(),
			ScopeId:           pr.GetScopeId(),
			Scope:             &scopes.ScopeInfo{Id: pr.GetScopeId(), Type: scope.Project.String(), ParentScopeId: oNoRoles.GetPublicId()},
			CreatedTime:       pr.GetCreateTime().GetTimestamp(),
			UpdatedTime:       pr.GetUpdateTime().GetTimestamp(),
			GrantScopeId:      &wrapperspb.StringValue{Value: pr.GetGrantScopeId()},
			Version:           pr.GetVersion(),
			AuthorizedActions: testAuthorizedActions,
		})
		totalRoles = append(totalRoles, wantProjRoles[i])
	}

	cases := []struct {
		name string
		req  *pbs.ListRolesRequest
		res  *pbs.ListRolesResponse
		err  error
	}{
		{
			name: "List Many Roles",
			req:  &pbs.ListRolesRequest{ScopeId: oWithRoles.GetPublicId()},
			res: &pbs.ListRolesResponse{
				Items:        wantOrgRoles,
				EstItemCount: 10,
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "asc",
			},
		},
		{
			name: "List No Roles",
			req:  &pbs.ListRolesRequest{ScopeId: oNoRoles.GetPublicId()},
			res: &pbs.ListRolesResponse{
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "asc",
			},
		},
		{
			name: "List Many Project Roles",
			req:  &pbs.ListRolesRequest{ScopeId: pWithRoles.GetPublicId()},
			res: &pbs.ListRolesResponse{
				Items:        wantProjRoles,
				EstItemCount: 10,
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "asc",
			},
		},
		{
			name: "List No Project Roles",
			req:  &pbs.ListRolesRequest{ScopeId: pNoRoles.GetPublicId()},
			res: &pbs.ListRolesResponse{
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "asc",
			},
		},
		{
			name: "List proj roles recursively",
			req:  &pbs.ListRolesRequest{ScopeId: pWithRoles.GetPublicId(), Recursive: true},
			res: &pbs.ListRolesResponse{
				Items:        wantProjRoles,
				EstItemCount: 10,
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "asc",
			},
		},
		{
			name: "List org roles recursively",
			req:  &pbs.ListRolesRequest{ScopeId: oNoRoles.GetPublicId(), Recursive: true},
			res: &pbs.ListRolesResponse{
				Items:        wantProjRoles,
				EstItemCount: 10,
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "asc",
			},
		},
		{
			name: "List global roles recursively",
			req:  &pbs.ListRolesRequest{ScopeId: "global", Recursive: true},
			res: &pbs.ListRolesResponse{
				Items:        totalRoles,
				EstItemCount: 20,
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "asc",
			},
		},
		{
			name: "Filter to org roles",
			req:  &pbs.ListRolesRequest{ScopeId: "global", Recursive: true, Filter: fmt.Sprintf(`"/item/scope/id"==%q`, oWithRoles.GetPublicId())},
			res: &pbs.ListRolesResponse{
				Items:        wantOrgRoles,
				EstItemCount: 10,
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "asc",
			},
		},
		{
			name: "Filter to proj roles",
			req:  &pbs.ListRolesRequest{ScopeId: "global", Recursive: true, Filter: fmt.Sprintf(`"/item/scope/id"==%q`, pWithRoles.GetPublicId())},
			res: &pbs.ListRolesResponse{
				Items:        wantProjRoles,
				EstItemCount: 10,
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "asc",
			},
		},
		{
			name: "Filter to no roles",
			req:  &pbs.ListRolesRequest{ScopeId: pWithRoles.GetPublicId(), Filter: `"/item/id"=="doesnt match"`},
			res: &pbs.ListRolesResponse{
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "asc",
			},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListRolesRequest{ScopeId: pWithRoles.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := roles.NewService(context.Background(), repoFn, 1000)
			require.NoError(err, "Couldn't create new role service.")

			// Test the non-anon case
			got, gErr := s.ListRoles(auth.DisabledAuthTestContext(repoFn, tc.req.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err))
				return
			}
			require.NoError(gErr)
			assert.Empty(
				cmp.Diff(
					got,
					tc.res,
					protocmp.Transform(),
					protocmp.IgnoreFields(&pbs.ListRolesResponse{}, "refresh_token"),
				),
				"ListRoles(%q) got response %q, wanted %q",
				tc.req,
				got,
				tc.res,
			)

			// Test the anon case
			got, gErr = s.ListRoles(auth.DisabledAuthTestContext(repoFn, tc.req.GetScopeId(), auth.WithUserId(globals.AnonymousUserId)), tc.req)
			require.NoError(gErr)
			assert.Len(got.Items, len(tc.res.Items))
			for _, item := range got.GetItems() {
				require.Nil(item.CreatedTime)
				require.Nil(item.PrincipalIds)
				require.Nil(item.Principals)
				require.Nil(item.Grants)
				require.Nil(item.GrantStrings)
				require.Nil(item.UpdatedTime)
				require.Zero(item.Version)
			}
		})
	}
}

func TestListPagination(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	ctx := context.Background()

	iamRepo := iam.TestRepo(t, conn, wrap)

	rw := db.New(conn)
	sqlDB, err := conn.SqlDB(ctx)
	require.NoError(t, err)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	require.NoError(t, err)
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}
	tokenRepo, err := tokenRepoFn()
	require.NoError(t, err)
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}

	o, _ := iam.TestScopes(t, iamRepo, iam.WithSkipDefaultRoleCreation(true))
	var wantRole []*pb.Role
	for i := 0; i < 9; i++ {
		or := iam.TestRole(t, conn, o.GetPublicId())
		wantRole = append(wantRole, &pb.Role{
			Id:                or.GetPublicId(),
			ScopeId:           or.GetScopeId(),
			Scope:             &scopes.ScopeInfo{Id: or.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			CreatedTime:       or.GetCreateTime().GetTimestamp(),
			UpdatedTime:       or.GetUpdateTime().GetTimestamp(),
			GrantScopeId:      &wrapperspb.StringValue{Value: or.GetGrantScopeId()},
			Version:           or.GetVersion(),
			AuthorizedActions: testAuthorizedActions,
		})
	}

	authMethod := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	// auth account is only used to join auth method to user.
	// We don't do anything else with the auth account in the test setup.
	acct := password.TestAccount(t, conn, authMethod.GetPublicId(), "test_user")

	u := iam.TestUser(t, iamRepo, o.GetPublicId(), iam.WithAccountIds(acct.PublicId))
	at, _ := tokenRepo.CreateAuthToken(ctx, u, acct.GetPublicId())

	privOrgRole := iam.TestRole(t, conn, o.GetPublicId())
	iam.TestRoleGrant(t, conn, privOrgRole.GetPublicId(), "id=*;type=*;actions=*")
	iam.TestUserRole(t, conn, privOrgRole.GetPublicId(), u.GetPublicId())

	wantRole = append(wantRole, &pb.Role{
		Id:                privOrgRole.GetPublicId(),
		ScopeId:           privOrgRole.GetScopeId(),
		Scope:             &scopes.ScopeInfo{Id: privOrgRole.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
		CreatedTime:       privOrgRole.GetCreateTime().GetTimestamp(),
		UpdatedTime:       privOrgRole.GetUpdateTime().GetTimestamp(),
		GrantScopeId:      &wrapperspb.StringValue{Value: privOrgRole.GetGrantScopeId()},
		Version:           privOrgRole.GetVersion(),
		AuthorizedActions: testAuthorizedActions,
	})

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

	s, err := roles.NewService(ctx, iamRepoFn, 1000)
	require.NoError(t, err)

	req := &pbs.ListRolesRequest{
		ScopeId:      o.GetPublicId(),
		Filter:       "",
		RefreshToken: "",
		PageSize:     2,
	}

	// first page
	got, err := s.ListRoles(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 2)
	// Compare without comparing the refresh token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListRolesResponse{
				Items:        wantRole[0:2],
				ResponseType: "delta",
				RefreshToken: "",
				SortBy:       "updated_time",
				SortDir:      "asc",
				RemovedIds:   nil,
				EstItemCount: 10,
			},
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListRolesResponse{}, "refresh_token"),
		),
	)

	// Request second page
	req.RefreshToken = got.RefreshToken
	got, err = s.ListRoles(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 2)
	// Compare without comparing the refresh token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListRolesResponse{
				Items:        wantRole[2:4],
				ResponseType: "delta",
				RefreshToken: "",
				SortBy:       "updated_time",
				SortDir:      "asc",
				RemovedIds:   nil,
				EstItemCount: 10,
			},
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListRolesResponse{}, "refresh_token"),
		),
	)

	// Request rest of results
	req.RefreshToken = got.RefreshToken
	req.PageSize = 10
	got, err = s.ListRoles(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 6)
	// Compare without comparing the refresh token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListRolesResponse{
				Items:        wantRole[4:],
				ResponseType: "complete",
				RefreshToken: "",
				SortBy:       "updated_time",
				SortDir:      "asc",
				RemovedIds:   nil,
				EstItemCount: 10,
			},
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListRolesResponse{}, "refresh_token"),
		),
	)

	// create another role
	or := iam.TestRole(t, conn, o.GetPublicId())
	wantRole = append(wantRole, &pb.Role{
		Id:                or.GetPublicId(),
		ScopeId:           or.GetScopeId(),
		Scope:             &scopes.ScopeInfo{Id: or.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
		CreatedTime:       or.GetCreateTime().GetTimestamp(),
		UpdatedTime:       or.GetUpdateTime().GetTimestamp(),
		GrantScopeId:      &wrapperspb.StringValue{Value: or.GetGrantScopeId()},
		Version:           or.GetVersion(),
		AuthorizedActions: testAuthorizedActions,
	})

	// delete a different role
	deletedRole := wantRole[0]
	_, err = iamRepo.DeleteRole(ctx, deletedRole.Id)
	require.NoError(t, err)
	wantRole = wantRole[1:]

	// Run analyze to update postgres estimates
	_, err = sqlDB.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	// Request updated results
	req.RefreshToken = got.RefreshToken
	got, err = s.ListRoles(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 1)
	// Compare without comparing the refresh token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListRolesResponse{
				Items:        wantRole[len(wantRole)-1:],
				ResponseType: "complete",
				RefreshToken: "",
				SortBy:       "updated_time",
				SortDir:      "asc",
				// Should contain the deleted role
				RemovedIds:   []string{deletedRole.Id},
				EstItemCount: 10,
			},
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListRolesResponse{}, "refresh_token"),
		),
	)

	// Request new page with filter requiring looping
	// to fill the page.
	req.RefreshToken = ""
	req.PageSize = 1
	req.Filter = fmt.Sprintf(`"/item/id"==%q or "/item/id"==%q`, wantRole[len(wantRole)-2].Id, wantRole[len(wantRole)-1].Id)
	got, err = s.ListRoles(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 1)
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListRolesResponse{
				Items:        []*pb.Role{wantRole[len(wantRole)-2]},
				ResponseType: "delta",
				RefreshToken: "",
				SortBy:       "updated_time",
				SortDir:      "asc",
				// Should be empty again
				RemovedIds:   nil,
				EstItemCount: 10,
			},
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListRolesResponse{}, "refresh_token"),
		),
	)
	req.RefreshToken = got.RefreshToken
	// Get the second page
	got, err = s.ListRoles(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 1)
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListRolesResponse{
				Items:        []*pb.Role{wantRole[len(wantRole)-1]},
				ResponseType: "complete",
				RefreshToken: "",
				SortBy:       "updated_time",
				SortDir:      "asc",
				RemovedIds:   nil,
				EstItemCount: 10,
			},
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListRolesResponse{}, "refresh_token"),
		),
	)
}

func TestDelete(t *testing.T) {
	or, pr, repoFn := createDefaultRolesAndRepo(t)

	s, err := roles.NewService(context.Background(), repoFn, 1000)
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
			scopeId: or.GetScopeId(),
			req: &pbs.DeleteRoleRequest{
				Id: or.GetPublicId(),
			},
		},
		{
			name:    "Delete bad role id",
			scopeId: or.GetScopeId(),
			req: &pbs.DeleteRoleRequest{
				Id: globals.RolePrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Bad Role Id formatting",
			scopeId: or.GetScopeId(),
			req: &pbs.DeleteRoleRequest{
				Id: "bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Project Scoped Delete an Existing Role",
			scopeId: pr.GetScopeId(),
			req: &pbs.DeleteRoleRequest{
				Id: pr.GetPublicId(),
			},
		},
		{
			name:    "Project Scoped Delete bad Role id",
			scopeId: pr.GetScopeId(),
			req: &pbs.DeleteRoleRequest{
				Id: globals.RolePrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteRole(auth.DisabledAuthTestContext(repoFn, tc.scopeId), tc.req)
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
	or, pr, repoFn := createDefaultRolesAndRepo(t)

	s, err := roles.NewService(context.Background(), repoFn, 1000)
	require.NoError(err, "Error when getting new role service")
	req := &pbs.DeleteRoleRequest{
		Id: or.GetPublicId(),
	}
	ctx := auth.DisabledAuthTestContext(repoFn, or.GetScopeId())
	_, gErr := s.DeleteRole(ctx, req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteRole(ctx, req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")

	projReq := &pbs.DeleteRoleRequest{
		Id: pr.GetPublicId(),
	}
	ctx = auth.DisabledAuthTestContext(repoFn, pr.GetScopeId())
	_, gErr = s.DeleteRole(ctx, projReq)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteRole(ctx, projReq)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")
}

func TestCreate(t *testing.T) {
	defaultOrgRole, defaultProjRole, repoFn := createDefaultRolesAndRepo(t)
	defaultCreated := defaultOrgRole.GetCreateTime().GetTimestamp().AsTime()
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
				Uri: fmt.Sprintf("roles/%s_", globals.RolePrefix),
				Item: &pb.Role{
					ScopeId:           defaultOrgRole.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: defaultOrgRole.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:              &wrapperspb.StringValue{Value: "name"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					GrantScopeId:      &wrapperspb.StringValue{Value: defaultProjRole.ScopeId},
					Version:           1,
					AuthorizedActions: testAuthorizedActions,
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
				Uri: fmt.Sprintf("roles/%s_", globals.RolePrefix),
				Item: &pb.Role{
					ScopeId:           scope.Global.String(),
					Scope:             &scopes.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
					Name:              &wrapperspb.StringValue{Value: "name"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					GrantScopeId:      &wrapperspb.StringValue{Value: defaultProjRole.ScopeId},
					Version:           1,
					AuthorizedActions: testAuthorizedActions,
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
				Uri: fmt.Sprintf("roles/%s_", globals.RolePrefix),
				Item: &pb.Role{
					ScopeId:           defaultProjRole.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: defaultProjRole.GetScopeId(), Type: scope.Project.String(), ParentScopeId: defaultOrgRole.GetScopeId()},
					Name:              &wrapperspb.StringValue{Value: "name"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					GrantScopeId:      &wrapperspb.StringValue{Value: defaultProjRole.ScopeId},
					Version:           1,
					AuthorizedActions: testAuthorizedActions,
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
				Id:      globals.RolePrefix + "_notallowed",
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateRoleRequest{Item: &pb.Role{
				ScopeId:     defaultProjRole.GetScopeId(),
				CreatedTime: timestamppb.Now(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateRoleRequest{Item: &pb.Role{
				ScopeId:     defaultProjRole.GetScopeId(),
				UpdatedTime: timestamppb.Now(),
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

			s, err := roles.NewService(context.Background(), repoFn, 1000)
			require.NoError(err, "Error when getting new role service.")

			got, gErr := s.CreateRole(auth.DisabledAuthTestContext(repoFn, tc.req.GetItem().GetScopeId()), req)
			if tc.err != nil {
				require.NotNil(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateRole(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				assert.True(strings.HasPrefix(got.GetItem().GetId(), globals.RolePrefix+"_"), "Expected %q to have the prefix %q", got.GetItem().GetId(), globals.RolePrefix+"_")
				gotCreateTime := got.GetItem().GetCreatedTime().AsTime()
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
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
	ctx := context.Background()
	grantString := "id=*;type=*;actions=*"
	g, err := perms.Parse(context.Background(), "global", grantString)
	require.NoError(t, err)
	_, actions := g.Actions()
	grant := &pb.Grant{
		Raw:       grantString,
		Canonical: g.CanonicalString(),
		Json: &pb.GrantJson{
			Id:      g.Id(),
			Ids:     g.Ids(),
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

	tested, err := roles.NewService(ctx, repoFn, 1000)
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

	created := or.GetCreateTime().GetTimestamp().AsTime()
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
					Id:                or.GetPublicId(),
					ScopeId:           or.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: or.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:              &wrapperspb.StringValue{Value: "new"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:       or.GetCreateTime().GetTimestamp(),
					GrantScopeId:      &wrapperspb.StringValue{Value: or.GetScopeId()},
					GrantStrings:      []string{grant.GetRaw()},
					Grants:            []*pb.Grant{grant},
					PrincipalIds:      []string{u.GetPublicId()},
					Principals:        []*pb.Principal{principal},
					AuthorizedActions: testAuthorizedActions,
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
					Id:                or.GetPublicId(),
					ScopeId:           or.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: or.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:              &wrapperspb.StringValue{Value: "new"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:       or.GetCreateTime().GetTimestamp(),
					GrantScopeId:      &wrapperspb.StringValue{Value: or.GetScopeId()},
					GrantStrings:      []string{grant.GetRaw()},
					Grants:            []*pb.Grant{grant},
					PrincipalIds:      []string{u.GetPublicId()},
					Principals:        []*pb.Principal{principal},
					AuthorizedActions: testAuthorizedActions,
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
					Id:                pr.GetPublicId(),
					ScopeId:           pr.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: pr.GetScopeId(), Type: scope.Project.String(), ParentScopeId: or.GetScopeId()},
					Name:              &wrapperspb.StringValue{Value: "new"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:       pr.GetCreateTime().GetTimestamp(),
					GrantScopeId:      &wrapperspb.StringValue{Value: pr.GetScopeId()},
					GrantStrings:      []string{grant.GetRaw()},
					Grants:            []*pb.Grant{grant},
					PrincipalIds:      []string{u.GetPublicId()},
					Principals:        []*pb.Principal{principal},
					AuthorizedActions: testAuthorizedActions,
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
					Id:                pr.GetPublicId(),
					ScopeId:           pr.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: pr.GetScopeId(), Type: scope.Project.String(), ParentScopeId: or.GetScopeId()},
					Name:              &wrapperspb.StringValue{Value: "new"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:       pr.GetCreateTime().GetTimestamp(),
					GrantScopeId:      &wrapperspb.StringValue{Value: pr.GetScopeId()},
					GrantStrings:      []string{grant.GetRaw()},
					Grants:            []*pb.Grant{grant},
					PrincipalIds:      []string{u.GetPublicId()},
					Principals:        []*pb.Principal{principal},
					AuthorizedActions: testAuthorizedActions,
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
					Id:                or.GetPublicId(),
					ScopeId:           or.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: or.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Description:       &wrapperspb.StringValue{Value: "default"},
					CreatedTime:       or.GetCreateTime().GetTimestamp(),
					GrantScopeId:      &wrapperspb.StringValue{Value: or.GetScopeId()},
					GrantStrings:      []string{grant.GetRaw()},
					Grants:            []*pb.Grant{grant},
					PrincipalIds:      []string{u.GetPublicId()},
					Principals:        []*pb.Principal{principal},
					AuthorizedActions: testAuthorizedActions,
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
					Id:                or.GetPublicId(),
					ScopeId:           or.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: or.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:              &wrapperspb.StringValue{Value: "updated"},
					Description:       &wrapperspb.StringValue{Value: "default"},
					CreatedTime:       or.GetCreateTime().GetTimestamp(),
					GrantScopeId:      &wrapperspb.StringValue{Value: or.GetScopeId()},
					GrantStrings:      []string{grant.GetRaw()},
					Grants:            []*pb.Grant{grant},
					PrincipalIds:      []string{u.GetPublicId()},
					Principals:        []*pb.Principal{principal},
					AuthorizedActions: testAuthorizedActions,
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
					Id:                or.GetPublicId(),
					ScopeId:           or.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: or.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:              &wrapperspb.StringValue{Value: "default"},
					Description:       &wrapperspb.StringValue{Value: "notignored"},
					CreatedTime:       or.GetCreateTime().GetTimestamp(),
					GrantScopeId:      &wrapperspb.StringValue{Value: or.GetScopeId()},
					GrantStrings:      []string{grant.GetRaw()},
					Grants:            []*pb.Grant{grant},
					PrincipalIds:      []string{u.GetPublicId()},
					Principals:        []*pb.Principal{principal},
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Update a Non Existing Role",
			req: &pbs.UpdateRoleRequest{
				Id: globals.RolePrefix + "_DoesntExis",
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
					Id:          globals.RolePrefix + "_somethinge",
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "new desc"},
				},
			},
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
					CreatedTime: timestamppb.Now(),
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
					UpdatedTime: timestamppb.Now(),
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
			_, gErr := tested.UpdateRole(auth.DisabledAuthTestContext(repoFn, tc.scopeId), req)
			require.Error(gErr)
			req.Item.Version = ver - 1
			_, gErr = tested.UpdateRole(auth.DisabledAuthTestContext(repoFn, tc.scopeId), req)
			require.Error(gErr)
			req.Item.Version = ver

			got, gErr := tested.UpdateRole(auth.DisabledAuthTestContext(repoFn, tc.scopeId), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateRole(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}

			if tc.err == nil {
				defer resetRoles(req.Id == pr.PublicId)
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateRole response to be nil, but was %v", got)
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
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
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	o, p := iam.TestScopes(t, iamRepo)
	s, err := roles.NewService(ctx, repoFn, 1000)
	require.NoError(t, err, "Error when getting new role service.")

	kmsCache := kms.TestKms(t, conn, wrap)
	databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	authMethod := oidc.TestAuthMethod(
		t, conn, databaseWrapper, o.GetPublicId(), oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	ldapAuthMethod := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://ldap1"})
	ldapManagedGroup := ldap.TestManagedGroup(t, conn, ldapAuthMethod, []string{"admin"})

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
	managedGroups := []*oidc.ManagedGroup{
		oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter),
		oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter),
		oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter),
	}

	addCases := []struct {
		name                string
		setup               func(*iam.Role)
		addUsers            []string
		addGroups           []string
		addManagedGroups    []string
		resultUsers         []string
		resultGroups        []string
		resultManagedGroups []string
		wantErr             bool
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
			name: "Add duplicate group on populated role",
			setup: func(r *iam.Role) {
				iam.TestGroupRole(t, conn, r.GetPublicId(), groups[0].GetPublicId())
			},
			addGroups:    []string{groups[1].GetPublicId(), groups[1].GetPublicId()},
			resultGroups: []string{groups[0].GetPublicId(), groups[1].GetPublicId()},
		},
		{
			name:                "Add managed group on empty role",
			setup:               func(r *iam.Role) {},
			addManagedGroups:    []string{managedGroups[1].GetPublicId()},
			resultManagedGroups: []string{managedGroups[1].GetPublicId()},
		},
		{
			name: "Add managed group on populated role",
			setup: func(r *iam.Role) {
				iam.TestManagedGroupRole(t, conn, r.GetPublicId(), managedGroups[0].GetPublicId())
			},
			addManagedGroups:    []string{managedGroups[1].GetPublicId()},
			resultManagedGroups: []string{managedGroups[0].GetPublicId(), managedGroups[1].GetPublicId()},
		},
		{
			name: "Add duplicate managed group on populated role",
			setup: func(r *iam.Role) {
				iam.TestManagedGroupRole(t, conn, r.GetPublicId(), managedGroups[0].GetPublicId())
			},
			addManagedGroups:    []string{managedGroups[1].GetPublicId(), managedGroups[1].GetPublicId()},
			resultManagedGroups: []string{managedGroups[0].GetPublicId(), managedGroups[1].GetPublicId()},
		},
		{
			name: "Add ldap managed group on populated role",
			setup: func(r *iam.Role) {
				iam.TestManagedGroupRole(t, conn, r.GetPublicId(), managedGroups[0].GetPublicId())
			},
			addManagedGroups:    []string{ldapManagedGroup.GetPublicId()},
			resultManagedGroups: []string{managedGroups[0].GetPublicId(), ldapManagedGroup.GetPublicId()},
		},
		{
			name:     "Add invalid u_recovery on role",
			setup:    func(r *iam.Role) {},
			addUsers: []string{globals.RecoveryUserId},
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
					PrincipalIds: append(tc.addUsers, append(tc.addGroups, tc.addManagedGroups...)...),
				}

				got, err := s.AddRolePrincipals(auth.DisabledAuthTestContext(repoFn, o.GetPublicId()), req)
				if tc.wantErr {
					assert.Error(t, err)
					return
				}
				s, ok := status.FromError(err)
				require.True(t, ok, fmt.Sprintf("Could not run FromError; input was %s", pretty.Sprint(err)))
				require.NoError(t, err, "Got error: %v", s)

				assert.True(t, equalPrincipals(got.GetItem(), append(tc.resultUsers, append(tc.resultGroups, tc.resultManagedGroups...)...)))
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
		{
			name: "Bad Principal Id",
			req: &pbs.AddRolePrincipalsRequest{
				Id:           role.GetPublicId(),
				Version:      role.GetVersion(),
				PrincipalIds: []string{"invalid"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "u_recovery Id",
			req: &pbs.AddRolePrincipalsRequest{
				Id:           role.GetPublicId(),
				Version:      role.GetVersion(),
				PrincipalIds: []string{globals.RecoveryUserId},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.AddRolePrincipals(auth.DisabledAuthTestContext(repoFn, p.GetPublicId()), tc.req)
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
	s, err := roles.NewService(context.Background(), repoFn, 1000)
	require.NoError(t, err, "Error when getting new role service.")

	o, p := iam.TestScopes(t, iamRepo)

	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrap)
	databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	authMethod := oidc.TestAuthMethod(
		t, conn, databaseWrapper, o.GetPublicId(), oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	ldapAuthMethod := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://ldap1"})
	ldapManagedGroup := ldap.TestManagedGroup(t, conn, ldapAuthMethod, []string{"admin"})

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
	managedGroups := []*oidc.ManagedGroup{
		oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter),
		oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter),
		oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter),
	}

	setCases := []struct {
		name                string
		setup               func(*iam.Role)
		setUsers            []string
		setGroups           []string
		setManagedGroups    []string
		resultUsers         []string
		resultGroups        []string
		resultManagedGroups []string
		wantErr             bool
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
			name: "Set duplicate user on populated role",
			setup: func(r *iam.Role) {
				iam.TestUserRole(t, conn, r.GetPublicId(), users[0].GetPublicId())
			},
			setUsers:    []string{users[1].GetPublicId(), users[1].GetPublicId()},
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
			name:                "Set managed group on empty role",
			setup:               func(r *iam.Role) {},
			setManagedGroups:    []string{managedGroups[1].GetPublicId()},
			resultManagedGroups: []string{managedGroups[1].GetPublicId()},
		},
		{
			name: "Set managed group on populated role",
			setup: func(r *iam.Role) {
				iam.TestManagedGroupRole(t, conn, r.GetPublicId(), managedGroups[0].GetPublicId())
			},
			setManagedGroups:    []string{managedGroups[1].GetPublicId()},
			resultManagedGroups: []string{managedGroups[1].GetPublicId()},
		},
		{
			name: "Set LDAP managed group on populated role",
			setup: func(r *iam.Role) {
				iam.TestManagedGroupRole(t, conn, r.GetPublicId(), managedGroups[0].GetPublicId())
			},
			setManagedGroups:    []string{ldapManagedGroup.GetPublicId()},
			resultManagedGroups: []string{ldapManagedGroup.GetPublicId()},
		},
		{
			name:     "Set invalid u_recovery on role",
			setup:    func(r *iam.Role) {},
			setUsers: []string{globals.RecoveryUserId},
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
					PrincipalIds: append(tc.setUsers, append(tc.setGroups, tc.setManagedGroups...)...),
				}

				got, err := s.SetRolePrincipals(auth.DisabledAuthTestContext(repoFn, o.GetPublicId()), req)
				if tc.wantErr {
					assert.Error(t, err)
					return
				}
				s, ok := status.FromError(err)
				require.True(t, ok, fmt.Sprintf("Could not run FromError; input was %s", pretty.Sprint(err)))
				require.NoError(t, err, "Got error: %v", s)

				assert.True(t, equalPrincipals(got.GetItem(), append(tc.resultUsers, append(tc.resultGroups, tc.resultManagedGroups...)...)))
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
		{
			name: "Bad Principal Id",
			req: &pbs.SetRolePrincipalsRequest{
				Id:           role.GetPublicId(),
				Version:      role.GetVersion(),
				PrincipalIds: []string{"invalid"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "u_recovery",
			req: &pbs.SetRolePrincipalsRequest{
				Id:           role.GetPublicId(),
				Version:      role.GetVersion(),
				PrincipalIds: []string{globals.RecoveryUserId},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.SetRolePrincipals(auth.DisabledAuthTestContext(repoFn, p.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "SetRolePrincipals(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestRemovePrincipal(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := roles.NewService(ctx, repoFn, 1000)
	require.NoError(t, err, "Error when getting new role service.")

	o, p := iam.TestScopes(t, iamRepo)

	kmsCache := kms.TestKms(t, conn, wrap)
	databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	authMethod := oidc.TestAuthMethod(
		t, conn, databaseWrapper, o.GetPublicId(), oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	ldapAuthMethod := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://ldap1"})
	ldapManagedGroup := ldap.TestManagedGroup(t, conn, ldapAuthMethod, []string{"admin"})

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
	managedGroups := []*oidc.ManagedGroup{
		oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter),
		oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter),
		oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter),
	}

	addCases := []struct {
		name                string
		setup               func(*iam.Role)
		removeUsers         []string
		removeGroups        []string
		removeManagedGroups []string
		resultUsers         []string
		resultGroups        []string
		resultManagedGroups []string
		wantErr             bool
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
			name: "Remove 1 duplicate user of 2 users from role",
			setup: func(r *iam.Role) {
				iam.TestUserRole(t, conn, r.GetPublicId(), users[0].GetPublicId())
				iam.TestUserRole(t, conn, r.GetPublicId(), users[1].GetPublicId())
			},
			removeUsers: []string{users[1].GetPublicId(), users[1].GetPublicId()},
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
			name: "Remove 1 duplicate group of 2 groups from role",
			setup: func(r *iam.Role) {
				iam.TestGroupRole(t, conn, r.GetPublicId(), groups[0].GetPublicId())
				iam.TestGroupRole(t, conn, r.GetPublicId(), groups[1].GetPublicId())
			},
			removeGroups: []string{groups[1].GetPublicId(), groups[1].GetPublicId()},
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
		{
			name:         "Remove managed group on empty role",
			setup:        func(r *iam.Role) {},
			removeGroups: []string{groups[1].GetPublicId()},
			wantErr:      true,
		},
		{
			name: "Remove 1 of 2 managed groups from role",
			setup: func(r *iam.Role) {
				iam.TestManagedGroupRole(t, conn, r.GetPublicId(), managedGroups[0].GetPublicId())
				iam.TestManagedGroupRole(t, conn, r.GetPublicId(), managedGroups[1].GetPublicId())
			},
			removeManagedGroups: []string{managedGroups[1].GetPublicId()},
			resultManagedGroups: []string{managedGroups[0].GetPublicId()},
		},
		{
			name: "Remove 1 duplicate managed group of 2 managed groups from role",
			setup: func(r *iam.Role) {
				iam.TestManagedGroupRole(t, conn, r.GetPublicId(), managedGroups[0].GetPublicId())
				iam.TestManagedGroupRole(t, conn, r.GetPublicId(), managedGroups[1].GetPublicId())
			},
			removeManagedGroups: []string{managedGroups[1].GetPublicId(), managedGroups[1].GetPublicId()},
			resultManagedGroups: []string{managedGroups[0].GetPublicId()},
		},
		{
			name: "Remove all managed groups from role",
			setup: func(r *iam.Role) {
				iam.TestManagedGroupRole(t, conn, r.GetPublicId(), managedGroups[0].GetPublicId())
				iam.TestManagedGroupRole(t, conn, r.GetPublicId(), managedGroups[1].GetPublicId())
			},
			removeManagedGroups: []string{managedGroups[0].GetPublicId(), managedGroups[1].GetPublicId()},
			resultManagedGroups: []string{},
		},
		{
			name: "Remove LDAP managed groups from role",
			setup: func(r *iam.Role) {
				iam.TestManagedGroupRole(t, conn, r.GetPublicId(), ldapManagedGroup.GetPublicId())
				iam.TestManagedGroupRole(t, conn, r.GetPublicId(), managedGroups[0].GetPublicId())
			},
			removeManagedGroups: []string{ldapManagedGroup.GetPublicId()},
			resultManagedGroups: []string{managedGroups[0].GetPublicId()},
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
					PrincipalIds: append(tc.removeUsers, append(tc.removeGroups, tc.removeManagedGroups...)...),
				}

				got, err := s.RemoveRolePrincipals(auth.DisabledAuthTestContext(repoFn, o.GetPublicId()), req)
				if tc.wantErr {
					assert.Error(t, err)
					return
				}
				s, ok := status.FromError(err)
				require.True(t, ok)
				require.NoError(t, err, "Got error: %v", s)

				assert.True(t, equalPrincipals(got.GetItem(), append(tc.resultUsers, append(tc.resultGroups, tc.resultManagedGroups...)...)))
			})
		}
	}

	role := iam.TestRole(t, conn, p.GetPublicId())

	failCases := []struct {
		name string
		req  *pbs.RemoveRolePrincipalsRequest
		err  error
	}{
		{
			name: "Bad Role Id",
			req: &pbs.RemoveRolePrincipalsRequest{
				Id:      "bad id",
				Version: role.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Bad User Id",
			req: &pbs.RemoveRolePrincipalsRequest{
				Id:           role.GetPublicId(),
				Version:      role.GetVersion(),
				PrincipalIds: []string{"g_validgroup", "invaliduser"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Bad Group Id",
			req: &pbs.RemoveRolePrincipalsRequest{
				Id:           role.GetPublicId(),
				Version:      role.GetVersion(),
				PrincipalIds: []string{"u_validuser", "invalidgroup"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.RemoveRolePrincipals(auth.DisabledAuthTestContext(repoFn, p.GetPublicId()), tc.req)
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
		parsed, err := perms.Parse(context.Background(), "o_abc123", v)
		require.NoError(err)
		assert.Equal(expected[i], got.GrantStrings[i])
		assert.Equal(expected[i], got.Grants[i].GetRaw())
		assert.Equal(v, got.Grants[i].GetCanonical())
		j := got.Grants[i].GetJson()
		require.NotNil(j)
		assert.Equal(parsed.Id(), j.GetId())
		assert.Equal(parsed.Ids(), j.GetIds())
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
	s, err := roles.NewService(context.Background(), repoFn, 1000)
	require.NoError(t, err, "Error when getting new role service.")

	addCases := []struct {
		name            string
		existing        []string
		add             []string
		result          []string
		wantErr         bool
		wantErrContains string
	}{
		{
			name:   "Add grant on empty role",
			add:    []string{"ids=*;type=*;actions=delete"},
			result: []string{"ids=*;type=*;actions=delete"},
		},
		{
			name:     "Add grant on role with grant",
			existing: []string{"id=u_foo;actions=read"},
			add:      []string{"ids=*;type=*;actions=delete"},
			result:   []string{"id=u_foo;actions=read", "ids=*;type=*;actions=delete"},
		},
		{
			name:     "Add duplicate grant on role with grant",
			existing: []string{"id=u_fooaA1;actions=read"},
			add:      []string{"ids=*;type=*;actions=delete", "ids=*;type=*;actions=delete"},
			result:   []string{"id=u_fooaA1;actions=read", "ids=*;type=*;actions=delete"},
		},
		{
			name:     "Add grant matching existing grant",
			existing: []string{"ids=u_foo;actions=read", "ids=*;type=*;actions=delete"},
			add:      []string{"ids=*;type=*;actions=delete"},
			wantErr:  true,
		},
		{
			name:            "Check add-host-sets deprecation",
			existing:        []string{"id=u_foo;actions=read", "id=*;type=*;actions=delete"},
			add:             []string{"ids=*;type=target;actions=add-host-sets"},
			wantErr:         true,
			wantErrContains: "Use \\\"add-host-sources\\\" instead",
		},
		{
			name:     "Check id field deprecation",
			existing: []string{"id=u_fooaA1;actions=read"},
			add:      []string{"id=*;type=*;actions=delete"},
			result:   []string{"id=u_fooaA1;actions=read", "id=*;type=*;actions=delete"},
			wantErr: func() bool {
				return !version.SupportsFeature(version.Binary, version.SupportIdInGrants)
			}(),
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
				got, err := s.AddRoleGrants(auth.DisabledAuthTestContext(repoFn, scopeId), req)
				if tc.wantErr {
					assert.Error(err)
					if tc.wantErrContains != "" {
						assert.Contains(err.Error(), tc.wantErrContains)
					}
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
				GrantStrings: []string{"ids=*;type=*;actions=create"},
				Version:      role.GetVersion() + 2,
			},
			err: handlers.ApiErrorWithCode(codes.Internal),
		},
		{
			name: "Bad Role Id",
			req: &pbs.AddRoleGrantsRequest{
				Id:           "bad id",
				GrantStrings: []string{"ids=*;type=*;actions=create"},
				Version:      role.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Unparseable Grant",
			req: &pbs.AddRoleGrantsRequest{
				Id:           role.GetPublicId(),
				GrantStrings: []string{"ids=*;type=*;actions=create", "unparseable"},
				Version:      role.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Empty Grant",
			req: &pbs.AddRoleGrantsRequest{
				Id:           role.GetPublicId(),
				GrantStrings: []string{"ids=*;type=*;actions=create", ""},
				Version:      role.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.AddRoleGrants(auth.DisabledAuthTestContext(repoFn, p.GetPublicId()), tc.req)
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

	s, err := roles.NewService(context.Background(), repoFn, 1000)
	require.NoError(t, err, "Error when getting new role service.")

	setCases := []struct {
		name            string
		existing        []string
		set             []string
		result          []string
		wantErr         bool
		wantErrContains string
	}{
		{
			name:   "Set grant on empty role",
			set:    []string{"ids=*;type=*;actions=delete"},
			result: []string{"ids=*;type=*;actions=delete"},
		},
		{
			name:     "Set grant on role with grant",
			existing: []string{"id=u_foo;actions=read"},
			set:      []string{"ids=*;type=*;actions=delete"},
			result:   []string{"ids=*;type=*;actions=delete"},
		},
		{
			name:     "Set grant matching existing grant",
			existing: []string{"id=u_foo;actions=read", "id=*;type=*;actions=delete"},
			set:      []string{"ids=*;type=*;actions=delete"},
			result:   []string{"ids=*;type=*;actions=delete"},
		},
		{
			name:     "Set duplicate grant matching existing grant",
			existing: []string{"id=u_foo;actions=read", "id=*;type=*;actions=delete"},
			set:      []string{"ids=*;type=*;actions=delete", "ids=*;type=*;actions=delete"},
			result:   []string{"ids=*;type=*;actions=delete"},
		},
		{
			name:     "Set empty on role",
			existing: []string{"id=hcst_foo;type=*;actions=read", "id=*;type=*;actions=delete"},
			set:      nil,
			result:   nil,
		},
		{
			name:            "Check add-host-sets deprecation",
			existing:        []string{"id=u_foo;actions=read", "id=*;type=*;actions=delete"},
			set:             []string{"ids=*;type=target;actions=add-host-sets"},
			wantErr:         true,
			wantErrContains: "Use \\\"add-host-sources\\\" instead",
		},
		{
			name:     "Check id field deprecation",
			existing: []string{"id=u_fooaA1;actions=read"},
			set:      []string{"id=*;type=*;actions=delete"},
			result:   []string{"id=*;type=*;actions=delete"},
			wantErr: func() bool {
				return !version.SupportsFeature(version.Binary, version.SupportIdInGrants)
			}(),
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
				got, err := s.SetRoleGrants(auth.DisabledAuthTestContext(repoFn, scopeId), req)
				if tc.wantErr {
					assert.Error(err)
					if tc.wantErrContains != "" {
						assert.Contains(err.Error(), tc.wantErrContains)
					}
					return
				}
				require.NoError(err, "Got error %v", err)
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
				GrantStrings: []string{"ids=*;type=*;actions=create"},
				Version:      role.GetVersion() + 2,
			},
			err: handlers.ApiErrorWithCode(codes.Internal),
		},
		{
			name: "Bad Role Id",
			req: &pbs.SetRoleGrantsRequest{
				Id:           "bad id",
				GrantStrings: []string{"ids=*;type=*;actions=create"},
				Version:      role.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Unparsable grant",
			req: &pbs.SetRoleGrantsRequest{
				Id:           role.GetPublicId(),
				GrantStrings: []string{"ids=*;type=*;actions=create", "unparseable"},
				Version:      role.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.SetRoleGrants(auth.DisabledAuthTestContext(repoFn, p.GetPublicId()), tc.req)
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
	s, err := roles.NewService(context.Background(), repoFn, 1000)
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
			existing: []string{"id=hcst_1;type=*;actions=read"},
			remove:   []string{"id=hcst_1;type=*;actions=read"},
		},
		{
			name:     "Remove partial",
			existing: []string{"id=hcst_1;type=*;actions=read", "id=hcst_2;type=*;actions=delete"},
			remove:   []string{"id=hcst_1;type=*;actions=read"},
			result:   []string{"id=hcst_2;type=*;actions=delete"},
		},
		{
			name:     "Remove duplicate",
			existing: []string{"id=hcst_1;type=*;actions=read", "id=hcst_2;type=*;actions=delete"},
			remove:   []string{"id=hcst_1;type=*;actions=read", "id=hcst_1;type=*;actions=read"},
			result:   []string{"id=hcst_2;type=*;actions=delete"},
		},
		{
			name:     "Remove non existant",
			existing: []string{"id=hcst_2;type=*;actions=delete"},
			remove:   []string{"id=hcst_1;type=*;actions=read"},
			result:   []string{"id=hcst_2;type=*;actions=delete"},
		},
		{
			name:     "Remove from empty role",
			existing: []string{},
			remove:   []string{"id=hcst_1;type=*;actions=read"},
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
				got, err := s.RemoveRoleGrants(auth.DisabledAuthTestContext(repoFn, scopeId), req)
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
				GrantStrings: []string{"id=hcst_2;type=*;actions=create"},
				Version:      role.GetVersion() + 2,
			},
			err: handlers.ApiErrorWithCode(codes.Internal),
		},
		{
			name: "Bad Role Id",
			req: &pbs.RemoveRoleGrantsRequest{
				Id:           "bad id",
				GrantStrings: []string{"id=*;type=*;actions=create"},
				Version:      role.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Empty Grant",
			req: &pbs.RemoveRoleGrantsRequest{
				Id:           role.GetPublicId(),
				GrantStrings: []string{"id=*;type=*;actions=create", ""},
				Version:      role.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Unparseable Grant",
			req: &pbs.RemoveRoleGrantsRequest{
				Id:           role.GetPublicId(),
				GrantStrings: []string{"id=*;type=*;actions=create", ";unparsable=2"},
				Version:      role.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.RemoveRoleGrants(auth.DisabledAuthTestContext(repoFn, p.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "RemoveRoleGrants(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}
