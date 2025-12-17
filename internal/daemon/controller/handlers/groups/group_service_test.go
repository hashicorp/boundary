// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package groups_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/groups"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/groups"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
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

var testAuthorizedActions = []string{"no-op", "read", "update", "delete", "add-members", "set-members", "remove-members"}

// Creates an org scoped group and a project scoped group.
func createDefaultGroupsAndRepo(t *testing.T) (*iam.Group, *iam.Group, func() (*iam.Repository, error)) {
	t.Helper()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	o, p := iam.TestScopes(t, iamRepo)
	og := iam.TestGroup(t, conn, o.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	pg := iam.TestGroup(t, conn, p.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	return og, pg, repoFn
}

func equalMembers(g *pb.Group, members []string) bool {
	if len(g.Members) != len(members) {
		return false
	}
	for _, m := range members {
		var foundInMembers bool
		var foundInPrincipalIds bool
		for _, v := range g.Members {
			if v.Id == m {
				foundInMembers = true
			}
		}
		for _, v := range g.MemberIds {
			if v == m {
				foundInPrincipalIds = true
			}
		}
		if !foundInMembers || !foundInPrincipalIds {
			return false
		}
	}
	return true
}

func TestGet(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	o, p := iam.TestScopes(t, iamRepo)
	u := iam.TestUser(t, iamRepo, o.GetPublicId())

	og := iam.TestGroup(t, conn, o.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	_ = iam.TestGroupMember(t, conn, og.GetPublicId(), u.GetPublicId())

	pg := iam.TestGroup(t, conn, p.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	_ = iam.TestGroupMember(t, conn, pg.GetPublicId(), u.GetPublicId())

	toMerge := &pbs.GetGroupRequest{
		Id: og.GetPublicId(),
	}

	wantOrgGroup := &pb.Group{
		Id:          og.GetPublicId(),
		ScopeId:     og.GetScopeId(),
		Scope:       &scopes.ScopeInfo{Id: og.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
		Name:        &wrapperspb.StringValue{Value: og.GetName()},
		Description: &wrapperspb.StringValue{Value: og.GetDescription()},
		CreatedTime: og.CreateTime.GetTimestamp(),
		UpdatedTime: og.UpdateTime.GetTimestamp(),
		Version:     1,
		MemberIds:   []string{u.GetPublicId()},
		Members: []*pb.Member{
			{
				Id:      u.GetPublicId(),
				ScopeId: u.GetScopeId(),
			},
		},
		AuthorizedActions: testAuthorizedActions,
	}

	wantProjGroup := &pb.Group{
		Id:          pg.GetPublicId(),
		ScopeId:     pg.GetScopeId(),
		Scope:       &scopes.ScopeInfo{Id: pg.GetScopeId(), Type: scope.Project.String(), ParentScopeId: o.GetPublicId()},
		Name:        &wrapperspb.StringValue{Value: pg.GetName()},
		Description: &wrapperspb.StringValue{Value: pg.GetDescription()},
		CreatedTime: pg.CreateTime.GetTimestamp(),
		UpdatedTime: pg.UpdateTime.GetTimestamp(),
		Version:     1,
		MemberIds:   []string{u.GetPublicId()},
		Members: []*pb.Member{
			{
				Id:      u.GetPublicId(),
				ScopeId: u.GetScopeId(),
			},
		},
		AuthorizedActions: testAuthorizedActions,
	}

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.GetGroupRequest
		res     *pbs.GetGroupResponse
		err     error
	}{
		{
			name:    "Get an Existing Group",
			scopeId: og.GetScopeId(),
			req:     &pbs.GetGroupRequest{Id: og.GetPublicId()},
			res:     &pbs.GetGroupResponse{Item: wantOrgGroup},
		},
		{
			name: "Get a non existent Group",
			req:  &pbs.GetGroupRequest{Id: globals.GroupPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Wrong id prefix",
			req:  &pbs.GetGroupRequest{Id: "j_1234567890"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "space in id",
			req:  &pbs.GetGroupRequest{Id: globals.GroupPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Project Scoped Get an Existing Group",
			scopeId: pg.GetScopeId(),
			req:     &pbs.GetGroupRequest{Id: pg.GetPublicId()},
			res:     &pbs.GetGroupResponse{Item: wantProjGroup},
		},
		{
			name:    "Project Scoped Get a non existent Group",
			scopeId: pg.GetScopeId(),
			req:     &pbs.GetGroupRequest{Id: globals.GroupPrefix + "_DoesntExis"},
			res:     nil,
			err:     handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Project Scoped Wrong id prefix",
			scopeId: pg.GetScopeId(),
			req:     &pbs.GetGroupRequest{Id: "j_1234567890"},
			res:     nil,
			err:     handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Project Scoped space in id",
			scopeId: pg.GetScopeId(),
			req:     &pbs.GetGroupRequest{Id: globals.GroupPrefix + "_1 23456789"},
			res:     nil,
			err:     handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.GetGroupRequest)
			proto.Merge(req, tc.req)

			s, err := groups.NewService(ctx, repoFn, 1000)
			require.NoError(err, "Couldn't create new group service.")

			got, gErr := s.GetGroup(auth.DisabledAuthTestContext(repoFn, tc.scopeId), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetGroup(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "GetGroup(%q) got response\n%q, wanted\n%q", req, got, tc.res)
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
	oNoGroups, pWithGroups := iam.TestScopes(t, iamRepo)
	oWithGroups, pNoGroups := iam.TestScopes(t, iamRepo)
	var wantGlobalGroups []*pb.Group
	var wantOrgGroups []*pb.Group
	var wantProjGroups []*pb.Group
	var totalGroups []*pb.Group
	for i := 0; i < 10; i++ {
		gg := iam.TestGroup(t, conn, "global")
		wantGlobalGroups = append(wantGlobalGroups, &pb.Group{
			Id:                gg.GetPublicId(),
			ScopeId:           gg.GetScopeId(),
			Scope:             &scopes.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: "global", Description: "Global Scope"},
			CreatedTime:       gg.GetCreateTime().GetTimestamp(),
			UpdatedTime:       gg.GetUpdateTime().GetTimestamp(),
			Version:           1,
			AuthorizedActions: testAuthorizedActions,
		})
		totalGroups = append(totalGroups, wantGlobalGroups[i])
		og := iam.TestGroup(t, conn, oWithGroups.GetPublicId())
		wantOrgGroups = append(wantOrgGroups, &pb.Group{
			Id:                og.GetPublicId(),
			ScopeId:           og.GetScopeId(),
			Scope:             &scopes.ScopeInfo{Id: oWithGroups.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			CreatedTime:       og.GetCreateTime().GetTimestamp(),
			UpdatedTime:       og.GetUpdateTime().GetTimestamp(),
			Version:           1,
			AuthorizedActions: testAuthorizedActions,
		})
		totalGroups = append(totalGroups, wantOrgGroups[i])
		pg := iam.TestGroup(t, conn, pWithGroups.GetPublicId())
		wantProjGroups = append(wantProjGroups, &pb.Group{
			Id:                pg.GetPublicId(),
			ScopeId:           pg.GetScopeId(),
			Scope:             &scopes.ScopeInfo{Id: pWithGroups.GetPublicId(), Type: scope.Project.String(), ParentScopeId: oNoGroups.GetPublicId()},
			CreatedTime:       pg.GetCreateTime().GetTimestamp(),
			UpdatedTime:       pg.GetUpdateTime().GetTimestamp(),
			Version:           1,
			AuthorizedActions: testAuthorizedActions,
		})
		totalGroups = append(totalGroups, wantProjGroups[i])
	}

	slices.Reverse(wantProjGroups)
	slices.Reverse(wantOrgGroups)
	slices.Reverse(wantGlobalGroups)
	slices.Reverse(totalGroups)

	cases := []struct {
		name string
		req  *pbs.ListGroupsRequest
		res  *pbs.ListGroupsResponse
		err  error
	}{
		{
			name: "List Global Groups",
			req:  &pbs.ListGroupsRequest{ScopeId: "global"},
			res: &pbs.ListGroupsResponse{
				Items:        wantGlobalGroups,
				EstItemCount: uint32(len(wantGlobalGroups)),
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "List Org Group",
			req:  &pbs.ListGroupsRequest{ScopeId: oWithGroups.GetPublicId()},
			res: &pbs.ListGroupsResponse{
				Items:        wantOrgGroups,
				EstItemCount: uint32(len(wantOrgGroups)),
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "List No Groups",
			req:  &pbs.ListGroupsRequest{ScopeId: oNoGroups.GetPublicId()},
			res: &pbs.ListGroupsResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "List Many Project Group",
			req:  &pbs.ListGroupsRequest{ScopeId: pWithGroups.GetPublicId()},
			res: &pbs.ListGroupsResponse{
				Items:        wantProjGroups,
				EstItemCount: uint32(len(wantProjGroups)),
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "List No Project Groups",
			req:  &pbs.ListGroupsRequest{ScopeId: pNoGroups.GetPublicId()},
			res: &pbs.ListGroupsResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "List proj groups recursively",
			req:  &pbs.ListGroupsRequest{ScopeId: pWithGroups.GetPublicId(), Recursive: true},
			res: &pbs.ListGroupsResponse{
				Items:        wantProjGroups,
				EstItemCount: uint32(len(wantProjGroups)),
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "List org groups recursively",
			req:  &pbs.ListGroupsRequest{ScopeId: oNoGroups.GetPublicId(), Recursive: true},
			res: &pbs.ListGroupsResponse{
				Items:        wantProjGroups,
				EstItemCount: uint32(len(wantProjGroups)),
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "List global groups recursively",
			req:  &pbs.ListGroupsRequest{ScopeId: "global", Recursive: true},
			res: &pbs.ListGroupsResponse{
				Items:        totalGroups,
				EstItemCount: uint32(len(totalGroups)),
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "Filter to org groups",
			req:  &pbs.ListGroupsRequest{ScopeId: "global", Recursive: true, Filter: fmt.Sprintf(`"/item/scope/id"==%q`, oWithGroups.GetPublicId())},
			res: &pbs.ListGroupsResponse{
				Items:        wantOrgGroups,
				EstItemCount: uint32(len(wantOrgGroups)),
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "Filter to project groups",
			req:  &pbs.ListGroupsRequest{ScopeId: "global", Recursive: true, Filter: fmt.Sprintf(`"/item/scope/id"==%q`, pWithGroups.GetPublicId())},
			res: &pbs.ListGroupsResponse{
				Items:        wantProjGroups,
				EstItemCount: uint32(len(wantProjGroups)),
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "Filter to no groups",
			req:  &pbs.ListGroupsRequest{ScopeId: "global", Recursive: true, Filter: `"/item/id"=="doesntmatch"`},
			res: &pbs.ListGroupsResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListGroupsRequest{ScopeId: "global", Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := groups.NewService(ctx, repoFn, 1000)
			require.NoError(err, "Couldn't create new group service.")

			// Test with a non-anon user
			got, gErr := s.ListGroups(auth.DisabledAuthTestContext(repoFn, tc.req.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListGroups(%q) got error %v, wanted %v", tc.req.GetScopeId(), gErr, tc.err)
				return
			}
			require.NoError(gErr)
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListGroupsResponse{}, "list_token"),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "ListGroups(%q) got response %q, wanted %q", tc.req.GetScopeId(), got, tc.res)

			// Test the anon case
			got, gErr = s.ListGroups(auth.DisabledAuthTestContext(repoFn, tc.req.GetScopeId(), auth.WithUserId(globals.AnonymousUserId)), tc.req)
			require.NoError(gErr)
			assert.Len(got.Items, len(tc.res.Items))
			for _, item := range got.GetItems() {
				require.Nil(item.CreatedTime)
				require.Nil(item.Members)
				require.Nil(item.UpdatedTime)
				require.Zero(item.Version)
			}
		})
	}
}

func groupToProto(u *iam.Group, si *scopes.ScopeInfo, authorizedActions []string) *pb.Group {
	pu := &pb.Group{
		Id:                u.GetPublicId(),
		ScopeId:           u.GetScopeId(),
		Scope:             si,
		CreatedTime:       u.GetCreateTime().GetTimestamp(),
		UpdatedTime:       u.GetUpdateTime().GetTimestamp(),
		Version:           u.GetVersion(),
		AuthorizedActions: testAuthorizedActions,
	}
	if u.GetName() != "" {
		pu.Name = wrapperspb.String(u.GetName())
	}
	if u.GetDescription() != "" {
		pu.Description = wrapperspb.String(u.GetDescription())
	}
	return pu
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
	sqlDB, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}
	tokenRepo, err := tokenRepoFn()
	require.NoError(t, err)

	// Run analyze to update postgres meta tables
	_, err = sqlDB.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	oNoGroups, pWithGroups := iam.TestScopes(t, iamRepo)
	oWithGroups, pNoGroups := iam.TestScopes(t, iamRepo)

	authMethod := password.TestAuthMethods(t, conn, "global", 1)[0]
	acct := password.TestAccount(t, conn, authMethod.GetPublicId(), "test_user")
	u := iam.TestUser(t, iamRepo, "global", iam.WithAccountIds(acct.PublicId))
	// add roles to be able to see all users
	allowedRole := iam.TestRole(t, conn, "global")
	iam.TestRoleGrant(t, conn, allowedRole.GetPublicId(), "ids=*;type=*;actions=*")
	iam.TestUserRole(t, conn, allowedRole.GetPublicId(), u.GetPublicId())
	for _, scope := range []*iam.Scope{oWithGroups, oNoGroups, pWithGroups, pNoGroups} {
		allowedRole := iam.TestRole(t, conn, scope.GetPublicId())
		iam.TestRoleGrant(t, conn, allowedRole.GetPublicId(), "ids=*;type=*;actions=*")
		iam.TestUserRole(t, conn, allowedRole.GetPublicId(), u.GetPublicId())
	}

	at, err := tokenRepo.CreateAuthToken(ctx, u, acct.GetPublicId())
	require.NoError(t, err)

	// Test without anon user
	requestInfo := authpb.RequestInfo{
		TokenFormat: uint32(auth.AuthTokenTypeBearer),
		PublicId:    at.GetPublicId(),
		Token:       at.GetToken(),
	}
	requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
	ctx = auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)

	var allGroups []*pb.Group
	var projGroups []*pb.Group
	var orgGroups []*pb.Group
	var globalGroups []*pb.Group
	var safeToDeleteGroup string
	globalScopeInfo := &scopes.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: "global", Description: "Global Scope"}
	orgScopeInfo := &scopes.ScopeInfo{Id: oWithGroups.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()}
	projScopeInfo := &scopes.ScopeInfo{Id: pWithGroups.GetPublicId(), Type: scope.Project.String(), ParentScopeId: pWithGroups.GetParentId()}
	for i := 0; i < 10; i++ {
		gg := iam.TestGroup(t, conn, scope.Global.String())
		allGroups = append(allGroups, groupToProto(gg, globalScopeInfo, testAuthorizedActions))
		globalGroups = append(globalGroups, groupToProto(gg, globalScopeInfo, testAuthorizedActions))
		og := iam.TestGroup(t, conn, oWithGroups.GetPublicId())
		allGroups = append(allGroups, groupToProto(og, orgScopeInfo, testAuthorizedActions))
		orgGroups = append(orgGroups, groupToProto(og, orgScopeInfo, testAuthorizedActions))
		pg := iam.TestGroup(t, conn, pWithGroups.GetPublicId())
		allGroups = append(allGroups, groupToProto(pg, projScopeInfo, testAuthorizedActions))
		projGroups = append(projGroups, groupToProto(pg, projScopeInfo, testAuthorizedActions))
		safeToDeleteGroup = pg.GetPublicId()
	}
	slices.Reverse(allGroups)
	slices.Reverse(projGroups)
	slices.Reverse(orgGroups)
	slices.Reverse(globalGroups)

	a, err := groups.NewService(ctx, iamRepoFn, 1000)
	require.NoError(t, err, "Couldn't create new group service.")

	// Run analyze to update postgres estimates
	_, err = sqlDB.ExecContext(context.Background(), "analyze")
	require.NoError(t, err)

	itemCount := uint32(len(allGroups))
	testPageSize := int((itemCount - 2) / 2)

	// Start paginating, recursively
	req := &pbs.ListGroupsRequest{
		ScopeId:   "global",
		Recursive: true,
		Filter:    "",
		ListToken: "",
		PageSize:  uint32(testPageSize),
	}
	got, err := a.ListGroups(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), testPageSize)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListGroupsResponse{
				Items:        allGroups[0:testPageSize],
				ResponseType: "delta",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				// In addition to the added groups, there are the groups added
				// by the test setup when specifying the permissions of the
				// requester
				EstItemCount: itemCount,
			},
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListGroupsResponse{}, "list_token"),
		),
	)

	// Request second page
	req.ListToken = got.ListToken
	got, err = a.ListGroups(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), testPageSize)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListGroupsResponse{
				Items:        allGroups[testPageSize : testPageSize*2],
				ResponseType: "delta",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: itemCount,
			},
			protocmp.Transform(),
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.IgnoreFields(&pbs.ListGroupsResponse{}, "list_token"),
		),
	)

	// Request rest of results
	req.ListToken = got.ListToken
	req.PageSize = 10
	got, err = a.ListGroups(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 2)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListGroupsResponse{
				Items:        allGroups[testPageSize*2:],
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: itemCount,
			},
			protocmp.Transform(),
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.IgnoreFields(&pbs.ListGroupsResponse{}, "list_token"),
		),
	)

	// Update 2 groups and see them in the refresh
	g1 := allGroups[len(allGroups)-1]
	g1.Description = wrapperspb.String("updated1")
	resp1, err := a.UpdateGroup(ctx, &pbs.UpdateGroupRequest{
		Id:         g1.GetId(),
		Item:       &pb.Group{Description: g1.GetDescription(), Version: g1.GetVersion()},
		UpdateMask: &field_mask.FieldMask{Paths: []string{"description"}},
	})
	require.NoError(t, err)
	g1.UpdatedTime = resp1.GetItem().GetUpdatedTime()
	g1.Version = resp1.GetItem().GetVersion()
	allGroups = append([]*pb.Group{g1}, allGroups[:len(allGroups)-1]...)

	g2 := allGroups[len(allGroups)-1]
	g2.Description = wrapperspb.String("updated2")
	resp2, err := a.UpdateGroup(ctx, &pbs.UpdateGroupRequest{
		Id:         g2.GetId(),
		Item:       &pb.Group{Description: g2.GetDescription(), Version: g2.GetVersion()},
		UpdateMask: &field_mask.FieldMask{Paths: []string{"description"}},
	})
	require.NoError(t, err)
	g2.UpdatedTime = resp2.GetItem().GetUpdatedTime()
	g2.Version = resp2.GetItem().GetVersion()
	allGroups = append([]*pb.Group{g2}, allGroups[:len(allGroups)-1]...)

	// Run analyze to update postgres estimates
	_, err = sqlDB.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	// Request updated results
	req.ListToken = got.ListToken
	req.PageSize = 1
	got, err = a.ListGroups(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 1)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListGroupsResponse{
				Items:        []*pb.Group{allGroups[0]},
				ResponseType: "delta",
				SortBy:       "updated_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: itemCount,
			},
			protocmp.Transform(),
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.IgnoreFields(&pbs.ListGroupsResponse{}, "list_token"),
		),
	)

	// Get next page
	req.ListToken = got.ListToken
	got, err = a.ListGroups(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 1)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListGroupsResponse{
				Items:        []*pb.Group{allGroups[1]},
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: itemCount,
			},
			protocmp.Transform(),
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.IgnoreFields(&pbs.ListGroupsResponse{}, "list_token"),
		),
	)

	// Request new page with filter requiring looping
	// to fill the page.
	req.ListToken = ""
	req.PageSize = 1
	req.Filter = fmt.Sprintf(`"/item/id"==%q or "/item/id"==%q`, allGroups[len(allGroups)-2].Id, allGroups[len(allGroups)-1].Id)
	got, err = a.ListGroups(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 1)
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListGroupsResponse{
				Items:        []*pb.Group{allGroups[len(allGroups)-2]},
				ResponseType: "delta",
				SortBy:       "created_time",
				SortDir:      "desc",
				// Should be empty again
				RemovedIds:   nil,
				EstItemCount: itemCount,
			},
			protocmp.Transform(),
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.IgnoreFields(&pbs.ListGroupsResponse{}, "list_token"),
		),
	)
	req.ListToken = got.ListToken
	// Get the second page
	got, err = a.ListGroups(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 1)
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListGroupsResponse{
				Items:        []*pb.Group{allGroups[len(allGroups)-1]},
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: itemCount,
			},
			protocmp.Transform(),
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.IgnoreFields(&pbs.ListGroupsResponse{}, "list_token"),
		),
	)

	_, err = iamRepo.DeleteGroup(ctx, safeToDeleteGroup)
	require.NoError(t, err)
	req.ListToken = got.ListToken
	got, err = a.ListGroups(ctx, req)
	require.NoError(t, err)
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListGroupsResponse{
				Items:        nil,
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "desc",
				RemovedIds:   []string{safeToDeleteGroup},
				EstItemCount: itemCount,
			},
			protocmp.Transform(),
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.IgnoreFields(&pbs.ListGroupsResponse{}, "list_token"),
		),
	)

	// Create unauthenticated user
	unauthAt := authtoken.TestAuthToken(t, conn, kms, oWithGroups.GetPublicId())
	unauthR := iam.TestRole(t, conn, pWithGroups.GetPublicId())
	_ = iam.TestUserRole(t, conn, unauthR.GetPublicId(), unauthAt.GetIamUserId())

	// Make a request with the unauthenticated user,
	// ensure the response is 403 forbidden.
	requestInfo = authpb.RequestInfo{
		TokenFormat: uint32(auth.AuthTokenTypeBearer),
		PublicId:    unauthAt.GetPublicId(),
		Token:       unauthAt.GetToken(),
	}
	requestContext = context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
	ctx = auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)

	_, err = a.ListGroups(ctx, &pbs.ListGroupsRequest{
		ScopeId:   "global",
		Recursive: true,
	})
	require.Error(t, err)
	assert.Equal(t, handlers.ForbiddenError(), err)
}

func TestDelete(t *testing.T) {
	og, pg, repoFn := createDefaultGroupsAndRepo(t)

	s, err := groups.NewService(context.Background(), repoFn, 1000)
	require.NoError(t, err, "Error when getting new group service.")

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.DeleteGroupRequest
		res     *pbs.DeleteGroupResponse
		err     error
	}{
		{
			name:    "Delete an Existing Group",
			scopeId: og.GetScopeId(),
			req: &pbs.DeleteGroupRequest{
				Id: og.GetPublicId(),
			},
		},
		{
			name:    "Delete bad group id",
			scopeId: og.GetScopeId(),
			req: &pbs.DeleteGroupRequest{
				Id: globals.GroupPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Bad Group Id formatting",
			scopeId: og.GetScopeId(),
			req: &pbs.DeleteGroupRequest{
				Id: "bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Project Scoped Delete an Existing Group",
			scopeId: pg.GetScopeId(),
			req: &pbs.DeleteGroupRequest{
				Id: pg.GetPublicId(),
			},
		},
		{
			name:    "Project Scoped Delete bad group id",
			scopeId: pg.GetScopeId(),
			req: &pbs.DeleteGroupRequest{
				Id: globals.GroupPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteGroup(auth.DisabledAuthTestContext(repoFn, tc.scopeId), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteGroup(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.EqualValuesf(tc.res, got, "DeleteGroup(%+v) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	og, pg, repoFn := createDefaultGroupsAndRepo(t)

	s, err := groups.NewService(context.Background(), repoFn, 1000)
	require.NoError(err, "Error when getting new group service")
	scopeId := og.GetScopeId()
	req := &pbs.DeleteGroupRequest{
		Id: og.GetPublicId(),
	}
	ctx := auth.DisabledAuthTestContext(repoFn, scopeId)
	_, gErr := s.DeleteGroup(ctx, req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteGroup(ctx, req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")

	scopeId = pg.GetScopeId()
	projReq := &pbs.DeleteGroupRequest{
		Id: pg.GetPublicId(),
	}
	ctx = auth.DisabledAuthTestContext(repoFn, scopeId)
	_, gErr = s.DeleteGroup(ctx, projReq)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteGroup(ctx, projReq)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")
}

func TestCreate(t *testing.T) {
	defaultOGroup, defaultPGroup, repoFn := createDefaultGroupsAndRepo(t)
	defaultCreated := defaultOGroup.GetCreateTime().GetTimestamp().AsTime()
	toMerge := &pbs.CreateGroupRequest{}

	cases := []struct {
		name string
		req  *pbs.CreateGroupRequest
		res  *pbs.CreateGroupResponse
		err  error
	}{
		{
			name: "Create a valid Group",
			req: &pbs.CreateGroupRequest{Item: &pb.Group{
				ScopeId:     defaultOGroup.GetScopeId(),
				Name:        &wrapperspb.StringValue{Value: "name"},
				Description: &wrapperspb.StringValue{Value: "desc"},
			}},
			res: &pbs.CreateGroupResponse{
				Uri: fmt.Sprintf("groups/%s_", globals.GroupPrefix),
				Item: &pb.Group{
					ScopeId:           defaultOGroup.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: defaultOGroup.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:              &wrapperspb.StringValue{Value: "name"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					Version:           1,
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Create a global Group",
			req: &pbs.CreateGroupRequest{Item: &pb.Group{
				ScopeId:     scope.Global.String(),
				Name:        &wrapperspb.StringValue{Value: "name"},
				Description: &wrapperspb.StringValue{Value: "desc"},
			}},
			res: &pbs.CreateGroupResponse{
				Uri: fmt.Sprintf("groups/%s_", globals.GroupPrefix),
				Item: &pb.Group{
					ScopeId:           scope.Global.String(),
					Scope:             &scopes.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
					Name:              &wrapperspb.StringValue{Value: "name"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					Version:           1,
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Create a valid Project Scoped Group",
			req: &pbs.CreateGroupRequest{
				Item: &pb.Group{
					ScopeId:     defaultPGroup.GetScopeId(),
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.CreateGroupResponse{
				Uri: fmt.Sprintf("groups/%s_", globals.GroupPrefix),
				Item: &pb.Group{
					ScopeId:           defaultPGroup.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: defaultPGroup.GetScopeId(), Type: scope.Project.String(), ParentScopeId: defaultOGroup.GetScopeId()},
					Name:              &wrapperspb.StringValue{Value: "name"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					Version:           1,
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateGroupRequest{Item: &pb.Group{
				Id: globals.GroupPrefix + "_notallowed",
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateGroupRequest{Item: &pb.Group{
				CreatedTime: timestamppb.Now(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateGroupRequest{Item: &pb.Group{
				UpdatedTime: timestamppb.Now(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.CreateGroupRequest)
			proto.Merge(req, tc.req)

			s, err := groups.NewService(context.Background(), repoFn, 1000)
			require.NoError(err, "Error when getting new group service.")

			got, gErr := s.CreateGroup(auth.DisabledAuthTestContext(repoFn, req.GetItem().GetScopeId()), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateGroup(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				assert.True(strings.HasPrefix(got.GetItem().GetId(), globals.GroupPrefix+"_"))
				gotCreateTime := got.GetItem().GetCreatedTime().AsTime()
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
				// Verify it is a group created after the test setup's default group
				assert.True(gotCreateTime.After(defaultCreated), "New group should have been created after default group. Was created %v, which is after %v", gotCreateTime, defaultCreated)
				assert.True(gotUpdateTime.After(defaultCreated), "New group should have been updated after default group. Was updated %v, which is after %v", gotUpdateTime, defaultCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "CreateGroup(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	o, p := iam.TestScopes(t, iamRepo)
	u := iam.TestUser(t, iamRepo, o.GetPublicId())

	og := iam.TestGroup(t, conn, o.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	_ = iam.TestGroupMember(t, conn, og.GetPublicId(), u.GetPublicId())

	pg := iam.TestGroup(t, conn, p.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	_ = iam.TestGroupMember(t, conn, pg.GetPublicId(), u.GetPublicId())

	var ogVersion uint32 = 1
	var pgVersion uint32 = 1

	resetGroups := func(proj bool) {
		repo, err := repoFn()
		require.NoError(t, err, "Couldn't get a new repo")
		if proj {
			pgVersion++
			pg, _, _, err = repo.UpdateGroup(ctx, pg, pgVersion, []string{"Name", "Description"})
			require.NoError(t, err, "Failed to reset the group")
			pgVersion++
		} else {
			ogVersion++
			og, _, _, err = repo.UpdateGroup(ctx, og, ogVersion, []string{"Name", "Description"})
			require.NoError(t, err, "Failed to reset the group")
			ogVersion++
		}
	}

	created := og.GetCreateTime().GetTimestamp().AsTime()
	toMerge := &pbs.UpdateGroupRequest{
		Id: og.GetPublicId(),
	}

	tested, err := groups.NewService(ctx, repoFn, 1000)
	require.NoError(t, err, "Error creating new service")
	cases := []struct {
		name    string
		scopeId string
		req     *pbs.UpdateGroupRequest
		res     *pbs.UpdateGroupResponse
		err     error
	}{
		{
			name:    "Update an Existing Group",
			scopeId: og.GetScopeId(),
			req: &pbs.UpdateGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateGroupResponse{
				Item: &pb.Group{
					Id:          og.GetPublicId(),
					ScopeId:     og.GetScopeId(),
					Scope:       &scopes.ScopeInfo{Id: og.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: og.GetCreateTime().GetTimestamp(),
					MemberIds:   []string{u.GetPublicId()},
					Members: []*pb.Member{
						{
							Id:      u.GetPublicId(),
							ScopeId: u.GetScopeId(),
						},
					},
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name:    "Multiple Paths in single string",
			scopeId: og.GetScopeId(),
			req: &pbs.UpdateGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateGroupResponse{
				Item: &pb.Group{
					Id:          og.GetPublicId(),
					ScopeId:     og.GetScopeId(),
					Scope:       &scopes.ScopeInfo{Id: og.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: og.GetCreateTime().GetTimestamp(),
					MemberIds:   []string{u.GetPublicId()},
					Members: []*pb.Member{
						{
							Id:      u.GetPublicId(),
							ScopeId: u.GetScopeId(),
						},
					},
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name:    "Update an Existing Project Scoped Group",
			scopeId: pg.GetScopeId(),
			req: &pbs.UpdateGroupRequest{
				Id: pg.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateGroupResponse{
				Item: &pb.Group{
					Id:          pg.GetPublicId(),
					ScopeId:     pg.GetScopeId(),
					Scope:       &scopes.ScopeInfo{Id: pg.GetScopeId(), Type: scope.Project.String(), ParentScopeId: og.GetScopeId()},
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: pg.GetCreateTime().GetTimestamp(),
					MemberIds:   []string{u.GetPublicId()},
					Members: []*pb.Member{
						{
							Id:      u.GetPublicId(),
							ScopeId: u.GetScopeId(),
						},
					},
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name:    "Multiple Paths in single string",
			scopeId: pg.GetScopeId(),
			req: &pbs.UpdateGroupRequest{
				Id: pg.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateGroupResponse{
				Item: &pb.Group{
					Id:          pg.GetPublicId(),
					ScopeId:     pg.GetScopeId(),
					Scope:       &scopes.ScopeInfo{Id: pg.GetScopeId(), Type: scope.Project.String(), ParentScopeId: og.GetScopeId()},
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: pg.GetCreateTime().GetTimestamp(),
					MemberIds:   []string{u.GetPublicId()},
					Members: []*pb.Member{
						{
							Id:      u.GetPublicId(),
							ScopeId: u.GetScopeId(),
						},
					},
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateGroupRequest{
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "No Paths in Mask",
			scopeId: og.GetScopeId(),
			req: &pbs.UpdateGroupRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Only non-existent paths in Mask",
			scopeId: og.GetScopeId(),
			req: &pbs.UpdateGroupRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistent_field"}},
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "Unset Name",
			scopeId: og.GetScopeId(),
			req: &pbs.UpdateGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Group{
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateGroupResponse{
				Item: &pb.Group{
					Id:          og.GetPublicId(),
					ScopeId:     og.GetScopeId(),
					Scope:       &scopes.ScopeInfo{Id: og.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Description: &wrapperspb.StringValue{Value: "default"},
					CreatedTime: og.GetCreateTime().GetTimestamp(),
					MemberIds:   []string{u.GetPublicId()},
					Members: []*pb.Member{
						{
							Id:      u.GetPublicId(),
							ScopeId: u.GetScopeId(),
						},
					},
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name:    "Update Only Name",
			scopeId: og.GetScopeId(),
			req: &pbs.UpdateGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateGroupResponse{
				Item: &pb.Group{
					Id:          og.GetPublicId(),
					ScopeId:     og.GetScopeId(),
					Scope:       &scopes.ScopeInfo{Id: og.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "default"},
					CreatedTime: og.GetCreateTime().GetTimestamp(),
					MemberIds:   []string{u.GetPublicId()},
					Members: []*pb.Member{
						{
							Id:      u.GetPublicId(),
							ScopeId: u.GetScopeId(),
						},
					},
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name:    "Update Only Description",
			scopeId: og.GetScopeId(),
			req: &pbs.UpdateGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
				},
			},
			res: &pbs.UpdateGroupResponse{
				Item: &pb.Group{
					Id:          og.GetPublicId(),
					ScopeId:     og.GetScopeId(),
					Scope:       &scopes.ScopeInfo{Id: og.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
					CreatedTime: og.GetCreateTime().GetTimestamp(),
					MemberIds:   []string{u.GetPublicId()},
					Members: []*pb.Member{
						{
							Id:      u.GetPublicId(),
							ScopeId: u.GetScopeId(),
						},
					},
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Update a Non Existing Group",
			req: &pbs.UpdateGroupRequest{
				Id: globals.GroupPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateGroupRequest{
				Id: og.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.Group{
					Id:          globals.GroupPrefix + "_somethinge",
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "new desc"},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.Group{
					CreatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.Group{
					UpdatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ver := ogVersion
			if tc.req.Id == pg.PublicId {
				ver = pgVersion
			}
			tc.req.Item.Version = ver

			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.UpdateGroupRequest)
			proto.Merge(req, tc.req)

			// Test with bad version (too high, too low)
			req.Item.Version = ver + 2
			_, gErr := tested.UpdateGroup(auth.DisabledAuthTestContext(repoFn, tc.scopeId), req)
			require.Error(gErr)
			req.Item.Version = ver - 1
			_, gErr = tested.UpdateGroup(auth.DisabledAuthTestContext(repoFn, tc.scopeId), req)
			require.Error(gErr)
			req.Item.Version = ver

			got, gErr := tested.UpdateGroup(auth.DisabledAuthTestContext(repoFn, tc.scopeId), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateGroup(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}

			if tc.err == nil {
				defer resetGroups(req.Id == pg.PublicId)
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateGroup response to be nil, but was %v", got)
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
				// Verify it is a group updated after it was created
				assert.True(gotUpdateTime.After(created), "Updated group should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

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
			), "UpdateGroup(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestAddMember(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := groups.NewService(context.Background(), repoFn, 100)
	require.NoError(t, err, "Error when getting new group service.")

	o, p := iam.TestScopes(t, iamRepo)
	users := []*iam.User{
		iam.TestUser(t, iamRepo, o.GetPublicId()),
		iam.TestUser(t, iamRepo, o.GetPublicId()),
		iam.TestUser(t, iamRepo, o.GetPublicId()),
	}

	addCases := []struct {
		name         string
		setup        func(*iam.Group)
		addUsers     []string
		addGroups    []string
		resultUsers  []string
		resultGroups []string
		wantErr      bool
	}{
		{
			name:        "Add user on empty group",
			setup:       func(g *iam.Group) {},
			addUsers:    []string{users[1].GetPublicId()},
			resultUsers: []string{users[1].GetPublicId()},
		},
		{
			name: "Add user on populated group",
			setup: func(g *iam.Group) {
				iam.TestGroupMember(t, conn, g.GetPublicId(), users[0].GetPublicId())
			},
			addUsers:    []string{users[1].GetPublicId()},
			resultUsers: []string{users[0].GetPublicId(), users[1].GetPublicId()},
		},
		{
			name: "Add duplicate user on populated group",
			setup: func(g *iam.Group) {
				iam.TestGroupMember(t, conn, g.GetPublicId(), users[0].GetPublicId())
			},
			addUsers:    []string{users[1].GetPublicId(), users[1].GetPublicId()},
			resultUsers: []string{users[0].GetPublicId(), users[1].GetPublicId()},
		},
		{
			name: "Add empty on populated group",
			setup: func(g *iam.Group) {
				iam.TestGroupMember(t, conn, g.GetPublicId(), users[0].GetPublicId())
				iam.TestGroupMember(t, conn, g.GetPublicId(), users[1].GetPublicId())
			},
			wantErr: true,
		},
		{
			name:     "Add invalid u_recovery to group",
			setup:    func(g *iam.Group) {},
			addUsers: []string{globals.RecoveryUserId},
			wantErr:  true,
		},
	}

	for _, tc := range addCases {
		for _, scp := range []*iam.Scope{o, p} {
			t.Run(tc.name+"_"+scp.GetType(), func(t *testing.T) {
				grp := iam.TestGroup(t, conn, scp.GetPublicId())
				tc.setup(grp)
				req := &pbs.AddGroupMembersRequest{
					Id:        grp.GetPublicId(),
					Version:   grp.GetVersion(),
					MemberIds: tc.addUsers,
				}

				got, err := s.AddGroupMembers(auth.DisabledAuthTestContext(repoFn, scp.GetPublicId()), req)
				if tc.wantErr {
					assert.Error(t, err)
					return
				}
				s, ok := status.FromError(err)
				require.True(t, ok)
				require.NoError(t, err, "Got error: %v", s)

				assert.True(t, equalMembers(got.GetItem(), tc.resultUsers))
			})
		}
	}

	grp := iam.TestGroup(t, conn, p.GetPublicId())

	failCases := []struct {
		name string
		req  *pbs.AddGroupMembersRequest
		err  error
	}{
		{
			name: "Bad Group Id",
			req: &pbs.AddGroupMembersRequest{
				Id:      "bad id",
				Version: grp.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid user id in member list",
			req: &pbs.AddGroupMembersRequest{
				Id:        grp.GetPublicId(),
				Version:   grp.GetVersion(),
				MemberIds: []string{"invalid"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "u_recovery",
			req: &pbs.AddGroupMembersRequest{
				Id:        grp.GetPublicId(),
				Version:   grp.GetVersion(),
				MemberIds: []string{globals.RecoveryUserId},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.AddGroupMembers(auth.DisabledAuthTestContext(repoFn, grp.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "AddGroupMembers(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestSetMember(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := groups.NewService(context.Background(), repoFn, 1000)
	require.NoError(t, err, "Error when getting new group service.")

	o, p := iam.TestScopes(t, iamRepo)
	users := []*iam.User{
		iam.TestUser(t, iamRepo, o.GetPublicId()),
		iam.TestUser(t, iamRepo, o.GetPublicId()),
		iam.TestUser(t, iamRepo, o.GetPublicId()),
	}

	setCases := []struct {
		name         string
		setup        func(*iam.Group)
		setUsers     []string
		setGroups    []string
		resultUsers  []string
		resultGroups []string
		wantErr      bool
	}{
		{
			name:        "Set user on empty group",
			setup:       func(r *iam.Group) {},
			setUsers:    []string{users[1].GetPublicId()},
			resultUsers: []string{users[1].GetPublicId()},
		},
		{
			name: "Set user on populated group",
			setup: func(r *iam.Group) {
				iam.TestGroupMember(t, conn, r.GetPublicId(), users[0].GetPublicId())
			},
			setUsers:    []string{users[1].GetPublicId()},
			resultUsers: []string{users[1].GetPublicId()},
		},
		{
			name: "Set duplicate user on populated group",
			setup: func(r *iam.Group) {
				iam.TestGroupMember(t, conn, r.GetPublicId(), users[0].GetPublicId())
			},
			setUsers:    []string{users[1].GetPublicId(), users[1].GetPublicId()},
			resultUsers: []string{users[1].GetPublicId()},
		},
		{
			name: "Set empty on populated group",
			setup: func(r *iam.Group) {
				iam.TestGroupMember(t, conn, r.GetPublicId(), users[0].GetPublicId())
				iam.TestGroupMember(t, conn, r.GetPublicId(), users[1].GetPublicId())
			},
			setUsers:    []string{},
			resultUsers: nil,
		},
	}

	for _, tc := range setCases {
		for _, scp := range []*iam.Scope{o, p} {
			t.Run(tc.name+"_"+scp.GetType(), func(t *testing.T) {
				grp := iam.TestGroup(t, conn, scp.GetPublicId())
				tc.setup(grp)
				req := &pbs.SetGroupMembersRequest{
					Id:        grp.GetPublicId(),
					Version:   grp.GetVersion(),
					MemberIds: tc.setUsers,
				}

				got, err := s.SetGroupMembers(auth.DisabledAuthTestContext(repoFn, scp.GetPublicId()), req)
				if tc.wantErr {
					assert.Error(t, err)
					return
				}
				s, ok := status.FromError(err)
				require.True(t, ok)
				require.NoError(t, err, "Got error: %v", s)

				assert.True(t, equalMembers(got.GetItem(), append(tc.resultUsers, tc.resultGroups...)))
			})
		}
	}

	grp := iam.TestGroup(t, conn, p.GetPublicId())

	failCases := []struct {
		name string
		req  *pbs.SetGroupMembersRequest
		err  error
	}{
		{
			name: "Bad Group Id",
			req: &pbs.SetGroupMembersRequest{
				Id:      "bad id",
				Version: grp.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid user id in member list",
			req: &pbs.SetGroupMembersRequest{
				Id:        grp.GetPublicId(),
				Version:   grp.GetVersion(),
				MemberIds: []string{"invalid"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "u_recovery",
			req: &pbs.SetGroupMembersRequest{
				Id:        grp.GetPublicId(),
				Version:   grp.GetVersion(),
				MemberIds: []string{globals.RecoveryUserId},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.SetGroupMembers(auth.DisabledAuthTestContext(repoFn, grp.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "SetGroupMembers(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestRemoveMember(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := groups.NewService(context.Background(), repoFn, 1000)
	require.NoError(t, err, "Error when getting new grp service.")

	o, p := iam.TestScopes(t, iamRepo)
	users := []*iam.User{
		iam.TestUser(t, iamRepo, o.GetPublicId()),
		iam.TestUser(t, iamRepo, o.GetPublicId()),
		iam.TestUser(t, iamRepo, o.GetPublicId()),
	}

	addCases := []struct {
		name         string
		setup        func(*iam.Group)
		removeUsers  []string
		removeGroups []string
		resultUsers  []string
		resultGroups []string
		wantErr      bool
	}{
		{
			name:        "Remove user on empty group",
			setup:       func(r *iam.Group) {},
			removeUsers: []string{users[1].GetPublicId()},
			wantErr:     true,
		},
		{
			name: "Remove 1 of 2 users from group",
			setup: func(r *iam.Group) {
				iam.TestGroupMember(t, conn, r.GetPublicId(), users[0].GetPublicId())
				iam.TestGroupMember(t, conn, r.GetPublicId(), users[1].GetPublicId())
			},
			removeUsers: []string{users[1].GetPublicId()},
			resultUsers: []string{users[0].GetPublicId()},
		},
		{
			name: "Remove all users from group",
			setup: func(r *iam.Group) {
				iam.TestGroupMember(t, conn, r.GetPublicId(), users[0].GetPublicId())
				iam.TestGroupMember(t, conn, r.GetPublicId(), users[1].GetPublicId())
			},
			removeUsers: []string{users[0].GetPublicId(), users[1].GetPublicId()},
			resultUsers: []string{},
		},
		{
			name: "Remove duplicate user from group",
			setup: func(r *iam.Group) {
				iam.TestGroupMember(t, conn, r.GetPublicId(), users[0].GetPublicId())
				iam.TestGroupMember(t, conn, r.GetPublicId(), users[1].GetPublicId())
			},
			removeUsers: []string{users[0].GetPublicId(), users[0].GetPublicId()},
			resultUsers: []string{users[1].GetPublicId()},
		},
		{
			name: "Remove empty on populated group",
			setup: func(r *iam.Group) {
				iam.TestGroupMember(t, conn, r.GetPublicId(), users[0].GetPublicId())
			},
			wantErr: true,
		},
	}

	for _, tc := range addCases {
		for _, scp := range []*iam.Scope{o, p} {
			t.Run(tc.name+"_"+scp.GetType(), func(t *testing.T) {
				grp := iam.TestGroup(t, conn, scp.GetPublicId())
				tc.setup(grp)
				req := &pbs.RemoveGroupMembersRequest{
					Id:        grp.GetPublicId(),
					Version:   grp.GetVersion(),
					MemberIds: tc.removeUsers,
				}

				got, err := s.RemoveGroupMembers(auth.DisabledAuthTestContext(repoFn, scp.GetPublicId()), req)
				if tc.wantErr {
					assert.Error(t, err)
					return
				}
				s, ok := status.FromError(err)
				require.True(t, ok)
				require.NoError(t, err, "Got error: %v", s)

				assert.True(t, equalMembers(got.GetItem(), tc.resultUsers))
			})
		}
	}

	grp := iam.TestGroup(t, conn, p.GetPublicId())

	failCases := []struct {
		name string
		req  *pbs.RemoveGroupMembersRequest
		err  error
	}{
		{
			name: "Bad Group Id",
			req: &pbs.RemoveGroupMembersRequest{
				Id:      "bad id",
				Version: grp.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid user id in member list",
			req: &pbs.RemoveGroupMembersRequest{
				Id:        grp.GetPublicId(),
				Version:   grp.GetVersion(),
				MemberIds: []string{"invalid"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.RemoveGroupMembers(auth.DisabledAuthTestContext(repoFn, grp.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "RemoveGroupMembers(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}
