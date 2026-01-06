// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package users_test

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
	talias "github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/users"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/boundary/internal/types/scope"
	pbalias "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/aliases"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/users"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testAuthorizedActions = []string{"no-op", "read", "update", "delete", "add-accounts", "set-accounts", "remove-accounts", "list-resolvable-aliases"}

func createDefaultUserAndRepos(t *testing.T, withAccts bool) (*iam.User, []string, common.IamRepoFactory, common.TargetAliasRepoFactory) {
	t.Helper()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	rw := db.New(conn)
	repo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return repo, nil
	}
	aliasRepoFn := func() (*talias.Repository, error) {
		return talias.NewRepository(context.Background(), rw, rw, kmsCache)
	}
	o, _ := iam.TestScopes(t, repo)
	u := iam.TestUser(t, repo, o.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))

	switch withAccts {
	case false:
		return u, nil, repoFn, aliasRepoFn
	default:
		require := require.New(t)
		databaseWrap, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)
		primaryAm := oidc.TestAuthMethod(t, conn, databaseWrap, o.PublicId, oidc.ActivePublicState, "alice-rp", "fido",
			oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice-eve-smith.com")[0]),
			oidc.WithApiUrl(oidc.TestConvertToUrls(t, "http://localhost:9200")[0]),
			oidc.WithSigningAlgs(oidc.RS256),
		)
		iam.TestSetPrimaryAuthMethod(t, repo, o, primaryAm.PublicId)

		oidcAcct := oidc.TestAccount(t, conn, primaryAm, "alice", oidc.WithFullName("Alice Eve Smith"), oidc.WithEmail("alice@smith.com"))

		secondaryAm := password.TestAuthMethods(t, conn, o.PublicId, 1)
		require.Len(secondaryAm, 1)
		pwAcct := password.TestAccount(t, conn, secondaryAm[0].PublicId, "alice")

		added, err := repo.AddUserAccounts(ctx, u.PublicId, u.Version, []string{oidcAcct.PublicId, pwAcct.PublicId})
		require.NoError(err)
		require.Len(added, 2)

		// reload the user with their accounts
		u, accts, err := repo.LookupUser(ctx, u.PublicId)
		require.NoError(err)
		return u, accts, repoFn, aliasRepoFn
	}
}

func TestGet(t *testing.T) {
	u, uAccts, repoFn, aliasRepo := createDefaultUserAndRepos(t, true)

	toMerge := &pbs.GetUserRequest{
		Id: u.GetPublicId(),
	}

	wantU := &pb.User{
		Id:                u.GetPublicId(),
		ScopeId:           u.GetScopeId(),
		Scope:             &scopes.ScopeInfo{Id: u.ScopeId, Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
		Name:              &wrapperspb.StringValue{Value: u.GetName()},
		Description:       &wrapperspb.StringValue{Value: u.GetDescription()},
		CreatedTime:       u.CreateTime.GetTimestamp(),
		UpdatedTime:       u.UpdateTime.GetTimestamp(),
		Version:           u.Version,
		AuthorizedActions: testAuthorizedActions,
		LoginName:         u.LoginName,
		FullName:          u.GetFullName(),
		Email:             u.GetEmail(),
		PrimaryAccountId:  u.GetPrimaryAccountId(),
		AccountIds:        uAccts,
		Accounts:          []*pb.Account{{Id: uAccts[0], ScopeId: u.ScopeId}, {Id: uAccts[1], ScopeId: u.ScopeId}},
	}

	cases := []struct {
		name string
		req  *pbs.GetUserRequest
		res  *pbs.GetUserResponse
		err  error
	}{
		{
			name: "Get an Existing User",
			req:  &pbs.GetUserRequest{Id: u.GetPublicId()},
			res:  &pbs.GetUserResponse{Item: wantU},
		},
		{
			name: "Get a non existent User",
			req:  &pbs.GetUserRequest{Id: globals.UserPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Wrong id prefix",
			req:  &pbs.GetUserRequest{Id: "j_1234567890"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "space in id",
			req:  &pbs.GetUserRequest{Id: globals.UserPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.GetUserRequest)
			proto.Merge(req, tc.req)

			s, err := users.NewService(context.Background(), repoFn, aliasRepo, 1000)
			require.NoError(err, "Couldn't create new user service.")

			got, gErr := s.GetUser(auth.DisabledAuthTestContext(repoFn, u.GetScopeId()), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetUser(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "GetUser(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	aliasRepoFn := func() (*talias.Repository, error) {
		return talias.NewRepository(context.Background(), rw, rw, kmsCache)
	}

	oNoUsers, _ := iam.TestScopes(t, iamRepo)
	oWithUsers, _ := iam.TestScopes(t, iamRepo)

	databaseWrap, err := kmsCache.GetWrapper(context.Background(), oWithUsers.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	primaryAm := oidc.TestAuthMethod(t, conn, databaseWrap, oWithUsers.PublicId, oidc.ActivePublicState, "alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice-eve-smith.com")[0]),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "http://localhost:9200")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
	)
	iam.TestSetPrimaryAuthMethod(t, iamRepo, oWithUsers, primaryAm.PublicId)

	secondaryAm := password.TestAuthMethods(t, conn, oWithUsers.PublicId, 1)
	require.Len(t, secondaryAm, 1)

	s, err := users.NewService(context.Background(), repoFn, aliasRepoFn, 1000)
	require.NoError(t, err)

	var wantUsers []*pb.User

	// Populate expected values for recursive test
	var totalUsers []*pb.User
	{
		disabledAuthCtx := auth.DisabledAuthTestContext(repoFn, "global")
		anon, err := s.GetUser(disabledAuthCtx, &pbs.GetUserRequest{Id: globals.AnonymousUserId})
		require.NoError(t, err)
		totalUsers = append(totalUsers, anon.GetItem())
		authUser, err := s.GetUser(disabledAuthCtx, &pbs.GetUserRequest{Id: globals.AnyAuthenticatedUserId})
		require.NoError(t, err)
		totalUsers = append(totalUsers, authUser.GetItem())
		recovery, err := s.GetUser(disabledAuthCtx, &pbs.GetUserRequest{Id: globals.RecoveryUserId})
		require.NoError(t, err)
		totalUsers = append(totalUsers, recovery.GetItem())
	}

	// Add new users
	for i := 0; i < 10; i++ {
		newU, err := iam.NewUser(ctx, oWithUsers.GetPublicId())
		require.NoError(t, err)
		u, err := iamRepo.CreateUser(context.Background(), newU)
		require.NoError(t, err)
		oidcAcct := oidc.TestAccount(t, conn, primaryAm, fmt.Sprintf("alice+%d", i), oidc.WithFullName("Alice Eve Smith"), oidc.WithEmail("alice@smith.com"))
		pwAcct := password.TestAccount(t, conn, secondaryAm[0].PublicId, fmt.Sprintf("alice+%d", i))

		added, err := iamRepo.AddUserAccounts(ctx, u.PublicId, u.Version, []string{oidcAcct.PublicId, pwAcct.PublicId})
		require.NoError(t, err)
		require.Len(t, added, 2)

		u, _, err = iamRepo.LookupUser(ctx, u.PublicId)
		require.NoError(t, err)
		wantUsers = append(wantUsers, &pb.User{
			Id:                u.GetPublicId(),
			ScopeId:           u.GetScopeId(),
			Scope:             &scopes.ScopeInfo{Id: u.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			CreatedTime:       u.GetCreateTime().GetTimestamp(),
			UpdatedTime:       u.GetUpdateTime().GetTimestamp(),
			Version:           2,
			AuthorizedActions: testAuthorizedActions,
			LoginName:         oidcAcct.GetSubject(),
			FullName:          oidcAcct.GetFullName(),
			Email:             oidcAcct.GetEmail(),
			PrimaryAccountId:  oidcAcct.GetPublicId(),
		})
	}
	// Populate these users into the total
	totalUsers = append(totalUsers, wantUsers...)
	slices.Reverse(totalUsers)
	slices.Reverse(wantUsers)

	// Run analyze to update postgres estimates
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	cases := []struct {
		name string
		req  *pbs.ListUsersRequest
		res  *pbs.ListUsersResponse
		err  error
	}{
		{
			name: "List Many Users",
			req:  &pbs.ListUsersRequest{ScopeId: oWithUsers.GetPublicId()},
			res: &pbs.ListUsersResponse{
				Items:        wantUsers,
				EstItemCount: uint32(len(wantUsers)),
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "List No Users",
			req:  &pbs.ListUsersRequest{ScopeId: oNoUsers.GetPublicId()},
			res: &pbs.ListUsersResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "List Recursively in Org",
			req:  &pbs.ListUsersRequest{ScopeId: oWithUsers.GetPublicId(), Recursive: true},
			res: &pbs.ListUsersResponse{
				Items:        wantUsers,
				EstItemCount: uint32(len(wantUsers)),
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "List Recursively in Global",
			req:  &pbs.ListUsersRequest{ScopeId: "global", Recursive: true},
			res: &pbs.ListUsersResponse{
				Items:        totalUsers,
				EstItemCount: uint32(len(totalUsers)),
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "Filter Many Users",
			req:  &pbs.ListUsersRequest{ScopeId: "global", Recursive: true, Filter: fmt.Sprintf(`"/item/scope/id"==%q`, oWithUsers.GetPublicId())},
			res: &pbs.ListUsersResponse{
				Items:        wantUsers,
				EstItemCount: uint32(len(wantUsers)),
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "Filter To No Users",
			req:  &pbs.ListUsersRequest{ScopeId: oWithUsers.GetPublicId(), Filter: `"/item/id"=="doesntmatch"`},
			res: &pbs.ListUsersResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListUsersRequest{ScopeId: oWithUsers.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(err, "Couldn't create new user service.")

			// Test with non-anon user
			got, gErr := s.ListUsers(auth.DisabledAuthTestContext(repoFn, tc.req.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListUsers(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.IgnoreFields(&pbs.ListUsersResponse{}, "list_token"),
			), "ListUsers(%q) got response %q, wanted %q", tc.req, got, tc.res)
			// Test with anon user

			got, gErr = s.ListUsers(auth.DisabledAuthTestContext(repoFn, tc.req.GetScopeId(), auth.WithUserId(globals.AnonymousUserId)), tc.req)
			require.NoError(gErr)
			assert.Len(got.Items, len(tc.res.Items))
			for _, item := range got.GetItems() {
				require.Empty(item.Version)
				require.Nil(item.CreatedTime)
				require.Nil(item.UpdatedTime)
				require.Nil(item.Accounts)
				require.Nil(item.AccountIds)
			}
		})
	}
}

func userToProto(u *iam.User, si *scopes.ScopeInfo, authorizedActions []string) *pb.User {
	pu := &pb.User{
		Id:                u.GetPublicId(),
		ScopeId:           u.GetScopeId(),
		Scope:             si,
		CreatedTime:       u.GetCreateTime().GetTimestamp(),
		UpdatedTime:       u.GetUpdateTime().GetTimestamp(),
		Version:           u.GetVersion(),
		AuthorizedActions: authorizedActions,
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
	aliasRepoFn := func() (*talias.Repository, error) {
		return talias.NewRepository(ctx, rw, rw, kms)
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

	oNoUsers, _ := iam.TestScopes(t, iamRepo)
	oWithUsers, p := iam.TestScopes(t, iamRepo)

	var allUsers []*pb.User
	// Get the 3 system users (u_recovery, u_anon, u_auth)
	us, _, err := iamRepo.ListUsers(ctx, []string{"global"})
	require.NoError(t, err)
	require.Len(t, us, 3)
	// They (should) be returned in reverse order by create time, so we reverse
	slices.Reverse(us)
	for _, u := range us {
		allUsers = append(allUsers, userToProto(u, &scopes.ScopeInfo{
			Id:          u.ScopeId,
			Name:        scope.Global.String(),
			Description: "Global Scope",
			Type:        scope.Global.String(),
		}, testAuthorizedActions))
	}

	authMethod := password.TestAuthMethods(t, conn, "global", 1)[0]
	acct := password.TestAccount(t, conn, authMethod.GetPublicId(), "test_user")
	u := iam.TestUser(t, iamRepo, "global", iam.WithAccountIds(acct.PublicId))
	allUsers = append(allUsers, userToProto(u, &scopes.ScopeInfo{
		Id:          u.ScopeId,
		Name:        scope.Global.String(),
		Description: "Global Scope",
		Type:        scope.Global.String(),
	}, testAuthorizedActions))

	// add roles to be able to see all users
	allowedRole := iam.TestRole(t, conn, "global")
	iam.TestRoleGrant(t, conn, allowedRole.GetPublicId(), "ids=*;type=*;actions=*")
	iam.TestUserRole(t, conn, allowedRole.GetPublicId(), u.GetPublicId())
	for _, scope := range []*iam.Scope{oWithUsers, oNoUsers} {
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

	var safeToDeleteUser string
	orgScopeInfo := &scopes.ScopeInfo{Id: oWithUsers.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()}
	for i := 0; i < 10; i++ {
		ou := iam.TestUser(t, iamRepo, oWithUsers.GetPublicId())
		allUsers = append(allUsers, userToProto(ou, orgScopeInfo, testAuthorizedActions))
		safeToDeleteUser = ou.GetPublicId()
	}
	slices.Reverse(allUsers)

	a, err := users.NewService(ctx, iamRepoFn, aliasRepoFn, 1000)
	require.NoError(t, err, "Couldn't create new user service.")

	// Run analyze to update postgres estimates
	_, err = sqlDB.ExecContext(context.Background(), "analyze")
	require.NoError(t, err)

	itemCount := uint32(len(allUsers))
	testPageSize := int((itemCount - 2) / 2)

	// Start paginating, recursively
	req := &pbs.ListUsersRequest{
		ScopeId:   "global",
		Recursive: true,
		Filter:    "",
		ListToken: "",
		PageSize:  uint32(testPageSize),
	}
	got, err := a.ListUsers(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), testPageSize)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListUsersResponse{
				Items:        allUsers[0:testPageSize],
				ResponseType: "delta",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				// In addition to the added users, there are the users added
				// by the test setup when specifying the permissions of the
				// requester
				EstItemCount: itemCount,
			},
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListUsersResponse{}, "list_token"),
		),
	)

	// Request second page
	req.ListToken = got.ListToken
	got, err = a.ListUsers(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), testPageSize)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListUsersResponse{
				Items:        allUsers[testPageSize : testPageSize*2],
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
			protocmp.IgnoreFields(&pbs.ListUsersResponse{}, "list_token"),
		),
	)

	// Request rest of results
	req.ListToken = got.ListToken
	req.PageSize = 10
	got, err = a.ListUsers(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 2)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListUsersResponse{
				Items:        allUsers[testPageSize*2:],
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
			protocmp.IgnoreFields(&pbs.ListUsersResponse{}, "list_token"),
		),
	)

	// Update 2 users and see them in the refresh
	r1 := allUsers[len(allUsers)-1]
	r1.Description = wrapperspb.String("updated1")
	resp1, err := a.UpdateUser(ctx, &pbs.UpdateUserRequest{
		Id:         r1.GetId(),
		Item:       &pb.User{Description: r1.GetDescription(), Version: r1.GetVersion()},
		UpdateMask: &field_mask.FieldMask{Paths: []string{"description"}},
	})
	require.NoError(t, err)
	r1.UpdatedTime = resp1.GetItem().GetUpdatedTime()
	r1.Version = resp1.GetItem().GetVersion()
	allUsers = append([]*pb.User{r1}, allUsers[:len(allUsers)-1]...)

	r2 := allUsers[len(allUsers)-1]
	r2.Description = wrapperspb.String("updated2")
	resp2, err := a.UpdateUser(ctx, &pbs.UpdateUserRequest{
		Id:         r2.GetId(),
		Item:       &pb.User{Description: r2.GetDescription(), Version: r2.GetVersion()},
		UpdateMask: &field_mask.FieldMask{Paths: []string{"description"}},
	})
	require.NoError(t, err)
	r2.UpdatedTime = resp2.GetItem().GetUpdatedTime()
	r2.Version = resp2.GetItem().GetVersion()
	allUsers = append([]*pb.User{r2}, allUsers[:len(allUsers)-1]...)

	// Run analyze to update postgres estimates
	_, err = sqlDB.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	// Request updated results
	req.ListToken = got.ListToken
	req.PageSize = 1
	got, err = a.ListUsers(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 1)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListUsersResponse{
				Items:        []*pb.User{allUsers[0]},
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
			protocmp.IgnoreFields(&pbs.ListUsersResponse{}, "list_token"),
		),
	)

	// Get next page
	req.ListToken = got.ListToken
	got, err = a.ListUsers(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 1)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListUsersResponse{
				Items:        []*pb.User{allUsers[1]},
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
			protocmp.IgnoreFields(&pbs.ListUsersResponse{}, "list_token"),
		),
	)

	// Request new page with filter requiring looping
	// to fill the page.
	req.ListToken = ""
	req.PageSize = 1
	req.Filter = fmt.Sprintf(`"/item/id"==%q or "/item/id"==%q`, allUsers[len(allUsers)-2].Id, allUsers[len(allUsers)-1].Id)
	got, err = a.ListUsers(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 1)
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListUsersResponse{
				Items:        []*pb.User{allUsers[len(allUsers)-2]},
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
			protocmp.IgnoreFields(&pbs.ListUsersResponse{}, "list_token"),
		),
	)
	req.ListToken = got.ListToken
	// Get the second page
	got, err = a.ListUsers(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 1)
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListUsersResponse{
				Items:        []*pb.User{allUsers[len(allUsers)-1]},
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
			protocmp.IgnoreFields(&pbs.ListUsersResponse{}, "list_token"),
		),
	)

	_, err = iamRepo.DeleteUser(ctx, safeToDeleteUser)
	require.NoError(t, err)
	req.ListToken = got.ListToken
	got, err = a.ListUsers(ctx, req)
	require.NoError(t, err)
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListUsersResponse{
				Items:        nil,
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "desc",
				RemovedIds:   []string{safeToDeleteUser},
				EstItemCount: itemCount,
			},
			protocmp.Transform(),
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.IgnoreFields(&pbs.ListUsersResponse{}, "list_token"),
		),
	)

	// Create unauthenticated user
	unauthAt := authtoken.TestAuthToken(t, conn, kms, oWithUsers.GetPublicId())
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

	_, err = a.ListUsers(ctx, &pbs.ListUsersRequest{
		ScopeId:   "global",
		Recursive: true,
	})
	require.Error(t, err)
	assert.ErrorIs(t, handlers.ForbiddenError(), err)
}

func TestListResolvableAliasesPagination(t *testing.T) {
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
	aliasRepoFn := func() (*talias.Repository, error) {
		return talias.NewRepository(ctx, rw, rw, kms)
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

	_, p := iam.TestScopes(t, iamRepo)
	tar := tcp.TestTarget(ctx, t, conn, p.GetPublicId(), "resolvable")

	_, unresolvableP := iam.TestScopes(t, iamRepo)
	unresolvedTar := tcp.TestTarget(ctx, t, conn, unresolvableP.GetPublicId(), "unresolvable")
	// Create an alias that shouldn't be included in the paginated list results.
	talias.TestAlias(t, rw, "unresolved.alias", talias.WithDestinationId(unresolvedTar.GetPublicId()))

	authMethod := password.TestAuthMethods(t, conn, "global", 1)[0]
	acct := password.TestAccount(t, conn, authMethod.GetPublicId(), "test_user")
	u := iam.TestUser(t, iamRepo, "global", iam.WithAccountIds(acct.PublicId))

	// add roles for requester to be able to perform all actions on everyone
	allowedRole := iam.TestRole(t, conn, "global", iam.WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeDescendants}))
	iam.TestRoleGrant(t, conn, allowedRole.GetPublicId(), "ids=*;type=*;actions=*")
	iam.TestUserRole(t, conn, allowedRole.GetPublicId(), u.GetPublicId())

	at, err := tokenRepo.CreateAuthToken(ctx, u, acct.GetPublicId())
	require.NoError(t, err)

	// add roles for user whose resolvable aliases are being listed they can
	// only see the aliases which resolve to targets in project p.
	resolvingUsersAt := authtoken.TestAuthToken(t, conn, kms, scope.Global.String())
	roleForResolving := iam.TestRole(t, conn, "global", iam.WithGrantScopeIds([]string{p.GetPublicId(), globals.GrantScopeThis}))
	iam.TestRoleGrant(t, conn, roleForResolving.GetPublicId(), "ids=*;type=target;actions=authorize-session")
	iam.TestRoleGrant(t, conn, roleForResolving.GetPublicId(), "ids={{.User.Id}};type=user;actions=list-resolvable-aliases")
	iam.TestUserRole(t, conn, roleForResolving.GetPublicId(), resolvingUsersAt.GetIamUserId())

	var allAliases []*talias.Alias
	var allAliasPbs []*pbalias.Alias
	var safeToRemoveAlias *talias.Alias
	for i := 0; i < 10; i++ {
		na := talias.TestAlias(t, rw, fmt.Sprintf("aliase%d.test", i), talias.WithDestinationId(tar.GetPublicId()))
		allAliases = append(allAliases, na)
		allAliasPbs = append(allAliasPbs, &pbalias.Alias{
			Id:            na.GetPublicId(),
			Value:         na.GetValue(),
			DestinationId: wrapperspb.String(na.GetDestinationId()),
			CreatedTime:   na.GetCreateTime().GetTimestamp(),
			UpdatedTime:   na.GetUpdateTime().GetTimestamp(),
			Type:          "target",
		})

		safeToRemoveAlias = na
	}
	slices.Reverse(allAliases)
	slices.Reverse(allAliasPbs)

	a, err := users.NewService(ctx, iamRepoFn, aliasRepoFn, 1000)
	require.NoError(t, err, "Couldn't create new user service.")

	// Run analyze to update postgres estimates
	_, err = sqlDB.ExecContext(context.Background(), "analyze")
	require.NoError(t, err)

	// +1 because we have one alias that points to an unresolvable target
	itemCount := uint32(len(allAliasPbs)) + 1
	testPageSize := int((itemCount - 2) / 2)

	// See that the resolvingUser can query themselves
	requestInfo := authpb.RequestInfo{
		TokenFormat: uint32(auth.AuthTokenTypeBearer),
		PublicId:    resolvingUsersAt.GetPublicId(),
		Token:       resolvingUsersAt.GetToken(),
	}
	requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
	ctx = auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)
	got, err := a.ListResolvableAliases(ctx, &pbs.ListResolvableAliasesRequest{
		Id: resolvingUsersAt.GetIamUserId(),
	})
	require.NoError(t, err)
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListResolvableAliasesResponse{
				Items:        allAliasPbs,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 10,
			},
			protocmp.Transform(),
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.IgnoreFields(&pbs.ListResolvableAliasesResponse{}, "list_token"),
		),
	)

	// This user cannot list resolvable for other aliases
	_, err = a.ListResolvableAliases(ctx, &pbs.ListResolvableAliasesRequest{
		Id: at.GetIamUserId(),
	})
	require.Error(t, err)
	assert.ErrorIs(t, handlers.ForbiddenError(), err)

	// Now let the admin user list resolvable aliases
	requestInfo = authpb.RequestInfo{
		TokenFormat: uint32(auth.AuthTokenTypeBearer),
		PublicId:    at.GetPublicId(),
		Token:       at.GetToken(),
	}
	requestContext = context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
	ctx = auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)

	req := &pbs.ListResolvableAliasesRequest{
		Id:        resolvingUsersAt.GetIamUserId(),
		ListToken: "",
		PageSize:  uint32(testPageSize),
	}
	got, err = a.ListResolvableAliases(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), testPageSize)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListResolvableAliasesResponse{
				Items:        allAliasPbs[0:testPageSize],
				ResponseType: "delta",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				// In addition to the added users, there are the users added
				// by the test setup when specifying the permissions of the
				// requester
				EstItemCount: itemCount,
			},
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListResolvableAliasesResponse{}, "list_token"),
		),
	)

	// Request second page
	req.ListToken = got.ListToken
	got, err = a.ListResolvableAliases(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), testPageSize)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListResolvableAliasesResponse{
				Items:        allAliasPbs[testPageSize : testPageSize*2],
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
			protocmp.IgnoreFields(&pbs.ListResolvableAliasesResponse{}, "list_token"),
		),
	)

	// Request rest of results
	req.ListToken = got.ListToken
	req.PageSize = 10
	got, err = a.ListResolvableAliases(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 2)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListResolvableAliasesResponse{
				Items:        allAliasPbs[testPageSize*2:],
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
			protocmp.IgnoreFields(&pbs.ListResolvableAliasesResponse{}, "list_token"),
		),
	)

	// Update 2 aliases and see them in the refresh
	aliasRepo, err := aliasRepoFn()
	require.NoError(t, err)

	for i := 0; i < 2; i++ {
		r := allAliases[len(allAliasPbs)-1]
		rPb := allAliasPbs[len(allAliasPbs)-1]
		r.Description = fmt.Sprintf("updated%d", i)

		updated, _, err := aliasRepo.UpdateAlias(ctx, r, r.GetVersion(), []string{"description"})
		require.NoError(t, err)

		r.Version = updated.GetVersion()
		r.UpdateTime = updated.GetUpdateTime()
		rPb.UpdatedTime = updated.GetUpdateTime().GetTimestamp()
		// ListResolvableAliases does not return the description, or the version
		// so we do not update those values here in the protobuf aliases
		allAliases = append([]*talias.Alias{r}, allAliases[:len(allAliases)-1]...)
		allAliasPbs = append([]*pbalias.Alias{rPb}, allAliasPbs[:len(allAliasPbs)-1]...)
	}

	// Run analyze to update postgres estimates
	_, err = sqlDB.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	// Request updated results
	req.ListToken = got.ListToken
	req.PageSize = 1
	got, err = a.ListResolvableAliases(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 1)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListResolvableAliasesResponse{
				Items:        []*pbalias.Alias{allAliasPbs[0]},
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
			protocmp.IgnoreFields(&pbs.ListResolvableAliasesResponse{}, "list_token"),
		),
	)

	// Get next page
	req.ListToken = got.ListToken
	got, err = a.ListResolvableAliases(ctx, req)
	require.NoError(t, err)
	require.Len(t, got.GetItems(), 1)
	// Compare without comparing the list token
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListResolvableAliasesResponse{
				Items:        []*pbalias.Alias{allAliasPbs[1]},
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
			protocmp.IgnoreFields(&pbs.ListResolvableAliasesResponse{}, "list_token"),
		),
	)

	_, err = aliasRepo.DeleteAlias(ctx, safeToRemoveAlias.GetPublicId())
	require.NoError(t, err)
	req.ListToken = got.ListToken
	got, err = a.ListResolvableAliases(ctx, req)
	require.NoError(t, err)
	assert.Empty(t,
		cmp.Diff(
			got,
			&pbs.ListResolvableAliasesResponse{
				Items:        nil,
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "desc",
				RemovedIds:   []string{safeToRemoveAlias.GetPublicId()},
				EstItemCount: itemCount,
			},
			protocmp.Transform(),
			protocmp.SortRepeated(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			}),
			protocmp.IgnoreFields(&pbs.ListResolvableAliasesResponse{}, "list_token"),
		),
	)

	// Create unauthenticated user
	unauthAt := authtoken.TestAuthToken(t, conn, kms, scope.Global.String())
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

	_, err = a.ListResolvableAliases(ctx, &pbs.ListResolvableAliasesRequest{
		Id: resolvingUsersAt.GetIamUserId(),
	})
	require.Error(t, err)
	assert.ErrorIs(t, handlers.ForbiddenError(), err)
}

func TestDelete(t *testing.T) {
	u, _, repoFn, aliasRepoFn := createDefaultUserAndRepos(t, false)

	s, err := users.NewService(context.Background(), repoFn, aliasRepoFn, 1000)
	require.NoError(t, err, "Error when getting new user service.")

	cases := []struct {
		name string
		req  *pbs.DeleteUserRequest
		res  *pbs.DeleteUserResponse
		err  error
	}{
		{
			name: "Delete an Existing User",
			req: &pbs.DeleteUserRequest{
				Id: u.GetPublicId(),
			},
		},
		{
			name: "Delete bad user id",
			req: &pbs.DeleteUserRequest{
				Id: globals.UserPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Bad User Id formatting",
			req: &pbs.DeleteUserRequest{
				Id: "bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteUser(auth.DisabledAuthTestContext(repoFn, u.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteUser(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.EqualValuesf(tc.res, got, "DeleteUser(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	u, _, repoFn, aliasRepoFn := createDefaultUserAndRepos(t, false)

	s, err := users.NewService(context.Background(), repoFn, aliasRepoFn, 1000)
	require.NoError(err, "Error when getting new user service")
	req := &pbs.DeleteUserRequest{
		Id: u.GetPublicId(),
	}
	ctx := auth.DisabledAuthTestContext(repoFn, u.GetScopeId())
	_, gErr := s.DeleteUser(ctx, req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteUser(ctx, req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")
}

func TestCreate(t *testing.T) {
	defaultUser, _, repoFn, aliasRepoFn := createDefaultUserAndRepos(t, false)
	defaultCreated := defaultUser.GetCreateTime().GetTimestamp().AsTime()

	cases := []struct {
		name string
		req  *pbs.CreateUserRequest
		res  *pbs.CreateUserResponse
		err  error
	}{
		{
			name: "Create a valid User",
			req: &pbs.CreateUserRequest{Item: &pb.User{
				ScopeId:     defaultUser.GetScopeId(),
				Name:        &wrapperspb.StringValue{Value: "name"},
				Description: &wrapperspb.StringValue{Value: "desc"},
			}},
			res: &pbs.CreateUserResponse{
				Uri: fmt.Sprintf("users/%s_", globals.UserPrefix),
				Item: &pb.User{
					ScopeId:           defaultUser.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: defaultUser.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:              &wrapperspb.StringValue{Value: "name"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					Version:           1,
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Create a valid Global User",
			req: &pbs.CreateUserRequest{Item: &pb.User{
				ScopeId:     scope.Global.String(),
				Name:        &wrapperspb.StringValue{Value: "name"},
				Description: &wrapperspb.StringValue{Value: "desc"},
			}},
			res: &pbs.CreateUserResponse{
				Uri: fmt.Sprintf("users/%s_", globals.UserPrefix),
				Item: &pb.User{
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
			name: "Can't specify Id",
			req: &pbs.CreateUserRequest{Item: &pb.User{
				ScopeId: defaultUser.GetScopeId(),
				Id:      globals.UserPrefix + "_notallowed",
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateUserRequest{Item: &pb.User{
				ScopeId:     defaultUser.GetScopeId(),
				CreatedTime: timestamppb.Now(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateUserRequest{Item: &pb.User{
				ScopeId:     defaultUser.GetScopeId(),
				UpdatedTime: timestamppb.Now(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := users.NewService(context.Background(), repoFn, aliasRepoFn, 1000)
			require.NoError(err, "Error when getting new user service.")

			got, gErr := s.CreateUser(auth.DisabledAuthTestContext(repoFn, tc.req.GetItem().GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateUser(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				assert.True(strings.HasPrefix(got.GetItem().GetId(), globals.UserPrefix+"_"))
				gotCreateTime := got.GetItem().GetCreatedTime().AsTime()
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
				// Verify it is a user created after the test setup's default user
				assert.True(gotCreateTime.After(defaultCreated), "New user should have been created after default user. Was created %v, which is after %v", gotCreateTime, defaultCreated)
				assert.True(gotUpdateTime.After(defaultCreated), "New user should have been updated after default user. Was updated %v, which is after %v", gotUpdateTime, defaultCreated)

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
			), "CreateUser(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	u, _, repoFn, aliasRepoFn := createDefaultUserAndRepos(t, false)
	tested, err := users.NewService(context.Background(), repoFn, aliasRepoFn, 1000)
	require.NoError(t, err, "Error when getting new user service.")

	created := u.GetCreateTime().GetTimestamp().AsTime()
	toMerge := &pbs.UpdateUserRequest{
		Id: u.GetPublicId(),
	}

	var version uint32 = 1

	resetUser := func() {
		repo, err := repoFn()
		require.NoError(t, err, "Couldn't get a new repo")
		version++ // From the test case that resulted in calling this
		u, _, _, err = repo.UpdateUser(context.Background(), u, version, []string{"Name", "Description"})
		require.NoError(t, err, "Failed to reset the user")
		version++
	}

	cases := []struct {
		name string
		req  *pbs.UpdateUserRequest
		res  *pbs.UpdateUserResponse
		err  error
	}{
		{
			name: "Update an Existing User",
			req: &pbs.UpdateUserRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.User{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateUserResponse{
				Item: &pb.User{
					Id:                u.GetPublicId(),
					ScopeId:           u.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: u.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:              &wrapperspb.StringValue{Value: "new"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:       u.GetCreateTime().GetTimestamp(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateUserRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.User{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateUserResponse{
				Item: &pb.User{
					Id:                u.GetPublicId(),
					ScopeId:           u.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: u.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:              &wrapperspb.StringValue{Value: "new"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:       u.GetCreateTime().GetTimestamp(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateUserRequest{
				Item: &pb.User{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "No Paths in Mask",
			req: &pbs.UpdateUserRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.User{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Only non-existent paths in Mask",
			req: &pbs.UpdateUserRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistent_field"}},
				Item: &pb.User{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateUserRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.User{
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateUserResponse{
				Item: &pb.User{
					Id:                u.GetPublicId(),
					ScopeId:           u.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: u.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Description:       &wrapperspb.StringValue{Value: "default"},
					CreatedTime:       u.GetCreateTime().GetTimestamp(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateUserRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.User{
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateUserResponse{
				Item: &pb.User{
					Id:                u.GetPublicId(),
					ScopeId:           u.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: u.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:              &wrapperspb.StringValue{Value: "updated"},
					Description:       &wrapperspb.StringValue{Value: "default"},
					CreatedTime:       u.GetCreateTime().GetTimestamp(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateUserRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.User{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
				},
			},
			res: &pbs.UpdateUserResponse{
				Item: &pb.User{
					Id:                u.GetPublicId(),
					ScopeId:           u.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: u.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:              &wrapperspb.StringValue{Value: "default"},
					Description:       &wrapperspb.StringValue{Value: "notignored"},
					CreatedTime:       u.GetCreateTime().GetTimestamp(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Update a Non Existing User",
			req: &pbs.UpdateUserRequest{
				Id: globals.UserPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.User{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateUserRequest{
				Id: u.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.User{
					Id:          globals.UserPrefix + "_somethinge",
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "new desc"},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateUserRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.User{
					CreatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateUserRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.User{
					UpdatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.req.Item.Version = version

			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.UpdateUserRequest)
			proto.Merge(req, tc.req)

			// Test with bad version (too high, too low)
			req.Item.Version = version + 2
			_, gErr := tested.UpdateUser(auth.DisabledAuthTestContext(repoFn, u.GetScopeId()), req)
			require.Error(gErr)
			req.Item.Version = version - 1
			_, gErr = tested.UpdateUser(auth.DisabledAuthTestContext(repoFn, u.GetScopeId()), req)
			require.Error(gErr)
			req.Item.Version = version

			got, gErr := tested.UpdateUser(auth.DisabledAuthTestContext(repoFn, u.GetScopeId()), req)
			if tc.err != nil {
				require.Error(gErr)
				require.True(errors.Is(gErr, tc.err), "UpdateUser(%+v) got error %v, wanted %v", req, gErr, tc.err)
			} else {
				defer resetUser()
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateUser response to be nil, but was %v", got)
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
				// Verify it is a user updated after it was created
				assert.True(gotUpdateTime.After(created), "Updated user should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil
				assert.Equal(version+1, got.GetItem().GetVersion())
				tc.res.Item.Version = version + 1
			}
			assert.Empty(cmp.Diff(
				tc.res,
				got,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "UpdateUser(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestAddAccount(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	ctx := context.Background()
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	aliasRepoFn := func() (*talias.Repository, error) {
		return talias.NewRepository(ctx, rw, rw, kmsCache)
	}
	s, err := users.NewService(ctx, repoFn, aliasRepoFn, 1000)
	require.NoError(t, err, "Error when getting new user service.")

	o, _ := iam.TestScopes(t, iamRepo)
	acctCnt := 3
	accts := make([]*password.Account, 0, acctCnt)
	for i := 0; i < acctCnt; i++ {
		amId := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0].GetPublicId()
		newAcct := password.TestAccount(t, conn, amId, "name1")
		accts = append(accts, newAcct)
	}

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	oidcAm := oidc.TestAuthMethod(
		t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	oidcAcct := oidc.TestAccount(t, conn, oidcAm, "test-subject")

	ldapAm := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://ldap1"})
	ldapAcct := ldap.TestAccount(t, conn, ldapAm, "test-acct",
		ldap.WithMemberOfGroups(ctx, "admin"),
		ldap.WithFullName(ctx, "test-name"),
		ldap.WithEmail(ctx, "test-email"),
		ldap.WithDn(ctx, "test-dn"),
	)

	addCases := []struct {
		name           string
		setup          func(*iam.User)
		addAccounts    []string
		resultAccounts []string
		wantErr        bool
	}{
		{
			name:           "Add account on empty user",
			setup:          func(u *iam.User) {},
			addAccounts:    []string{accts[1].GetPublicId()},
			resultAccounts: []string{accts[1].GetPublicId()},
		},
		{
			name:           "Add oidc account on empty user",
			setup:          func(u *iam.User) {},
			addAccounts:    []string{oidcAcct.GetPublicId()},
			resultAccounts: []string{oidcAcct.GetPublicId()},
		},
		{
			name:           "Add ldap account on empty user",
			setup:          func(u *iam.User) {},
			addAccounts:    []string{ldapAcct.GetPublicId()},
			resultAccounts: []string{ldapAcct.GetPublicId()},
		},
		{
			name: "Add account on populated user",
			setup: func(u *iam.User) {
				_, err := iamRepo.SetUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			addAccounts:    []string{accts[1].GetPublicId()},
			resultAccounts: []string{accts[0].GetPublicId(), accts[1].GetPublicId()},
		},
		{
			name: "Add duplicate account on populated user",
			setup: func(u *iam.User) {
				_, err := iamRepo.SetUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			addAccounts:    []string{accts[1].GetPublicId(), accts[1].GetPublicId()},
			resultAccounts: []string{accts[0].GetPublicId(), accts[1].GetPublicId()},
		},
		{
			name: "Add empty on populated user",
			setup: func(u *iam.User) {
				_, err := iamRepo.SetUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId(), accts[1].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			wantErr: true,
		},
	}

	for _, tc := range addCases {
		t.Run(tc.name, func(t *testing.T) {
			usr := iam.TestUser(t, iamRepo, o.GetPublicId())
			defer func() {
				_, err := iamRepo.DeleteUser(context.Background(), usr.GetPublicId())
				require.NoError(t, err)
			}()
			tc.setup(usr)
			req := &pbs.AddUserAccountsRequest{
				Id:         usr.GetPublicId(),
				Version:    usr.GetVersion(),
				AccountIds: tc.addAccounts,
			}

			got, err := s.AddUserAccounts(auth.DisabledAuthTestContext(repoFn, o.GetPublicId()), req)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err, "Got error: %v", err)
			assert.ElementsMatch(t, got.GetItem().GetAccountIds(), tc.resultAccounts)
		})
	}

	usr := iam.TestUser(t, iamRepo, o.GetPublicId())

	failCases := []struct {
		name string
		req  *pbs.AddUserAccountsRequest
		err  error
	}{
		{
			name: "Bad user Id",
			req: &pbs.AddUserAccountsRequest{
				Id:      "bad id",
				Version: usr.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Bad account Id",
			req: &pbs.AddUserAccountsRequest{
				Id:         usr.GetPublicId(),
				Version:    usr.GetVersion(),
				AccountIds: []string{"invalid"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.AddUserAccounts(auth.DisabledAuthTestContext(repoFn, usr.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "AddUserAccounts(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestSetAccount(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	ctx := context.Background()
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	aliasRepoFn := func() (*talias.Repository, error) {
		return talias.NewRepository(ctx, rw, rw, kmsCache)
	}
	s, err := users.NewService(ctx, repoFn, aliasRepoFn, 1000)
	require.NoError(t, err, "Error when getting new user service.")

	o, _ := iam.TestScopes(t, iamRepo)
	acctCnt := 3
	accts := make([]*password.Account, 0, acctCnt)
	for i := 0; i < acctCnt; i++ {
		amId := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0].GetPublicId()
		newAcct := password.TestAccount(t, conn, amId, "name1")
		accts = append(accts, newAcct)
	}

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	oidcAm := oidc.TestAuthMethod(
		t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	oidcAcct := oidc.TestAccount(t, conn, oidcAm, "test-subject")

	ldapAm := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://ldap1"})
	ldapAcct := ldap.TestAccount(t, conn, ldapAm, "test-acct",
		ldap.WithMemberOfGroups(ctx, "admin"),
		ldap.WithFullName(ctx, "test-name"),
		ldap.WithEmail(ctx, "test-email"),
		ldap.WithDn(ctx, "test-dn"),
	)

	setCases := []struct {
		name           string
		setup          func(*iam.User)
		setAccounts    []string
		resultAccounts []string
		wantErr        bool
	}{
		{
			name:           "Set account on empty user",
			setup:          func(u *iam.User) {},
			setAccounts:    []string{accts[1].GetPublicId()},
			resultAccounts: []string{accts[1].GetPublicId()},
		},
		{
			name:           "Set oidc account on empty user",
			setup:          func(u *iam.User) {},
			setAccounts:    []string{oidcAcct.GetPublicId()},
			resultAccounts: []string{oidcAcct.GetPublicId()},
		},
		{
			name:           "Set ldap account on empty user",
			setup:          func(u *iam.User) {},
			setAccounts:    []string{ldapAcct.GetPublicId()},
			resultAccounts: []string{ldapAcct.GetPublicId()},
		},
		{
			name: "Set account on populated user",
			setup: func(u *iam.User) {
				_, err := iamRepo.AddUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			setAccounts:    []string{accts[1].GetPublicId()},
			resultAccounts: []string{accts[1].GetPublicId()},
		},
		{
			name: "Set duplicate account on populated user",
			setup: func(u *iam.User) {
				_, err := iamRepo.AddUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			setAccounts:    []string{accts[1].GetPublicId(), accts[1].GetPublicId()},
			resultAccounts: []string{accts[1].GetPublicId()},
		},
		{
			name: "Set empty on populated user",
			setup: func(u *iam.User) {
				_, err := iamRepo.AddUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId(), accts[1].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			setAccounts:    []string{},
			resultAccounts: nil,
		},
	}

	for _, tc := range setCases {
		t.Run(tc.name, func(t *testing.T) {
			usr := iam.TestUser(t, iamRepo, o.GetPublicId())
			defer func() {
				_, err := iamRepo.DeleteUser(context.Background(), usr.GetPublicId())
				require.NoError(t, err)
			}()

			tc.setup(usr)
			req := &pbs.SetUserAccountsRequest{
				Id:         usr.GetPublicId(),
				Version:    usr.GetVersion(),
				AccountIds: tc.setAccounts,
			}

			got, err := s.SetUserAccounts(auth.DisabledAuthTestContext(repoFn, o.GetPublicId()), req)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err, "Got error: %v", err)
			assert.ElementsMatch(t, got.GetItem().GetAccountIds(), tc.resultAccounts)
		})
	}

	usr := iam.TestUser(t, iamRepo, o.GetPublicId())

	failCases := []struct {
		name string
		req  *pbs.SetUserAccountsRequest
		err  error
	}{
		{
			name: "Bad User Id",
			req: &pbs.SetUserAccountsRequest{
				Id:      "bad id",
				Version: usr.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Bad account Id",
			req: &pbs.SetUserAccountsRequest{
				Id:         usr.GetPublicId(),
				Version:    usr.GetVersion(),
				AccountIds: []string{"invalid"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.SetUserAccounts(auth.DisabledAuthTestContext(repoFn, usr.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "SetUserAccounts(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestRemoveAccount(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	ctx := context.Background()
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	aliasRepoFn := func() (*talias.Repository, error) {
		return talias.NewRepository(ctx, rw, rw, kmsCache)
	}
	s, err := users.NewService(ctx, repoFn, aliasRepoFn, 1000)
	require.NoError(t, err, "Error when getting new user service.")

	o, _ := iam.TestScopes(t, iamRepo)
	acctCnt := 3
	accts := make([]*password.Account, 0, acctCnt)
	for i := 0; i < acctCnt; i++ {
		amId := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0].GetPublicId()
		newAcct := password.TestAccount(t, conn, amId, "name1")
		accts = append(accts, newAcct)
	}

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	oidcAm := oidc.TestAuthMethod(
		t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	oidcAcct := oidc.TestAccount(t, conn, oidcAm, "test-subject")

	ldapAm := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://ldap1"})
	ldapAcct := ldap.TestAccount(t, conn, ldapAm, "test-acct",
		ldap.WithMemberOfGroups(ctx, "admin"),
		ldap.WithFullName(ctx, "test-name"),
		ldap.WithEmail(ctx, "test-email"),
		ldap.WithDn(ctx, "test-dn"),
	)

	addCases := []struct {
		name           string
		setup          func(*iam.User)
		removeAccounts []string
		resultAccounts []string
		wantErr        bool
	}{
		{
			name:           "Remove account on empty user",
			setup:          func(*iam.User) {},
			removeAccounts: []string{accts[1].GetPublicId()},
			wantErr:        true,
		},
		{
			name: "Remove 1 of 2 accounts from user",
			setup: func(u *iam.User) {
				_, err := iamRepo.SetUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId(), accts[1].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			removeAccounts: []string{accts[1].GetPublicId()},
			resultAccounts: []string{accts[0].GetPublicId()},
		},
		{
			name: "Remove 1 oidc account of 2 accounts from user",
			setup: func(u *iam.User) {
				_, err := iamRepo.SetUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId(), oidcAcct.GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			removeAccounts: []string{oidcAcct.GetPublicId()},
			resultAccounts: []string{accts[0].GetPublicId()},
		},
		{
			name: "Remove 1 duplicate accounts of 2 accounts from user",
			setup: func(u *iam.User) {
				_, err := iamRepo.SetUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId(), accts[1].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			removeAccounts: []string{accts[1].GetPublicId(), accts[1].GetPublicId()},
			resultAccounts: []string{accts[0].GetPublicId()},
		},
		{
			name: "Remove 1 ldap account of 3 accounts from user",
			setup: func(u *iam.User) {
				_, err := iamRepo.SetUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId(), oidcAcct.GetPublicId(), ldapAcct.GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			removeAccounts: []string{ldapAcct.GetPublicId()},
			resultAccounts: []string{accts[0].GetPublicId(), oidcAcct.GetPublicId()},
		},
		{
			name: "Remove all accounts from user",
			setup: func(u *iam.User) {
				_, err := iamRepo.SetUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId(), accts[1].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			removeAccounts: []string{accts[0].GetPublicId(), accts[1].GetPublicId()},
			resultAccounts: []string{},
		},
		{
			name: "Remove empty on populated user",
			setup: func(u *iam.User) {
				_, err := iamRepo.SetUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			wantErr: true,
		},
	}

	for _, tc := range addCases {
		t.Run(tc.name, func(t *testing.T) {
			usr := iam.TestUser(t, iamRepo, o.GetPublicId())
			defer func() {
				_, err := iamRepo.DeleteUser(context.Background(), usr.GetPublicId())
				require.NoError(t, err)
			}()
			tc.setup(usr)
			req := &pbs.RemoveUserAccountsRequest{
				Id:         usr.GetPublicId(),
				Version:    usr.GetVersion(),
				AccountIds: tc.removeAccounts,
			}

			got, err := s.RemoveUserAccounts(auth.DisabledAuthTestContext(repoFn, o.GetPublicId()), req)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err, "Got error: %v", err)

			assert.ElementsMatch(t, got.GetItem().GetAccountIds(), tc.resultAccounts)
		})
	}

	usr := iam.TestUser(t, iamRepo, o.GetPublicId())

	failCases := []struct {
		name string
		req  *pbs.RemoveUserAccountsRequest
		err  error
	}{
		{
			name: "Bad User Id",
			req: &pbs.RemoveUserAccountsRequest{
				Id:      "bad id",
				Version: usr.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Bad account Id",
			req: &pbs.RemoveUserAccountsRequest{
				Id:         usr.GetPublicId(),
				Version:    usr.GetVersion(),
				AccountIds: []string{"invalid"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.RemoveUserAccounts(auth.DisabledAuthTestContext(repoFn, usr.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "AddUserAccounts(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}
