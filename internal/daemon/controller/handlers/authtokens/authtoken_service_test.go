// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package authtokens_test

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/authtokens"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authtokens"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	fullAuthorizedActions = []string{"no-op", "read", "read:self", "delete", "delete:self"}
	selfAuthorizedActions = []string{"read:self", "delete:self"}
)

func TestGetSelf(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)

	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrap), nil
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}

	a, err := authtokens.NewService(ctx, tokenRepoFn, iamRepoFn, 1000)
	require.NoError(t, err, "Couldn't create new auth token service.")

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	at1 := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())
	at2 := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())

	cases := []struct {
		name   string
		token  *authtoken.AuthToken
		readId string
		err    error
	}{
		{
			name:   "at1 read self",
			token:  at1,
			readId: at1.GetPublicId(),
		},
		{
			name:   "at1 read at2",
			token:  at1,
			readId: at2.GetPublicId(),
			err:    handlers.ApiErrorWithCodeAndMessage(codes.PermissionDenied, "Forbidden."),
		},
		{
			name:   "at2 read self",
			token:  at2,
			readId: at2.GetPublicId(),
		},
		{
			name:   "at2 read at1",
			token:  at2,
			readId: at1.GetPublicId(),
			err:    handlers.ApiErrorWithCodeAndMessage(codes.PermissionDenied, "Forbidden."),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			// Setup the auth request information
			req := httptest.NewRequest("GET", fmt.Sprintf("http://127.0.0.1/v1/auth-tokens/%s", tc.readId), nil)
			requestInfo := authpb.RequestInfo{
				Path:        req.URL.Path,
				Method:      req.Method,
				TokenFormat: uint32(auth.AuthTokenTypeBearer),
				PublicId:    tc.token.GetPublicId(),
				Token:       tc.token.GetToken(),
			}

			ctx := auth.NewVerifierContext(ctx, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)
			ctx = context.WithValue(ctx, requests.ContextRequestInformationKey, &requests.RequestContext{})
			got, err := a.GetAuthToken(ctx, &pbs.GetAuthTokenRequest{Id: tc.readId})
			if tc.err != nil {
				require.EqualError(err, tc.err.Error())
				require.Nil(got)
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Equal(tc.token.GetPublicId(), got.GetItem().GetId())
			// Ensure we didn't simply have e.g. read on all tokens
			assert.Equal([]string{"read:self", "delete:self"}, got.Item.GetAuthorizedActions())
		})
	}
}

func TestGet(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrap), nil
	}
	repoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}

	s, err := authtokens.NewService(ctx, repoFn, iamRepoFn, 1000)
	require.NoError(t, err, "Couldn't create new auth token service.")

	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())

	wireAuthToken := pb.AuthToken{
		Id:                      at.GetPublicId(),
		ScopeId:                 at.GetScopeId(),
		UserId:                  at.GetIamUserId(),
		AuthMethodId:            at.GetAuthMethodId(),
		AccountId:               at.GetAuthAccountId(),
		CreatedTime:             at.GetCreateTime().GetTimestamp(),
		UpdatedTime:             at.GetUpdateTime().GetTimestamp(),
		ApproximateLastUsedTime: at.GetApproximateLastAccessTime().GetTimestamp(),
		ExpirationTime:          at.GetExpirationTime().GetTimestamp(),
		Scope:                   &scopes.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
		AuthorizedActions:       fullAuthorizedActions,
	}

	cases := []struct {
		name string
		req  *pbs.GetAuthTokenRequest
		res  *pbs.GetAuthTokenResponse
		err  error
	}{
		{
			name: "Get an existing auth token",
			req:  &pbs.GetAuthTokenRequest{Id: wireAuthToken.GetId()},
			res:  &pbs.GetAuthTokenResponse{Item: &wireAuthToken},
		},
		{
			name: "Get a non existing auth token",
			req:  &pbs.GetAuthTokenRequest{Id: globals.AuthTokenPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Wrong id prefix",
			req:  &pbs.GetAuthTokenRequest{Id: "j_1234567890"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "space in id",
			req:  &pbs.GetAuthTokenRequest{Id: globals.AuthTokenPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.GetAuthToken(auth.DisabledAuthTestContext(iamRepoFn, org.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetAuthToken(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetAuthToken(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestList_Self(t *testing.T) {
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)

	iamRepo := iam.TestRepo(t, conn, wrap)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(testCtx, rw, rw, kms)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(testCtx, rw, rw, kms)
	}

	// This will result in the scope having default permissions, which now
	// includes list on auth tokens
	o, _ := iam.TestScopes(t, iamRepo)

	// Each of these should only end up being able to list themselves
	at := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())
	otherAt := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())

	cases := []struct {
		name      string
		requester *authtoken.AuthToken
		count     int
	}{
		{
			name:      "First token sees only self",
			requester: at,
		},
		{
			name:      "Second token sees only self",
			requester: otherAt,
		},
	}

	a, err := authtokens.NewService(testCtx, tokenRepoFn, iamRepoFn, 1000)
	require.NoError(t, err)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			// Setup the auth request information
			req := httptest.NewRequest("GET", fmt.Sprintf("http://127.0.0.1/v1/auth-tokens?scope_id=%s", o.GetPublicId()), nil)
			requestInfo := authpb.RequestInfo{
				Path:        req.URL.Path,
				Method:      req.Method,
				TokenFormat: uint32(auth.AuthTokenTypeBearer),
				PublicId:    tc.requester.GetPublicId(),
				Token:       tc.requester.GetToken(),
			}

			ctx := auth.NewVerifierContext(testCtx, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)
			got, err := a.ListAuthTokens(ctx, &pbs.ListAuthTokensRequest{ScopeId: o.GetPublicId()})
			require.NoError(err)
			require.Len(got.Items, 1)
			assert.Equal(got.Items[0].GetId(), tc.requester.GetPublicId())
			// Ensure we didn't simply have e.g. read on all tokens
			assert.Equal(got.Items[0].GetAuthorizedActions(), []string{"read:self", "delete:self"})
		})
	}
}

func authTokenToProto(at *authtoken.AuthToken, scope *scopes.ScopeInfo, authorizedActions []string) *pb.AuthToken {
	return &pb.AuthToken{
		Id:                      at.GetPublicId(),
		ScopeId:                 at.GetScopeId(),
		UserId:                  at.GetIamUserId(),
		AuthMethodId:            at.GetAuthMethodId(),
		AccountId:               at.GetAuthAccountId(),
		CreatedTime:             at.GetCreateTime().GetTimestamp(),
		UpdatedTime:             at.GetUpdateTime().GetTimestamp(),
		ApproximateLastUsedTime: at.GetApproximateLastAccessTime().GetTimestamp(),
		ExpirationTime:          at.GetExpirationTime().GetTimestamp(),
		Scope:                   scope,
		AuthorizedActions:       authorizedActions,
	}
}

func TestList(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDB, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrap), nil
	}
	repoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(context.Background(), rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrap)

	orgNoTokens, _ := iam.TestScopes(t, iamRepo)

	var globalTokens []*pb.AuthToken
	for i := 0; i < 3; i++ {
		at := authtoken.TestAuthToken(t, conn, kms, scope.Global.String())
		atp := authTokenToProto(at, &scopes.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"}, fullAuthorizedActions)
		globalTokens = append(globalTokens, atp)
	}

	orgWithSomeTokens, _ := iam.TestScopes(t, iamRepo)
	var wantSomeTokens []*pb.AuthToken
	for i := 0; i < 3; i++ {
		at := authtoken.TestAuthToken(t, conn, kms, orgWithSomeTokens.GetPublicId())
		atp := authTokenToProto(at, &scopes.ScopeInfo{Id: orgWithSomeTokens.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()}, fullAuthorizedActions)
		wantSomeTokens = append(wantSomeTokens, atp)
	}

	orgWithOtherTokens, _ := iam.TestScopes(t, iamRepo)
	var wantOtherTokens []*pb.AuthToken
	for i := 0; i < 3; i++ {
		at := authtoken.TestAuthToken(t, conn, kms, orgWithOtherTokens.GetPublicId())
		atp := authTokenToProto(at, &scopes.ScopeInfo{Id: orgWithOtherTokens.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()}, fullAuthorizedActions)
		wantOtherTokens = append(wantOtherTokens, atp)
	}

	// Run analyze to update postgres estimates
	_, err = sqlDB.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	allTokens := append(globalTokens, wantSomeTokens...)
	allTokens = append(allTokens, wantOtherTokens...)

	cases := []struct {
		name string
		req  *pbs.ListAuthTokensRequest
		res  *pbs.ListAuthTokensResponse
		err  error
	}{
		{
			name: "List Some Tokens",
			req:  &pbs.ListAuthTokensRequest{ScopeId: orgWithSomeTokens.GetPublicId()},
			res: &pbs.ListAuthTokensResponse{
				Items:        wantSomeTokens,
				EstItemCount: 3,
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "asc",
			},
		},
		{
			name: "List Other Tokens",
			req:  &pbs.ListAuthTokensRequest{ScopeId: orgWithOtherTokens.GetPublicId()},
			res: &pbs.ListAuthTokensResponse{
				Items:        wantOtherTokens,
				EstItemCount: 3,
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "asc",
			},
		},
		{
			name: "List No Token",
			req:  &pbs.ListAuthTokensRequest{ScopeId: orgNoTokens.GetPublicId()},
			res: &pbs.ListAuthTokensResponse{
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "asc",
			},
		},
		// TODO: When an org doesn't exist, we should return a 404 instead of an empty list.
		{
			name: "Unfound Org",
			req:  &pbs.ListAuthTokensRequest{ScopeId: scope.Org.Prefix() + "_DoesntExis"},
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "List Recursively",
			req:  &pbs.ListAuthTokensRequest{ScopeId: "global", Recursive: true},
			res: &pbs.ListAuthTokensResponse{
				Items:        allTokens,
				EstItemCount: 9,
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "asc",
			},
		},
		{
			name: "Paginate listing",
			req:  &pbs.ListAuthTokensRequest{ScopeId: scope.Global.String(), Recursive: true, PageSize: 2},
			res: &pbs.ListAuthTokensResponse{
				Items:        allTokens[:2],
				EstItemCount: 9,
				ResponseType: "delta",
				SortBy:       "updated_time",
				SortDir:      "asc",
			},
		},
		{
			name: "Filter to Some Tokens",
			req: &pbs.ListAuthTokensRequest{
				ScopeId: "global", Recursive: true,
				Filter: fmt.Sprintf(`"/item/scope/id"==%q`, orgWithSomeTokens.GetPublicId()),
			},
			res: &pbs.ListAuthTokensResponse{
				Items:        wantSomeTokens,
				EstItemCount: 3,
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "asc",
			},
		},
		{
			name: "Filter All Tokens",
			req:  &pbs.ListAuthTokensRequest{ScopeId: orgWithOtherTokens.GetPublicId(), Filter: `"/item/scope/id"=="thisdoesntmatch"`},
			res: &pbs.ListAuthTokensResponse{
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "asc",
			},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListAuthTokensRequest{ScopeId: orgWithSomeTokens.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := authtokens.NewService(context.Background(), repoFn, iamRepoFn, 1000)
			assert, require := assert.New(t), require.New(t)
			require.NoError(err, "Couldn't create new user service.")

			// Check non-anon listing
			got, gErr := s.ListAuthTokens(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId(), auth.WithUserId(globals.AnyAuthenticatedUserId)), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListAuthTokens() with scope %q got error %v, wanted %v", tc.req.GetScopeId(), gErr, tc.err)
				return
			} else {
				require.NoError(gErr)
			}

			// Compare without comparing the refresh token
			assert.Empty(
				cmp.Diff(
					got,
					tc.res,
					protocmp.Transform(),
					protocmp.IgnoreFields(&pbs.ListAuthTokensResponse{}, "refresh_token"),
				),
			)

			// Now check anon listing
			got, gErr = s.ListAuthTokens(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId(), auth.WithUserId(globals.AnonymousUserId)), tc.req)
			require.NoError(gErr)
			assert.Len(got.Items, len(tc.res.Items))
			for _, item := range got.GetItems() {
				require.Nil(item.CreatedTime)
				require.Nil(item.ExpirationTime)
				require.Nil(item.UpdatedTime)
				require.Nil(item.ApproximateLastUsedTime)
			}
		})
	}
}

func TestListPagination(t *testing.T) {
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDB, err := conn.SqlDB(testCtx)
	require.NoError(t, err)
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrap), nil
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(testCtx, rw, rw, kms)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(testCtx, rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrap)
	tokenRepo, _ := tokenRepoFn()
	orgWithTokens, pwt := iam.TestScopes(t, iamRepo)

	authMethod := password.TestAuthMethods(t, conn, orgWithTokens.GetPublicId(), 1)[0]
	// auth account is only used to join auth method to user.
	// We don't do anything else with the auth account in the test setup.
	acct := password.TestAccount(t, conn, authMethod.GetPublicId(), "test_user")

	u := iam.TestUser(t, iamRepo, orgWithTokens.GetPublicId(), iam.WithAccountIds(acct.PublicId))

	privProjRole := iam.TestRole(t, conn, pwt.GetPublicId())
	iam.TestRoleGrant(t, conn, privProjRole.GetPublicId(), "id=*;type=*;actions=*")
	iam.TestUserRole(t, conn, privProjRole.GetPublicId(), u.GetPublicId())

	var allTokens []*pb.AuthToken
	for i := 0; i < 9; i++ {
		at, _ := tokenRepo.CreateAuthToken(testCtx, u, acct.GetPublicId())
		atp := authTokenToProto(at, &scopes.ScopeInfo{Id: orgWithTokens.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()}, selfAuthorizedActions)
		allTokens = append(allTokens, atp)
	}

	a, err := authtokens.NewService(testCtx, tokenRepoFn, iamRepoFn, 1000)
	assert, require := assert.New(t), require.New(t)
	require.NoError(err, "Couldn't create new user service.")

	masterToken, _ := tokenRepo.CreateAuthToken(testCtx, u, acct.GetPublicId())
	mtp := authTokenToProto(masterToken, &scopes.ScopeInfo{Id: orgWithTokens.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()}, selfAuthorizedActions)
	allTokens = append(allTokens, mtp)

	// Run analyze to update postgres estimates
	_, err = sqlDB.ExecContext(testCtx, "analyze")
	require.NoError(err)

	requestInfo := authpb.RequestInfo{
		TokenFormat: uint32(auth.AuthTokenTypeBearer),
		Token:       masterToken.GetToken(),
		PublicId:    masterToken.GetPublicId(),
	}
	requestContext := context.WithValue(testCtx, requests.ContextRequestInformationKey, &requests.RequestContext{})
	ctx := auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)

	// Start paginating, recursively
	req := &pbs.ListAuthTokensRequest{
		ScopeId:      masterToken.GetScopeId(),
		Recursive:    true,
		Filter:       "",
		RefreshToken: "",
		PageSize:     2,
	}
	got, err := a.ListAuthTokens(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 2)
	// all comparisons will be done without comparing the refresh token
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListAuthTokensResponse{
				Items:        allTokens[0:2],
				ResponseType: "delta",
				RefreshToken: "",
				SortBy:       "updated_time",
				SortDir:      "asc",
				RemovedIds:   nil,
				EstItemCount: 10,
			},
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListAuthTokensResponse{}, "refresh_token"),
		),
	)

	// request second page
	req.RefreshToken = got.RefreshToken
	got, err = a.ListAuthTokens(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 2)
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListAuthTokensResponse{
				Items:        allTokens[2:4],
				ResponseType: "delta",
				RefreshToken: "",
				SortBy:       "updated_time",
				SortDir:      "asc",
				RemovedIds:   nil,
				EstItemCount: 10,
			},
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListAuthTokensResponse{}, "refresh_token"),
		),
	)

	// request the rest of the results
	req.RefreshToken = got.RefreshToken
	req.PageSize = 6
	got, err = a.ListAuthTokens(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 6)
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListAuthTokensResponse{
				Items:        allTokens[4:],
				ResponseType: "complete",
				RefreshToken: "",
				SortBy:       "updated_time",
				SortDir:      "asc",
				RemovedIds:   nil,
				EstItemCount: 10,
			},
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListAuthTokensResponse{}, "refresh_token"),
		),
	)

	// create another auth token
	at, _ := tokenRepo.CreateAuthToken(testCtx, u, acct.GetPublicId())
	newToken := authTokenToProto(at, &scopes.ScopeInfo{Id: orgWithTokens.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()}, selfAuthorizedActions)
	allTokens = append(allTokens, newToken)

	// delete a different auth token
	_, err = tokenRepo.DeleteAuthToken(ctx, allTokens[0].Id)
	require.NoError(err)
	deletedAuthToken := allTokens[0]
	allTokens = allTokens[1:]

	// Run analyze to update postgres estimates
	_, err = sqlDB.ExecContext(testCtx, "analyze")
	require.NoError(err)

	// request the changes
	req.RefreshToken = got.RefreshToken
	got, err = a.ListAuthTokens(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 1)
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListAuthTokensResponse{
				Items:        []*pb.AuthToken{newToken},
				ResponseType: "complete",
				RefreshToken: "",
				SortBy:       "updated_time",
				SortDir:      "asc",
				RemovedIds:   []string{deletedAuthToken.Id},
				EstItemCount: 10,
			},
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListAuthTokensResponse{}, "refresh_token"),
		),
	)

	// Request new page with filter requiring looping
	// to fill the page.
	req.RefreshToken = ""
	req.PageSize = 1
	req.Filter = fmt.Sprintf(`"/item/id"==%q or "/item/id"==%q`, allTokens[len(allTokens)-2].Id, allTokens[len(allTokens)-1].Id)
	got, err = a.ListAuthTokens(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 1)
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListAuthTokensResponse{
				Items:        []*pb.AuthToken{allTokens[len(allTokens)-2]},
				ResponseType: "delta",
				RefreshToken: "",
				SortBy:       "updated_time",
				SortDir:      "asc",
				// Should be empty again
				RemovedIds:   nil,
				EstItemCount: 10,
			},
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListAuthTokensResponse{}, "refresh_token"),
		),
	)
	req.RefreshToken = got.RefreshToken
	// Get the second page
	got, err = a.ListAuthTokens(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 1)
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListAuthTokensResponse{
				Items:        []*pb.AuthToken{allTokens[len(allTokens)-1]},
				ResponseType: "complete",
				RefreshToken: "",
				SortBy:       "updated_time",
				SortDir:      "asc",
				RemovedIds:   nil,
				EstItemCount: 10,
			},
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListAuthTokensResponse{}, "refresh_token"),
		),
	)
}

func TestDeleteSelf(t *testing.T) {
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)

	iamRepo := iam.TestRepo(t, conn, wrap)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(testCtx, rw, rw, kms)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(testCtx, rw, rw, kms)
	}

	a, err := authtokens.NewService(testCtx, tokenRepoFn, iamRepoFn, 1000)
	require.NoError(t, err, "Couldn't create new auth token service.")

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	at1 := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())
	at2 := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())

	cases := []struct {
		name     string
		token    *authtoken.AuthToken
		deleteId string
		err      error
	}{
		{
			name:     "at1 delete at2",
			token:    at1,
			deleteId: at2.GetPublicId(),
			err:      handlers.ApiErrorWithCodeAndMessage(codes.PermissionDenied, "Forbidden."),
		},
		{
			name:     "at2 delete at1",
			token:    at2,
			deleteId: at1.GetPublicId(),
			err:      handlers.ApiErrorWithCodeAndMessage(codes.PermissionDenied, "Forbidden."),
		},
		{
			name:     "at1 delete self",
			token:    at1,
			deleteId: at1.GetPublicId(),
		},
		{
			name:     "at2 delete self",
			token:    at2,
			deleteId: at2.GetPublicId(),
		},
		{
			name:     "at1 not found",
			token:    at1,
			deleteId: at1.GetPublicId(),
			err:      handlers.ApiErrorWithCodeAndMessage(codes.NotFound, "Resource not found."),
		},
		{
			name:     "at2 not found",
			token:    at2,
			deleteId: at2.GetPublicId(),
			err:      handlers.ApiErrorWithCodeAndMessage(codes.NotFound, "Resource not found."),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			// Setup the auth request information
			req := httptest.NewRequest("DELETE", fmt.Sprintf("http://127.0.0.1/v1/auth-tokens/%s", tc.deleteId), nil)
			requestInfo := authpb.RequestInfo{
				Path:        req.URL.Path,
				Method:      req.Method,
				TokenFormat: uint32(auth.AuthTokenTypeBearer),
				PublicId:    tc.token.GetPublicId(),
				Token:       tc.token.GetToken(),
			}

			ctx := auth.NewVerifierContext(testCtx, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)
			got, err := a.DeleteAuthToken(ctx, &pbs.DeleteAuthTokenRequest{Id: tc.deleteId})
			if tc.err != nil {
				require.EqualError(err, tc.err.Error())
				require.Nil(got)
				return
			}
			require.NoError(err)
		})
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrap), nil
	}
	repoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrap)

	org, _ := iam.TestScopes(t, iamRepo)
	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())

	s, err := authtokens.NewService(ctx, repoFn, iamRepoFn, 1000)
	require.NoError(t, err, "Error when getting new user service.")

	cases := []struct {
		name  string
		scope string
		req   *pbs.DeleteAuthTokenRequest
		res   *pbs.DeleteAuthTokenResponse
		err   error
	}{
		{
			name:  "Delete an existing token",
			scope: org.GetPublicId(),
			req: &pbs.DeleteAuthTokenRequest{
				Id: at.GetPublicId(),
			},
		},
		{
			name:  "Delete bad token id",
			scope: org.GetPublicId(),
			req: &pbs.DeleteAuthTokenRequest{
				Id: globals.AuthTokenPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:  "Bad token id formatting",
			scope: org.GetPublicId(),
			req: &pbs.DeleteAuthTokenRequest{
				Id: "bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteAuthToken(auth.DisabledAuthTestContext(iamRepoFn, tc.scope), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteAuthToken(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.EqualValuesf(tc.res, got, "DeleteAuthToken(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrap), nil
	}
	repoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrap)

	org, _ := iam.TestScopes(t, iamRepo)
	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())

	s, err := authtokens.NewService(ctx, repoFn, iamRepoFn, 1000)
	require.NoError(err, "Error when getting new user service")
	req := &pbs.DeleteAuthTokenRequest{
		Id: at.GetPublicId(),
	}
	_, gErr := s.DeleteAuthToken(auth.DisabledAuthTestContext(iamRepoFn, at.GetScopeId()), req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteAuthToken(auth.DisabledAuthTestContext(iamRepoFn, at.GetScopeId()), req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")
}
