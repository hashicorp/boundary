package authtokens_test

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
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

var testAuthorizedActions = []string{"no-op", "read", "read:self", "delete", "delete:self"}

func TestGetSelf(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)

	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrap), nil
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(rw, rw, kms)
	}

	a, err := authtokens.NewService(tokenRepoFn, iamRepoFn)
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

			ctx := auth.NewVerifierContext(context.Background(), iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)
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
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrap), nil
	}
	repoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}

	s, err := authtokens.NewService(repoFn, iamRepoFn)
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
		AuthorizedActions:       testAuthorizedActions,
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
			req:  &pbs.GetAuthTokenRequest{Id: authtoken.AuthTokenPrefix + "_DoesntExis"},
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
			req:  &pbs.GetAuthTokenRequest{Id: authtoken.AuthTokenPrefix + "_1 23456789"},
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
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)

	iamRepo := iam.TestRepo(t, conn, wrap)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(rw, rw, kms)
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

	a, err := authtokens.NewService(tokenRepoFn, iamRepoFn)
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

			ctx := auth.NewVerifierContext(context.Background(), iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)
			got, err := a.ListAuthTokens(ctx, &pbs.ListAuthTokensRequest{ScopeId: o.GetPublicId()})
			require.NoError(err)
			require.Len(got.Items, 1)
			assert.Equal(got.Items[0].GetId(), tc.requester.GetPublicId())
			// Ensure we didn't simply have e.g. read on all tokens
			assert.Equal(got.Items[0].GetAuthorizedActions(), []string{"read:self", "delete:self"})
		})
	}
}

func TestList(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrap), nil
	}
	repoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrap)

	orgNoTokens, _ := iam.TestScopes(t, iamRepo)

	var globalTokens []*pb.AuthToken
	for i := 0; i < 3; i++ {
		at := authtoken.TestAuthToken(t, conn, kms, scope.Global.String())
		globalTokens = append(globalTokens, &pb.AuthToken{
			Id:                      at.GetPublicId(),
			ScopeId:                 at.GetScopeId(),
			UserId:                  at.GetIamUserId(),
			AuthMethodId:            at.GetAuthMethodId(),
			AccountId:               at.GetAuthAccountId(),
			CreatedTime:             at.GetCreateTime().GetTimestamp(),
			UpdatedTime:             at.GetUpdateTime().GetTimestamp(),
			ApproximateLastUsedTime: at.GetApproximateLastAccessTime().GetTimestamp(),
			ExpirationTime:          at.GetExpirationTime().GetTimestamp(),
			Scope:                   &scopes.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
			AuthorizedActions:       testAuthorizedActions,
		})
	}

	orgWithSomeTokens, _ := iam.TestScopes(t, iamRepo)
	var wantSomeTokens []*pb.AuthToken
	for i := 0; i < 3; i++ {
		at := authtoken.TestAuthToken(t, conn, kms, orgWithSomeTokens.GetPublicId())
		wantSomeTokens = append(wantSomeTokens, &pb.AuthToken{
			Id:                      at.GetPublicId(),
			ScopeId:                 at.GetScopeId(),
			UserId:                  at.GetIamUserId(),
			AuthMethodId:            at.GetAuthMethodId(),
			AccountId:               at.GetAuthAccountId(),
			CreatedTime:             at.GetCreateTime().GetTimestamp(),
			UpdatedTime:             at.GetUpdateTime().GetTimestamp(),
			ApproximateLastUsedTime: at.GetApproximateLastAccessTime().GetTimestamp(),
			ExpirationTime:          at.GetExpirationTime().GetTimestamp(),
			Scope:                   &scopes.ScopeInfo{Id: orgWithSomeTokens.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			AuthorizedActions:       testAuthorizedActions,
		})
	}

	orgWithOtherTokens, _ := iam.TestScopes(t, iamRepo)
	var wantOtherTokens []*pb.AuthToken
	for i := 0; i < 3; i++ {
		at := authtoken.TestAuthToken(t, conn, kms, orgWithOtherTokens.GetPublicId())
		wantOtherTokens = append(wantOtherTokens, &pb.AuthToken{
			Id:                      at.GetPublicId(),
			ScopeId:                 at.GetScopeId(),
			UserId:                  at.GetIamUserId(),
			AuthMethodId:            at.GetAuthMethodId(),
			AccountId:               at.GetAuthAccountId(),
			CreatedTime:             at.GetCreateTime().GetTimestamp(),
			UpdatedTime:             at.GetUpdateTime().GetTimestamp(),
			ApproximateLastUsedTime: at.GetApproximateLastAccessTime().GetTimestamp(),
			ExpirationTime:          at.GetExpirationTime().GetTimestamp(),
			Scope:                   &scopes.ScopeInfo{Id: orgWithOtherTokens.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			AuthorizedActions:       testAuthorizedActions,
		})
	}

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
			res:  &pbs.ListAuthTokensResponse{Items: wantSomeTokens},
		},
		{
			name: "List Other Tokens",
			req:  &pbs.ListAuthTokensRequest{ScopeId: orgWithOtherTokens.GetPublicId()},
			res:  &pbs.ListAuthTokensResponse{Items: wantOtherTokens},
		},
		{
			name: "List No Token",
			req:  &pbs.ListAuthTokensRequest{ScopeId: orgNoTokens.GetPublicId()},
			res:  &pbs.ListAuthTokensResponse{},
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
			res:  &pbs.ListAuthTokensResponse{Items: allTokens},
		},
		{
			name: "Filter to Some Tokens",
			req: &pbs.ListAuthTokensRequest{
				ScopeId: "global", Recursive: true,
				Filter: fmt.Sprintf(`"/item/scope/id"==%q`, orgWithSomeTokens.GetPublicId()),
			},
			res: &pbs.ListAuthTokensResponse{Items: wantSomeTokens},
		},
		{
			name: "Filter All Tokens",
			req:  &pbs.ListAuthTokensRequest{ScopeId: orgWithOtherTokens.GetPublicId(), Filter: `"/item/scope/id"=="thisdoesntmatch"`},
			res:  &pbs.ListAuthTokensResponse{},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListAuthTokensRequest{ScopeId: orgWithSomeTokens.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := authtokens.NewService(repoFn, iamRepoFn)
			assert, require := assert.New(t), require.New(t)
			require.NoError(err, "Couldn't create new user service.")

			// Check non-anon listing
			got, gErr := s.ListAuthTokens(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId(), auth.WithUserId("u_auth")), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListAuthTokens() with scope %q got error %v, wanted %v", tc.req.GetScopeId(), gErr, tc.err)
				return
			} else {
				require.NoError(gErr)
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform(), protocmp.SortRepeatedFields(got)), "ListAuthTokens() with scope %q got response %q, wanted %q", tc.req.GetScopeId(), got, tc.res)

			// Now check anon listing
			got, gErr = s.ListAuthTokens(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId(), auth.WithUserId(auth.AnonymousUserId)), tc.req)
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

func TestDeleteSelf(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)

	iamRepo := iam.TestRepo(t, conn, wrap)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(rw, rw, kms)
	}

	a, err := authtokens.NewService(tokenRepoFn, iamRepoFn)
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

			ctx := auth.NewVerifierContext(context.Background(), iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)
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
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrap), nil
	}
	repoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrap)

	org, _ := iam.TestScopes(t, iamRepo)
	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())

	s, err := authtokens.NewService(repoFn, iamRepoFn)
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
				Id: authtoken.AuthTokenPrefix + "_doesntexis",
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
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrap), nil
	}
	repoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrap)

	org, _ := iam.TestScopes(t, iamRepo)
	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())

	s, err := authtokens.NewService(repoFn, iamRepoFn)
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
