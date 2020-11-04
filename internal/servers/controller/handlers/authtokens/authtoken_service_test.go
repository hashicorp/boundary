package authtokens_test

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authtokens"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/authtokens"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		Scope:                   &scopes.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String()},
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
			got, gErr := s.GetAuthToken(auth.DisabledAuthTestContext(auth.WithScopeId(org.GetPublicId())), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetAuthToken(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetAuthToken(%q) got response %q, wanted %q", tc.req, got, tc.res)
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
			Scope:                   &scopes.ScopeInfo{Id: orgWithSomeTokens.GetPublicId(), Type: scope.Org.String()},
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
			Scope:                   &scopes.ScopeInfo{Id: orgWithOtherTokens.GetPublicId(), Type: scope.Org.String()},
		})
	}

	cases := []struct {
		name  string
		scope string
		res   *pbs.ListAuthTokensResponse
		err   error
	}{
		{
			name:  "List Some Tokens",
			scope: orgWithSomeTokens.GetPublicId(),
			res:   &pbs.ListAuthTokensResponse{Items: wantSomeTokens},
		},
		{
			name:  "List Other Tokens",
			scope: orgWithOtherTokens.GetPublicId(),
			res:   &pbs.ListAuthTokensResponse{Items: wantOtherTokens},
		},
		{
			name:  "List No Token",
			scope: orgNoTokens.GetPublicId(),
			res:   &pbs.ListAuthTokensResponse{},
		},
		// TODO: When an org doesn't exist, we should return a 404 instead of an empty list.
		{
			name:  "Unfound Org",
			scope: scope.Org.Prefix() + "_DoesntExis",
			err:   handlers.ApiErrorWithCode(codes.NotFound),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := authtokens.NewService(repoFn, iamRepoFn)
			require.NoError(t, err, "Couldn't create new user service.")

			got, gErr := s.ListAuthTokens(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scope)), &pbs.ListAuthTokensRequest{ScopeId: tc.scope})
			if tc.err != nil {
				require.Error(t, gErr)
				assert.True(t, errors.Is(gErr, tc.err), "ListAuthTokens() with scope %q got error %v, wanted %v", tc.scope, gErr, tc.err)
			}
			assert.Empty(t, cmp.Diff(got, tc.res, protocmp.Transform(), protocmp.SortRepeatedFields(got)), "ListAuthTokens() with scope %q got response %q, wanted %q", tc.scope, got, tc.res)
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
			res: &pbs.DeleteAuthTokenResponse{},
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
			got, gErr := s.DeleteAuthToken(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scope)), tc.req)
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
	_, gErr := s.DeleteAuthToken(auth.DisabledAuthTestContext(auth.WithScopeId(at.GetScopeId())), req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteAuthToken(auth.DisabledAuthTestContext(auth.WithScopeId(at.GetScopeId())), req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")
}
