package authtokens_test

import (
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
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/authtokens"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
		name    string
		req     *pbs.GetAuthTokenRequest
		res     *pbs.GetAuthTokenResponse
		errCode codes.Code
	}{
		{
			name:    "Get an existing auth token",
			req:     &pbs.GetAuthTokenRequest{Id: wireAuthToken.GetId()},
			res:     &pbs.GetAuthTokenResponse{Item: &wireAuthToken},
			errCode: codes.OK,
		},
		{
			name:    "Get a non existing auth token",
			req:     &pbs.GetAuthTokenRequest{Id: authtoken.AuthTokenPrefix + "_DoesntExis"},
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Wrong id prefix",
			req:     &pbs.GetAuthTokenRequest{Id: "j_1234567890"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "space in id",
			req:     &pbs.GetAuthTokenRequest{Id: authtoken.AuthTokenPrefix + "_1 23456789"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.GetAuthToken(auth.DisabledAuthTestContext(auth.WithScopeId(org.GetPublicId())), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetAuthToken(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
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
		name    string
		scope   string
		res     *pbs.ListAuthTokensResponse
		errCode codes.Code
	}{
		{
			name:    "List Some Tokens",
			scope:   orgWithSomeTokens.GetPublicId(),
			res:     &pbs.ListAuthTokensResponse{Items: wantSomeTokens},
			errCode: codes.OK,
		},
		{
			name:    "List Other Tokens",
			scope:   orgWithOtherTokens.GetPublicId(),
			res:     &pbs.ListAuthTokensResponse{Items: wantOtherTokens},
			errCode: codes.OK,
		},
		{
			name:    "List No Token",
			scope:   orgNoTokens.GetPublicId(),
			res:     &pbs.ListAuthTokensResponse{},
			errCode: codes.OK,
		},
		// TODO: When an org doesn't exist, we should return a 404 instead of an empty list.
		{
			name:    "Unfound Org",
			scope:   scope.Org.Prefix() + "_DoesntExis",
			errCode: codes.NotFound,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := authtokens.NewService(repoFn, iamRepoFn)
			require.NoError(t, err, "Couldn't create new user service.")

			got, gErr := s.ListAuthTokens(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scope)), &pbs.ListAuthTokensRequest{ScopeId: tc.scope})
			assert.Equal(t, tc.errCode, status.Code(gErr), "ListAuthTokens() with scope %q got error %v, wanted %v", tc.scope, gErr, tc.errCode)
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
		name    string
		scope   string
		req     *pbs.DeleteAuthTokenRequest
		res     *pbs.DeleteAuthTokenResponse
		errCode codes.Code
	}{
		{
			name:  "Delete an existing token",
			scope: org.GetPublicId(),
			req: &pbs.DeleteAuthTokenRequest{
				Id: at.GetPublicId(),
			},
			errCode: codes.OK,
		},
		{
			name:  "Delete bad token id",
			scope: org.GetPublicId(),
			req: &pbs.DeleteAuthTokenRequest{
				Id: authtoken.AuthTokenPrefix + "_doesntexis",
			},
			errCode: codes.NotFound,
		},
		{
			name:  "Bad token id formatting",
			scope: org.GetPublicId(),
			req: &pbs.DeleteAuthTokenRequest{
				Id: "bad_format",
			},
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.DeleteAuthToken(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scope)), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "DeleteAuthToken(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.EqualValuesf(tc.res, got, "DeleteAuthToken(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert := assert.New(t)
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
	require.NoError(t, err, "Error when getting new user service")
	req := &pbs.DeleteAuthTokenRequest{
		Id: at.GetPublicId(),
	}
	_, gErr := s.DeleteAuthToken(auth.DisabledAuthTestContext(auth.WithScopeId(at.GetScopeId())), req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteAuthToken(auth.DisabledAuthTestContext(auth.WithScopeId(at.GetScopeId())), req)
	assert.Error(gErr, "Second attempt")
	assert.Equal(codes.NotFound, status.Code(gErr), "Expected permission denied for the second delete.")
}
