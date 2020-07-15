package authtokens_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/watchtower/internal/authtoken"
	"github.com/hashicorp/watchtower/internal/db"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/authtokens"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/authtokens"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGet(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, wrap)
	}

	org, _ := iam.TestScopes(t, conn)
	at := authtoken.TestAuthToken(t, conn, wrap, org.GetPublicId())

	toMerge := &pbs.GetAuthTokenRequest{
		OrgId: org.GetPublicId(),
	}

	wireAuthToken := pb.AuthToken{
		Id:                      at.GetPublicId(),
		UserId:                  at.GetIamUserId(),
		AuthMethodId:            at.GetAuthMethodId(),
		CreatedTime:             at.GetCreateTime().GetTimestamp(),
		UpdatedTime:             at.GetUpdateTime().GetTimestamp(),
		ApproximateLastUsedTime: at.GetApproximateLastAccessTime().GetTimestamp(),
		ExpirationTime:          at.GetExpirationTime().GetTimestamp(),
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
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.GetAuthTokenRequest)
			proto.Merge(req, tc.req)

			s, err := authtokens.NewService(repoFn)
			require.NoError(err, "Couldn't create new project service.")

			got, gErr := s.GetAuthToken(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetOrg(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			assert.True(proto.Equal(got, tc.res), "GetOrg(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, wrap)
	}

	orgNoTokens, _ := iam.TestScopes(t, conn)

	orgWithSomeTokens, _ := iam.TestScopes(t, conn)
	var wantSomeTokens []*pb.AuthToken
	for i := 0; i < 3; i++ {
		at := authtoken.TestAuthToken(t, conn, wrap, orgWithSomeTokens.GetPublicId())
		wantSomeTokens = append(wantSomeTokens, &pb.AuthToken{
			Id:                      at.GetPublicId(),
			UserId:                  at.GetIamUserId(),
			AuthMethodId:            at.GetAuthMethodId(),
			CreatedTime:             at.GetCreateTime().GetTimestamp(),
			UpdatedTime:             at.GetUpdateTime().GetTimestamp(),
			ApproximateLastUsedTime: at.GetApproximateLastAccessTime().GetTimestamp(),
			ExpirationTime:          at.GetExpirationTime().GetTimestamp(),
		})
	}

	orgWithOtherTokens, _ := iam.TestScopes(t, conn)
	var wantOtherTokens []*pb.AuthToken
	for i := 0; i < 3; i++ {
		at := authtoken.TestAuthToken(t, conn, wrap, orgWithOtherTokens.GetPublicId())
		wantOtherTokens = append(wantOtherTokens, &pb.AuthToken{
			Id:                      at.GetPublicId(),
			UserId:                  at.GetIamUserId(),
			AuthMethodId:            at.GetAuthMethodId(),
			CreatedTime:             at.GetCreateTime().GetTimestamp(),
			UpdatedTime:             at.GetUpdateTime().GetTimestamp(),
			ApproximateLastUsedTime: at.GetApproximateLastAccessTime().GetTimestamp(),
			ExpirationTime:          at.GetExpirationTime().GetTimestamp(),
		})
	}

	cases := []struct {
		name    string
		req     *pbs.ListAuthTokensRequest
		res     *pbs.ListAuthTokensResponse
		errCode codes.Code
	}{
		{
			name:    "List Some Tokens",
			req:     &pbs.ListAuthTokensRequest{OrgId: orgWithSomeTokens.GetPublicId()},
			res:     &pbs.ListAuthTokensResponse{Items: wantSomeTokens},
			errCode: codes.OK,
		},
		{
			name:    "List Other Tokens",
			req:     &pbs.ListAuthTokensRequest{OrgId: orgWithOtherTokens.GetPublicId()},
			res:     &pbs.ListAuthTokensResponse{Items: wantOtherTokens},
			errCode: codes.OK,
		},
		{
			name:    "List No Token",
			req:     &pbs.ListAuthTokensRequest{OrgId: orgNoTokens.GetPublicId()},
			res:     &pbs.ListAuthTokensResponse{},
			errCode: codes.OK,
		},
		{
			name:    "Invalid Org Id",
			req:     &pbs.ListAuthTokensRequest{OrgId: iam.UserPrefix + "_this is invalid"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		// TODO: When an org doesn't exist, we should return a 404 instead of an empty list.
		{
			name:    "Unfound Org",
			req:     &pbs.ListAuthTokensRequest{OrgId: scope.Org.Prefix() + "_DoesntExis"},
			res:     &pbs.ListAuthTokensResponse{},
			errCode: codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := authtokens.NewService(repoFn)
			require.NoError(t, err, "Couldn't create new user service.")

			got, gErr := s.ListAuthTokens(context.Background(), tc.req)
			assert.Equal(t, tc.errCode, status.Code(gErr), "ListUsers(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.Empty(t, cmp.Diff(got, tc.res, protocmp.Transform(), protocmp.SortRepeatedFields(got)), "ListUsers(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, wrap)
	}

	org, _ := iam.TestScopes(t, conn)
	at := authtoken.TestAuthToken(t, conn, wrap, org.GetPublicId())

	s, err := authtokens.NewService(repoFn)
	require.NoError(t, err, "Error when getting new user service.")

	cases := []struct {
		name    string
		req     *pbs.DeleteAuthTokenRequest
		res     *pbs.DeleteAuthTokenResponse
		errCode codes.Code
	}{
		{
			name: "Delete an Existing User",
			req: &pbs.DeleteAuthTokenRequest{
				OrgId: org.GetPublicId(),
				Id:    at.GetPublicId(),
			},
			res: &pbs.DeleteAuthTokenResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name: "Delete bad user id",
			req: &pbs.DeleteAuthTokenRequest{
				OrgId: org.GetPublicId(),
				Id:    authtoken.AuthTokenPrefix + "_doesntexis",
			},
			res: &pbs.DeleteAuthTokenResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Delete bad org id",
			req: &pbs.DeleteAuthTokenRequest{
				OrgId: "o_doesntexis",
				Id:    at.GetPublicId(),
			},
			res: &pbs.DeleteAuthTokenResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Bad org formatting",
			req: &pbs.DeleteAuthTokenRequest{
				OrgId: "bad_format",
				Id:    at.GetPublicId(),
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad User Id formatting",
			req: &pbs.DeleteAuthTokenRequest{
				OrgId: org.GetPublicId(),
				Id:    "bad_format",
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.DeleteAuthToken(context.Background(), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "DeleteUser(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.EqualValuesf(tc.res, got, "DeleteUser(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert := assert.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, wrap)
	}

	org, _ := iam.TestScopes(t, conn)
	at := authtoken.TestAuthToken(t, conn, wrap, org.GetPublicId())

	s, err := authtokens.NewService(repoFn)
	require.NoError(t, err, "Error when getting new user service")
	req := &pbs.DeleteAuthTokenRequest{
		OrgId: at.GetScopeId(),
		Id:    at.GetPublicId(),
	}
	got, gErr := s.DeleteAuthToken(context.Background(), req)
	assert.NoError(gErr, "First attempt")
	assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	got, gErr = s.DeleteAuthToken(context.Background(), req)
	assert.NoError(gErr, "Second attempt")
	assert.False(got.GetExisted(), "Expected existed to be false for the second delete.")
}
