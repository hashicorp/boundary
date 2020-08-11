package authenticate

import (
	"context"
	"strings"
	"testing"

	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	pba "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authtokens"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testPassword = "thetestpassword"
	testUsername = "default"
)

func TestAuthenticate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	o, _ := iam.TestScopes(t, conn)

	authTokenRepoFn := func() (*authtoken.Repository, error) { return authtoken.NewRepository(rw, rw, wrapper) }
	iamRepoFn := func() (*iam.Repository, error) { return iam.NewRepository(rw, rw, wrapper) }
	passwordRepoFn := func() (*password.Repository, error) { return password.NewRepository(rw, rw, wrapper) }
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	acct, err := password.NewAccount(am.GetPublicId(), testUsername)
	require.NoError(t, err)

	pwRepo, err := passwordRepoFn()
	require.NoError(t, err)
	acct, err = pwRepo.CreateAccount(context.Background(), acct, password.WithPassword(testPassword))
	require.NoError(t, err)

	cases := []struct {
		name    string
		request *pbs.AuthenticateRequest
		want    *pbs.AuthenticateResponse
		wantErr error
	}{
		{
			name: "basic",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "token",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"name":     {Kind: &structpb.Value_StringValue{StringValue: testUsername}},
						"password": {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			want: &pbs.AuthenticateResponse{Item: &pba.AuthToken{
				AuthMethodId: am.GetPublicId(),
			}},
		},
		{
			name: "no-token-type",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"name":     {Kind: &structpb.Value_StringValue{StringValue: testUsername}},
						"password": {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			want: &pbs.AuthenticateResponse{Item: &pba.AuthToken{
				AuthMethodId: am.GetPublicId(),
			}},
		},
		{
			name: "bad-token-type",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "email",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"name":     {Kind: &structpb.Value_StringValue{StringValue: testUsername}},
						"password": {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantErr: status.Error(codes.InvalidArgument, "invalid argument"),
		},
		{
			name: "no-authmethod",
			request: &pbs.AuthenticateRequest{
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"name":     {Kind: &structpb.Value_StringValue{StringValue: testUsername}},
						"password": {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantErr: status.Error(codes.InvalidArgument, "invalid argument"),
		},
		{
			name: "wrong-password",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "token",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"name":     {Kind: &structpb.Value_StringValue{StringValue: testUsername}},
						"password": {Kind: &structpb.Value_StringValue{StringValue: "wrong"}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantErr: status.Error(codes.Unauthenticated, "unauthenticated"),
		},
		{
			name: "wrong-login-name",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "token",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"name":     {Kind: &structpb.Value_StringValue{StringValue: "wrong"}},
						"password": {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantErr: status.Error(codes.Unauthenticated, "unauthenticated"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := NewService(passwordRepoFn, iamRepoFn, authTokenRepoFn)
			require.NoError(err)

			resp, err := s.Authenticate(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), tc.request)
			if tc.wantErr != nil {
				assert.Error(err)
				assert.Equal(status.Code(tc.wantErr), status.Code(err))
				return
			}
			require.NoError(err)
			aToken := resp.GetItem()
			assert.NotEmpty(aToken.GetId())
			assert.NotEmpty(aToken.GetToken())
			assert.True(strings.HasPrefix(aToken.GetToken(), aToken.GetId()))
			assert.Equal(am.GetPublicId(), aToken.GetAuthMethodId())
			assert.Equal(aToken.GetCreatedTime(), aToken.GetUpdatedTime())
			assert.Equal(aToken.GetCreatedTime(), aToken.GetApproximateLastUsedTime())
		})
	}
}

func TestAuthenticate_AuthAccountConnectedToIamUser(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	o, _ := iam.TestScopes(t, conn)

	passwordRepoFn := func() (*password.Repository, error) { return password.NewRepository(rw, rw, wrapper) }
	authTokenRepoFn := func() (*authtoken.Repository, error) { return authtoken.NewRepository(rw, rw, wrapper) }
	iamRepoFn := func() (*iam.Repository, error) { return iam.NewRepository(rw, rw, wrapper) }

	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	acct, err := password.NewAccount(am.GetPublicId(), testUsername)
	require.NoError(err)

	pwRepo, err := passwordRepoFn()
	require.NoError(err)
	acct, err = pwRepo.CreateAccount(context.Background(), acct, password.WithPassword(testPassword))
	require.NoError(err)

	// connected to an account.
	iamRepo, err := iamRepoFn()
	require.NoError(err)
	iamUser, err := iamRepo.LookupUserWithLogin(context.Background(), acct.GetPublicId(), iam.WithAutoVivify(true))
	require.NoError(err)

	s, err := NewService(passwordRepoFn, iamRepoFn, authTokenRepoFn)
	require.NoError(err)
	resp, err := s.Authenticate(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), &pbs.AuthenticateRequest{
		AuthMethodId: am.GetPublicId(),
		Credentials: func() *structpb.Struct {
			creds := map[string]*structpb.Value{
				"name":     {Kind: &structpb.Value_StringValue{StringValue: testUsername}},
				"password": {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
			}
			return &structpb.Struct{Fields: creds}
		}(),
	})
	require.NoError(err)

	aToken := resp.GetItem()
	assert.Equal(iamUser.GetPublicId(), aToken.GetUserId())
	assert.Equal(am.GetPublicId(), aToken.GetAuthMethodId())

	assert.NotEmpty(aToken.GetId())
	assert.NotEmpty(aToken.GetToken())
	assert.True(strings.HasPrefix(aToken.GetToken(), aToken.GetId()))
}
