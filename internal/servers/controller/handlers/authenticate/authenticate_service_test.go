package authenticate

import (
	"context"
	"errors"
	"strings"
	"testing"

	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	testPassword  = "thetestpassword"
	testLoginName = "default"
)

func TestAuthenticate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	authTokenRepoFn := func() (*authtoken.Repository, error) { return authtoken.NewRepository(rw, rw, kms) }
	iamRepoFn := func() (*iam.Repository, error) { return iam.NewRepository(rw, rw, kms) }
	passwordRepoFn := func() (*password.Repository, error) { return password.NewRepository(rw, rw, kms) }
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	acct, err := password.NewAccount(am.GetPublicId(), password.WithLoginName(testLoginName))
	require.NoError(t, err)

	pwRepo, err := passwordRepoFn()
	require.NoError(t, err)
	acct, err = pwRepo.CreateAccount(context.Background(), o.GetPublicId(), acct, password.WithPassword(testPassword))
	require.NoError(t, err)
	require.NotNil(t, acct)

	cases := []struct {
		name     string
		request  *pbs.AuthenticateRequest
		wantType string
		wantErr  error
	}{
		{
			name: "basic",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "token",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantType: "token",
		},
		{
			name: "cookie-type",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "cookie",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantType: "cookie",
		},
		{
			name: "no-token-type",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
		},
		{
			name: "bad-token-type",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "email",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantErr: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "no-authmethod",
			request: &pbs.AuthenticateRequest{
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantErr: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "wrong-password",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "token",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: "wrong"}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantErr: handlers.ApiErrorWithCode(codes.Unauthenticated),
		},
		{
			name: "wrong-login-name",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "token",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: "wrong"}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantErr: handlers.ApiErrorWithCode(codes.Unauthenticated),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := NewService(kms, passwordRepoFn, iamRepoFn, authTokenRepoFn)
			require.NoError(err)

			resp, err := s.Authenticate(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), tc.request)
			if tc.wantErr != nil {
				assert.Error(err)
				assert.Truef(errors.Is(err, tc.wantErr), "Got %#v, wanted %#v", err, tc.wantErr)
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
			assert.Equal(acct.GetPublicId(), aToken.GetAccountId())
			assert.Equal(am.GetPublicId(), aToken.GetAuthMethodId())
			assert.Equal(tc.wantType, resp.GetTokenType())
		})
	}
}

func TestAuthenticate_AuthAccountConnectedToIamUser(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	passwordRepoFn := func() (*password.Repository, error) { return password.NewRepository(rw, rw, kms) }
	authTokenRepoFn := func() (*authtoken.Repository, error) { return authtoken.NewRepository(rw, rw, kms) }
	iamRepoFn := func() (*iam.Repository, error) { return iam.NewRepository(rw, rw, kms) }

	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	acct, err := password.NewAccount(am.GetPublicId(), password.WithLoginName(testLoginName))
	require.NoError(err)

	pwRepo, err := passwordRepoFn()
	require.NoError(err)
	acct, err = pwRepo.CreateAccount(context.Background(), o.GetPublicId(), acct, password.WithPassword(testPassword))
	require.NoError(err)

	// connected to an account.
	iamRepo, err := iamRepoFn()
	require.NoError(err)
	iamUser, err := iamRepo.LookupUserWithLogin(context.Background(), acct.GetPublicId(), iam.WithAutoVivify(true))
	require.NoError(err)

	s, err := NewService(kms, passwordRepoFn, iamRepoFn, authTokenRepoFn)
	require.NoError(err)
	resp, err := s.Authenticate(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), &pbs.AuthenticateRequest{
		AuthMethodId: am.GetPublicId(),
		Credentials: func() *structpb.Struct {
			creds := map[string]*structpb.Value{
				"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
				"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
			}
			return &structpb.Struct{Fields: creds}
		}(),
	})
	require.NoError(err)

	aToken := resp.GetItem()
	assert.Equal(iamUser.GetPublicId(), aToken.GetUserId())
	assert.Equal(am.GetPublicId(), aToken.GetAuthMethodId())
	assert.Equal(acct.GetPublicId(), aToken.GetAccountId())

	assert.NotEmpty(aToken.GetId())
	assert.NotEmpty(aToken.GetToken())
	assert.True(strings.HasPrefix(aToken.GetToken(), aToken.GetId()))
}
