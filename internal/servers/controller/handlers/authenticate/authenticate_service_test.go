package authenticate

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"
	"testing"

	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/hashicorp/watchtower/internal/authtoken"
	"github.com/hashicorp/watchtower/internal/db"
	pba "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/authtokens"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	iamStore "github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func getAuthMethodAndAccountId(t *testing.T, org *iam.Scope, rw *db.Db) (string, string) {
	// TODO: Remove this when Auth Account repo is in place.
	insert := `insert into auth_method
	(public_id, scope_id)
	values
	($1, $2);`
	amId, err := db.NewPublicId("am")
	require.NoError(t, err)
	innerDb, err := rw.DB()
	require.NoError(t, err)
	_, err = innerDb.Exec(insert, amId, org.GetPublicId())
	require.NoError(t, err)
	aAcctId, err := db.NewPublicId("aa")
	require.NoError(t, err)

	aAcct := &iam.AuthAccount{AuthAccount: &iamStore.AuthAccount{
		PublicId:     aAcctId,
		ScopeId:      org.GetPublicId(),
		AuthMethodId: amId,
	}}
	require.NoError(t, rw.Create(context.Background(), aAcct))
	return aAcct.GetAuthMethodId(), aAcct.GetPublicId()
}

func TestAuthenticate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	RWDb.Store(rw)
	wrapper := db.TestWrapper(t)
	o, _ := iam.TestScopes(t, conn)

	authTokenRepoFn := func() (*authtoken.Repository, error) { return authtoken.NewRepository(rw, rw, wrapper) }
	iamRepoFn := func() (*iam.Repository, error) { return iam.NewRepository(rw, rw, wrapper) }
	amId, _ := getAuthMethodAndAccountId(t, o, rw)

	cases := []struct {
		name    string
		request *pbs.AuthenticateRequest
		want    *pbs.AuthenticateResponse
		wantErr error
	}{
		{
			name: "basic",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: amId,
				TokenType:    "token",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"name":     {Kind: &structpb.Value_StringValue{StringValue: "admin"}},
						"password": {Kind: &structpb.Value_StringValue{StringValue: "hunter2"}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			want: &pbs.AuthenticateResponse{Item: &pba.AuthToken{
				AuthMethodId: amId,
			}},
		},
		{
			name: "no-token-type",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: amId,
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"name":     {Kind: &structpb.Value_StringValue{StringValue: "admin"}},
						"password": {Kind: &structpb.Value_StringValue{StringValue: "hunter2"}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			want: &pbs.AuthenticateResponse{Item: &pba.AuthToken{
				AuthMethodId: amId,
			}},
		},
		{
			name: "bad-token-type",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: amId,
				TokenType:    "email",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"name":     {Kind: &structpb.Value_StringValue{StringValue: "admin"}},
						"password": {Kind: &structpb.Value_StringValue{StringValue: "hunter2"}},
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
						"name":     {Kind: &structpb.Value_StringValue{StringValue: "admin"}},
						"password": {Kind: &structpb.Value_StringValue{StringValue: "hunter2"}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantErr: status.Error(codes.InvalidArgument, "invalid argument"),
		},
		{
			name: "wrong-username-password",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: amId,
				TokenType:    "token",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"name":     {Kind: &structpb.Value_StringValue{StringValue: "wrong"}},
						"password": {Kind: &structpb.Value_StringValue{StringValue: "wrong"}},
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
			s, err := NewService(iamRepoFn, authTokenRepoFn)
			require.NoError(err)

			// TODO: remove when we stop faking things
			name := tc.request.Credentials.Fields["name"].GetStringValue()
			acctIdBytes := sha256.Sum256([]byte(name))
			acctId := fmt.Sprintf("aa_%s", base32.StdEncoding.EncodeToString(acctIdBytes[:])[0:10])

			aAcct := &iam.AuthAccount{AuthAccount: &iamStore.AuthAccount{
				PublicId:     acctId,
				ScopeId:      o.PublicId,
				AuthMethodId: amId,
			}}
			RWDb.Load().(*db.Db).Create(context.Background(), aAcct)

			resp, err := s.Authenticate(context.Background(), tc.request)
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
			assert.Equal(amId, aToken.GetAuthMethodId())
			assert.Equal(aToken.GetCreatedTime(), aToken.GetUpdatedTime())
			assert.Equal(aToken.GetCreatedTime(), aToken.GetApproximateLastUsedTime())
		})
	}
}

func TestAuthenticate_AuthAccountConnectedToIamUser(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	RWDb.Store(rw)
	wrapper := db.TestWrapper(t)
	o, _ := iam.TestScopes(t, conn)

	authTokenRepoFn := func() (*authtoken.Repository, error) { return authtoken.NewRepository(rw, rw, wrapper) }
	iamRepoFn := func() (*iam.Repository, error) { return iam.NewRepository(rw, rw, wrapper) }
	iamRepo, err := iamRepoFn()
	require.NoError(err)

	// connected to an account.
	amId, _ := getAuthMethodAndAccountId(t, o, rw)

	name := "admin"
	acctIdBytes := sha256.Sum256([]byte(name))
	acctId := fmt.Sprintf("aa_%s", base32.StdEncoding.EncodeToString(acctIdBytes[:])[0:10])

	aAcct := &iam.AuthAccount{AuthAccount: &iamStore.AuthAccount{
		PublicId:     acctId,
		ScopeId:      o.PublicId,
		AuthMethodId: amId,
	}}
	RWDb.Load().(*db.Db).Create(context.Background(), aAcct)

	iamUser, err := iamRepo.LookupUserWithLogin(context.Background(), acctId, iam.WithAutoVivify(true))
	require.NoError(err)

	s, err := NewService(iamRepoFn, authTokenRepoFn)
	require.NoError(err)
	resp, err := s.Authenticate(context.Background(), &pbs.AuthenticateRequest{
		AuthMethodId: amId,
		Credentials: func() *structpb.Struct {
			creds := map[string]*structpb.Value{
				"name":     {Kind: &structpb.Value_StringValue{StringValue: name}},
				"password": {Kind: &structpb.Value_StringValue{StringValue: "hunter2"}},
			}
			return &structpb.Struct{Fields: creds}
		}(),
	})
	require.NoError(err)

	aToken := resp.GetItem()
	assert.Equal(iamUser.GetPublicId(), aToken.GetUserId())
	assert.Equal(amId, aToken.GetAuthMethodId())

	assert.NotEmpty(aToken.GetId())
	assert.NotEmpty(aToken.GetToken())
	assert.True(strings.HasPrefix(aToken.GetToken(), aToken.GetId()))
}
