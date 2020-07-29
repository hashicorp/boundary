package accounts_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/watchtower/internal/auth"
	"github.com/hashicorp/watchtower/internal/auth/password"
	"github.com/hashicorp/watchtower/internal/authtoken"
	"github.com/hashicorp/watchtower/internal/db"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/auth"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/accounts"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestGet(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, wrap)
	}

	s, err := accounts.NewService(repoFn)
	require.NoError(t, err, "Couldn't create new auth token service.")

	org, _ := iam.TestScopes(t, conn)
	am := password.TestAuthMethods(t, conn, org.GetPublicId(), 1)[0]
	aa := password.TestAccounts(t, conn, org.GetPublicId(), am.GetPublicId(), 1)[0]

	wireAccount := pb.Account{
		Id:           aa.GetPublicId(),
		AuthMethodId: aa.GetAuthMethodId(),
		CreatedTime:  aa.GetCreateTime().GetTimestamp(),
		UpdatedTime:  aa.GetUpdateTime().GetTimestamp(),
		Scope:        &scopes.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String()},
		Type:         "password",
		Attributes:   &structpb.Struct{Fields: map[string]*structpb.Value{"username": structpb.NewStringValue(aa.GetUserName())}},
	}

	cases := []struct {
		name    string
		req     *pbs.GetAccountRequest
		res     *pbs.GetAccountResponse
		errCode codes.Code
	}{
		{
			name:    "Get an existing account",
			req:     &pbs.GetAccountRequest{AuthMethodId: wireAccount.GetAuthMethodId(), Id: wireAccount.GetId()},
			res:     &pbs.GetAccountResponse{Item: &wireAccount},
			errCode: codes.OK,
		},
		{
			name:    "Get a non existing account",
			req:     &pbs.GetAccountRequest{AuthMethodId: wireAccount.GetAuthMethodId(), Id: password.AccountPrefix + "_DoesntExis"},
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Wrong id prefix",
			req:     &pbs.GetAccountRequest{AuthMethodId: wireAccount.GetAuthMethodId(), Id: "j_1234567890"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "space in id",
			req:     &pbs.GetAccountRequest{AuthMethodId: wireAccount.GetAuthMethodId(), Id: authtoken.AuthTokenPrefix + "_1 23456789"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.GetAccount(auth.DisabledAuthTestContext(auth.WithScopeId(org.GetPublicId())), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetAccount(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetAccount(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, wrap)
	}

	o, _ := iam.TestScopes(t, conn)
	ams := password.TestAuthMethods(t, conn, o.GetPublicId(), 3)
	amNoAccounts, amSomeAccounts, amOtherAccounts := ams[0], ams[1], ams[2]

	var wantSomeAccounts []*pb.Account
	for _, aa := range password.TestAccounts(t, conn, o.GetPublicId(), amSomeAccounts.GetPublicId(), 3) {
		wantSomeAccounts = append(wantSomeAccounts, &pb.Account{
			Id:           aa.GetPublicId(),
			AuthMethodId: aa.GetAuthMethodId(),
			CreatedTime:  aa.GetCreateTime().GetTimestamp(),
			UpdatedTime:  aa.GetUpdateTime().GetTimestamp(),
			Scope:        &scopes.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String()},
			Type:         "password",
			Attributes:   &structpb.Struct{Fields: map[string]*structpb.Value{"username": structpb.NewStringValue(aa.GetUserName())}},
		})
	}

	var wantOtherAccounts []*pb.Account
	for _, aa := range password.TestAccounts(t, conn, o.GetPublicId(), amOtherAccounts.GetPublicId(), 3) {
		wantOtherAccounts = append(wantOtherAccounts, &pb.Account{
			Id:           aa.GetPublicId(),
			AuthMethodId: aa.GetAuthMethodId(),
			CreatedTime:  aa.GetCreateTime().GetTimestamp(),
			UpdatedTime:  aa.GetUpdateTime().GetTimestamp(),
			Scope:        &scopes.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String()},
			Type:         "password",
			Attributes:   &structpb.Struct{Fields: map[string]*structpb.Value{"username": structpb.NewStringValue(aa.GetUserName())}},
		})
	}

	cases := []struct {
		name       string
		authMethod string
		res        *pbs.ListAccountsResponse
		errCode    codes.Code
	}{
		{
			name:       "List Some Accounts",
			authMethod: amSomeAccounts.GetPublicId(),
			res:        &pbs.ListAccountsResponse{Items: wantSomeAccounts},
			errCode:    codes.OK,
		},
		{
			name:       "List Other Accounts",
			authMethod: amOtherAccounts.GetPublicId(),
			res:        &pbs.ListAccountsResponse{Items: wantOtherAccounts},
			errCode:    codes.OK,
		},
		{
			name:       "List No Accounts",
			authMethod: amNoAccounts.GetPublicId(),
			res:        &pbs.ListAccountsResponse{},
			errCode:    codes.OK,
		},
		// TODO: When an auth method doesn't exist, we should return a 404 instead of an empty list.
		{
			name:       "Unfound Auth Method",
			authMethod: password.AuthMethodPrefix + "_DoesntExis",
			res:        &pbs.ListAccountsResponse{},
			errCode:    codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := accounts.NewService(repoFn)
			require.NoError(t, err, "Couldn't create new user service.")

			got, gErr := s.ListAccounts(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), &pbs.ListAccountsRequest{AuthMethodId: tc.authMethod})
			assert.Equal(t, tc.errCode, status.Code(gErr), "ListAccounts() with auth method %q got error %v, wanted %v", tc.authMethod, gErr, tc.errCode)
			assert.Empty(t, cmp.Diff(got, tc.res, protocmp.Transform(), protocmp.SortRepeatedFields(got)), "ListUsers() with scope %q got response %q, wanted %q", tc.authMethod, got, tc.res)
		})
	}
}

func TestDelete(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, wrap)
	}

	o, _ := iam.TestScopes(t, conn)
	ams := password.TestAuthMethods(t, conn, o.GetPublicId(), 2)
	am1, wrongAm := ams[0], ams[1]

	ac := password.TestAccounts(t, conn, o.GetPublicId(), am1.GetPublicId(), 1)[0]
	wrongAc := password.TestAccounts(t, conn, o.GetPublicId(), wrongAm.GetPublicId(), 1)[0]

	s, err := accounts.NewService(repoFn)
	require.NoError(t, err, "Error when getting new user service.")

	cases := []struct {
		name    string
		scope   string
		req     *pbs.DeleteAccountRequest
		res     *pbs.DeleteAccountResponse
		errCode codes.Code
	}{
		{
			name: "Delete an existing token",
			req: &pbs.DeleteAccountRequest{
				AuthMethodId: am1.GetPublicId(),
				Id:           ac.GetPublicId(),
			},
			res: &pbs.DeleteAccountResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name: "Delete account from wrong auth method",
			req: &pbs.DeleteAccountRequest{
				AuthMethodId: am1.GetPublicId(),
				Id:           wrongAc.GetPublicId(),
			},
			// TODO(toddknight): This should return Existed:false. Figure out if this test is testing something valid
			// and if so make it pass.
			res: &pbs.DeleteAccountResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name: "Delete bad account id",
			req: &pbs.DeleteAccountRequest{
				AuthMethodId: am1.GetPublicId(),
				Id:           password.AccountPrefix + "_doesntexis",
			},
			res: &pbs.DeleteAccountResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Bad account id formatting",
			req: &pbs.DeleteAccountRequest{
				AuthMethodId: am1.GetPublicId(),
				Id:           "bad_format",
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.DeleteAccount(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "DeleteAccount(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.EqualValuesf(tc.res, got, "DeleteAccount(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert := assert.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, wrap)
	}

	org, _ := iam.TestScopes(t, conn)
	am := password.TestAuthMethods(t, conn, org.GetPublicId(), 1)[0]
	ac := password.TestAccounts(t, conn, org.GetPublicId(), am.GetPublicId(), 1)[0]

	s, err := accounts.NewService(repoFn)
	require.NoError(t, err, "Error when getting new user service")
	req := &pbs.DeleteAccountRequest{
		AuthMethodId: am.GetPublicId(),
		Id:           ac.GetPublicId(),
	}
	got, gErr := s.DeleteAccount(auth.DisabledAuthTestContext(auth.WithScopeId(ac.GetScopeId())), req)
	assert.NoError(gErr, "First attempt")
	assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	got, gErr = s.DeleteAccount(auth.DisabledAuthTestContext(auth.WithScopeId(ac.GetScopeId())), req)
	assert.NoError(gErr, "Second attempt")
	assert.False(got.GetExisted(), "Expected existed to be false for the second delete.")
}

func TestCreate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, wrap)
	}

	s, err := accounts.NewService(repoFn)
	require.NoError(t, err, "Error when getting new account service.")

	org, _ := iam.TestScopes(t, conn)
	am := password.TestAuthMethods(t, conn, org.GetPublicId(), 1)[0]
	defaultAccount := password.TestAccounts(t, conn, org.GetPublicId(), am.GetPublicId(), 1)[0]
	defaultCreated, err := ptypes.Timestamp(defaultAccount.GetCreateTime().GetTimestamp())
	require.NoError(t, err, "Error converting proto to timestamp.")

	defaultSt, err := handlers.ProtoToStruct(&pb.PasswordAccountAttributes{Username: "test"})
	require.NoError(t, err, "Error converting proto to struct.")

	cases := []struct {
		name    string
		req     *pbs.CreateAccountRequest
		res     *pbs.CreateAccountResponse
		errCode codes.Code
	}{
		{
			name: "Create a valid Account",
			req: &pbs.CreateAccountRequest{
				AuthMethodId: defaultAccount.GetAuthMethodId(),
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        "password",
					Attributes:  defaultSt,
				},
			},
			res: &pbs.CreateAccountResponse{
				Uri: fmt.Sprintf("scopes/%s/auth-methods/%s/accounts/%s_", defaultAccount.GetScopeId(), defaultAccount.GetAuthMethodId(), password.AccountPrefix),
				Item: &pb.Account{
					AuthMethodId: defaultAccount.GetAuthMethodId(),
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					Scope:        &scopes.ScopeInfo{Id: defaultAccount.GetScopeId(), Type: scope.Org.String()},
					Type:         "password",
					Attributes:   defaultSt,
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateAccountRequest{
				AuthMethodId: defaultAccount.GetAuthMethodId(),
				Item: &pb.Account{
					Id:         password.AccountPrefix + "_notallowed",
					Type:       "password",
					Attributes: defaultSt,
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify AuthMethodId",
			req: &pbs.CreateAccountRequest{
				AuthMethodId: defaultAccount.GetAuthMethodId(),
				Item: &pb.Account{
					AuthMethodId: defaultAccount.GetAuthMethodId(),
					Type:         "password",
					Attributes:   defaultSt,
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateAccountRequest{
				AuthMethodId: defaultAccount.GetAuthMethodId(),
				Item: &pb.Account{
					CreatedTime: ptypes.TimestampNow(),
					Type:        "password",
					Attributes:  defaultSt,
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateAccountRequest{
				AuthMethodId: defaultAccount.GetAuthMethodId(),
				Item: &pb.Account{
					UpdatedTime: ptypes.TimestampNow(),
					Type:        "password",
					Attributes:  defaultSt,
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Must specify type",
			req: &pbs.CreateAccountRequest{
				AuthMethodId: defaultAccount.GetAuthMethodId(),
				Item: &pb.Account{
					Attributes: defaultSt,
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Must specify username for password type",
			req: &pbs.CreateAccountRequest{
				AuthMethodId: defaultAccount.GetAuthMethodId(),
				Item: &pb.Account{
					Type: "password",
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.CreateAccount(auth.DisabledAuthTestContext(auth.WithScopeId(defaultAccount.GetScopeId())), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "CreateAccount(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				assert.True(strings.HasPrefix(got.GetItem().GetId(), password.AccountPrefix+"_"))
				gotCreateTime, err := ptypes.Timestamp(got.GetItem().GetCreatedTime())
				require.NoError(err, "Error converting proto to timestamp.")
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp.")
				// Verify it is a user created after the test setup's default user
				assert.True(gotCreateTime.After(defaultCreated), "New account should have been created after default user. Was created %v, which is after %v", gotCreateTime, defaultCreated)
				assert.True(gotUpdateTime.After(defaultCreated), "New account should have been updated after default user. Was updated %v, which is after %v", gotUpdateTime, defaultCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateAccount(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}
