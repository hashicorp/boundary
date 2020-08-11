package accounts_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authmethods"
	scopepb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/accounts"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/protobuf/field_mask"
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
	aa := password.TestAccounts(t, conn, am.GetPublicId(), 1)[0]

	wireAccount := pb.Account{
		Id:           aa.GetPublicId(),
		AuthMethodId: aa.GetAuthMethodId(),
		CreatedTime:  aa.GetCreateTime().GetTimestamp(),
		UpdatedTime:  aa.GetUpdateTime().GetTimestamp(),
		Scope:        &scopepb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String()},
		Version:      1,
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
	for _, aa := range password.TestAccounts(t, conn, amSomeAccounts.GetPublicId(), 3) {
		wantSomeAccounts = append(wantSomeAccounts, &pb.Account{
			Id:           aa.GetPublicId(),
			AuthMethodId: aa.GetAuthMethodId(),
			CreatedTime:  aa.GetCreateTime().GetTimestamp(),
			UpdatedTime:  aa.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String()},
			Version:      1,
			Type:         "password",
			Attributes:   &structpb.Struct{Fields: map[string]*structpb.Value{"username": structpb.NewStringValue(aa.GetUserName())}},
		})
	}

	var wantOtherAccounts []*pb.Account
	for _, aa := range password.TestAccounts(t, conn, amOtherAccounts.GetPublicId(), 3) {
		wantOtherAccounts = append(wantOtherAccounts, &pb.Account{
			Id:           aa.GetPublicId(),
			AuthMethodId: aa.GetAuthMethodId(),
			CreatedTime:  aa.GetCreateTime().GetTimestamp(),
			UpdatedTime:  aa.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String()},
			Version:      1,
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

	ac := password.TestAccounts(t, conn, am1.GetPublicId(), 1)[0]
	wrongAc := password.TestAccounts(t, conn, wrongAm.GetPublicId(), 1)[0]

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

	o, _ := iam.TestScopes(t, conn)
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	ac := password.TestAccounts(t, conn, am.GetPublicId(), 1)[0]

	s, err := accounts.NewService(repoFn)
	require.NoError(t, err, "Error when getting new user service")
	req := &pbs.DeleteAccountRequest{
		AuthMethodId: am.GetPublicId(),
		Id:           ac.GetPublicId(),
	}
	got, gErr := s.DeleteAccount(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), req)
	assert.NoError(gErr, "First attempt")
	assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	got, gErr = s.DeleteAccount(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), req)
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

	o, _ := iam.TestScopes(t, conn)
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	defaultAccount := password.TestAccounts(t, conn, am.GetPublicId(), 1)[0]
	defaultCreated, err := ptypes.Timestamp(defaultAccount.GetCreateTime().GetTimestamp())
	require.NoError(t, err, "Error converting proto to timestamp.")

	defaultSt, err := handlers.ProtoToStruct(&pb.PasswordAccountAttributes{Username: "thetestusername"})
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
				Uri: fmt.Sprintf("scopes/%s/auth-methods/%s/accounts/%s_", o.GetPublicId(), defaultAccount.GetAuthMethodId(), password.AccountPrefix),
				Item: &pb.Account{
					AuthMethodId: defaultAccount.GetAuthMethodId(),
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String()},
					Version:      1,
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
			got, gErr := s.CreateAccount(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), tc.req)
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

func TestUpdate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, wrap)
	}

	o, _ := iam.TestScopes(t, conn)
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	tested, err := accounts.NewService(repoFn)
	require.NoError(t, err, "Error when getting new auth_method service.")

	defaultScopeInfo := &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType()}
	defaultAttributes := &structpb.Struct{Fields: map[string]*structpb.Value{
		"username": structpb.NewStringValue("default"),
	}}

	freshAccount := func() (*pb.Account, func()) {
		acc, err := tested.CreateAccount(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())),
			&pbs.CreateAccountRequest{
				AuthMethodId: am.GetPublicId(),
				Item: &pb.Account{
					Name:        wrapperspb.String("default"),
					Description: wrapperspb.String("default"),
					Type:        "password",
					Attributes:  defaultAttributes,
				}},
		)
		require.NoError(t, err)

		clean := func() {
			_, err := tested.DeleteAccount(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())),
				&pbs.DeleteAccountRequest{AuthMethodId: am.GetPublicId(), Id: acc.GetItem().GetId()})
			require.NoError(t, err)
		}

		return acc.GetItem(), clean
	}

	cases := []struct {
		name    string
		req     *pbs.UpdateAccountRequest
		res     *pbs.UpdateAccountResponse
		errCode codes.Code
	}{
		{
			name: "Update an Existing AuthMethod",
			req: &pbs.UpdateAccountRequest{
				AuthMethodId: am.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "new"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					Type:         "password",
					Attributes:   defaultAttributes,
					Scope:        defaultScopeInfo,
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateAccountRequest{
				AuthMethodId: am.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "new"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					Type:         "password",
					Attributes:   defaultAttributes,
					Scope:        defaultScopeInfo,
				},
			},
			errCode: codes.OK,
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateAccountRequest{
				AuthMethodId: am.GetPublicId(),
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "No Paths in Mask",
			req: &pbs.UpdateAccountRequest{
				AuthMethodId: am.GetPublicId(),
				UpdateMask:   &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Only non-existant paths in Mask",
			req: &pbs.UpdateAccountRequest{
				AuthMethodId: am.GetPublicId(),
				UpdateMask:   &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateAccountRequest{
				AuthMethodId: am.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Account{
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Description:  &wrapperspb.StringValue{Value: "default"},
					Type:         "password",
					Attributes:   defaultAttributes,
					Scope:        defaultScopeInfo,
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateAccountRequest{
				AuthMethodId: am.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "updated"},
					Description:  &wrapperspb.StringValue{Value: "default"},
					Type:         "password",
					Attributes:   defaultAttributes,
					Scope:        defaultScopeInfo,
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateAccountRequest{
				AuthMethodId: am.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "default"},
					Description:  &wrapperspb.StringValue{Value: "notignored"},
					Type:         "password",
					Attributes:   defaultAttributes,
					Scope:        defaultScopeInfo,
				},
			},
			errCode: codes.OK,
		},
		// TODO: Updating a non existant auth_method should result in a NotFound exception but currently results in
		// the repoFn returning an internal error.
		{
			name: "Update a Non Existing Account",
			req: &pbs.UpdateAccountRequest{
				AuthMethodId: am.GetPublicId(),
				Id:           password.AccountPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			errCode: codes.Internal,
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateAccountRequest{
				AuthMethodId: am.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.Account{
					Id:          password.AccountPrefix + "_somethinge",
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "new desc"},
				}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateAccountRequest{
				AuthMethodId: am.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.Account{
					CreatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateAccountRequest{
				AuthMethodId: am.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.Account{
					UpdatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Type",
			req: &pbs.UpdateAccountRequest{
				AuthMethodId: am.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"type"},
				},
				Item: &pb.Account{
					Type: "oidc",
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			acc, cleanup := freshAccount()
			defer cleanup()

			tc.req.Version = 1

			if tc.req.GetId() == "" {
				tc.req.Id = acc.GetId()
			}

			if tc.res != nil && tc.res.Item != nil {
				tc.res.Item.Id = acc.GetId()
				tc.res.Item.CreatedTime = acc.GetCreatedTime()
			}

			got, gErr := tested.UpdateAccount(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "UpdateAccount(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)

			if tc.res == nil {
				require.Nil(got)
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateAccount response to be nil, but was %v", got)
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp")

				created, err := ptypes.Timestamp(acc.GetCreatedTime())
				require.NoError(err, "Error converting proto to timestamp")

				// Verify it is a auth_method updated after it was created
				assert.True(gotUpdateTime.After(created), "Updated account should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil

				assert.EqualValues(2, got.Item.Version)
				tc.res.Item.Version = 2
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "UpdateAccount(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}
