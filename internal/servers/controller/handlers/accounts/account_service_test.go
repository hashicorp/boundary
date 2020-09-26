package accounts_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/accounts"
	scopepb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/accounts"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestGet(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kms)
	}

	s, err := accounts.NewService(repoFn)
	require.NoError(t, err, "Couldn't create new auth token service.")

	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
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
		Attributes:   &structpb.Struct{Fields: map[string]*structpb.Value{"login_name": structpb.NewStringValue(aa.GetLoginName())}},
	}

	cases := []struct {
		name string
		req  *pbs.GetAccountRequest
		res  *pbs.GetAccountResponse
		err  error
	}{
		{
			name: "Get an existing account",
			req:  &pbs.GetAccountRequest{Id: wireAccount.GetId()},
			res:  &pbs.GetAccountResponse{Item: &wireAccount},
		},
		{
			name: "Get a non existing account",
			req:  &pbs.GetAccountRequest{Id: password.AccountPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Wrong id prefix",
			req:  &pbs.GetAccountRequest{Id: "j_1234567890"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "space in id",
			req:  &pbs.GetAccountRequest{Id: authtoken.AuthTokenPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.GetAccount(auth.DisabledAuthTestContext(auth.WithScopeId(org.GetPublicId())), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetAccount(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetAccount(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kms)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
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
			Attributes:   &structpb.Struct{Fields: map[string]*structpb.Value{"login_name": structpb.NewStringValue(aa.GetLoginName())}},
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
			Attributes:   &structpb.Struct{Fields: map[string]*structpb.Value{"login_name": structpb.NewStringValue(aa.GetLoginName())}},
		})
	}

	cases := []struct {
		name       string
		authMethod string
		res        *pbs.ListAccountsResponse
		err        error
	}{
		{
			name:       "List Some Accounts",
			authMethod: amSomeAccounts.GetPublicId(),
			res:        &pbs.ListAccountsResponse{Items: wantSomeAccounts},
		},
		{
			name:       "List Other Accounts",
			authMethod: amOtherAccounts.GetPublicId(),
			res:        &pbs.ListAccountsResponse{Items: wantOtherAccounts},
		},
		{
			name:       "List No Accounts",
			authMethod: amNoAccounts.GetPublicId(),
			res:        &pbs.ListAccountsResponse{},
		},
		{
			name:       "Unfound Auth Method",
			authMethod: password.AuthMethodPrefix + "_DoesntExis",
			err:        handlers.ApiErrorWithCode(codes.NotFound),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := accounts.NewService(repoFn)
			require.NoError(err, "Couldn't create new user service.")

			got, gErr := s.ListAccounts(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), &pbs.ListAccountsRequest{AuthMethodId: tc.authMethod})
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListAccounts() with auth method %q got error %v, wanted %v", tc.authMethod, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform(), protocmp.SortRepeatedFields(got)), "ListUsers() with scope %q got response %q, wanted %q", tc.authMethod, got, tc.res)
		})
	}
}

func TestDelete(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kms)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	am1 := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	ac := password.TestAccounts(t, conn, am1.GetPublicId(), 1)[0]

	s, err := accounts.NewService(repoFn)
	require.NoError(t, err, "Error when getting new user service.")

	cases := []struct {
		name  string
		scope string
		req   *pbs.DeleteAccountRequest
		res   *pbs.DeleteAccountResponse
		err   error
	}{
		{
			name: "Delete an existing token",
			req: &pbs.DeleteAccountRequest{
				Id: ac.GetPublicId(),
			},
			res: &pbs.DeleteAccountResponse{},
		},
		{
			name: "Delete bad account id",
			req: &pbs.DeleteAccountRequest{
				Id: password.AccountPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Bad account id formatting",
			req: &pbs.DeleteAccountRequest{
				Id: "bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteAccount(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteAccount(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.EqualValuesf(tc.res, got, "DeleteAccount(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrap)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kms)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	ac := password.TestAccounts(t, conn, am.GetPublicId(), 1)[0]

	s, err := accounts.NewService(repoFn)
	require.NoError(err, "Error when getting new user service")
	req := &pbs.DeleteAccountRequest{
		Id: ac.GetPublicId(),
	}
	_, gErr := s.DeleteAccount(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteAccount(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")
}

func TestCreate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kms)
	}

	s, err := accounts.NewService(repoFn)
	require.NoError(t, err, "Error when getting new account service.")

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	defaultAccount := password.TestAccounts(t, conn, am.GetPublicId(), 1)[0]
	defaultCreated, err := ptypes.Timestamp(defaultAccount.GetCreateTime().GetTimestamp())
	require.NoError(t, err, "Error converting proto to timestamp.")

	createAttr := func(un, pw string) *structpb.Struct {
		attr := &pb.PasswordAccountAttributes{LoginName: un}
		if pw != "" {
			attr.Password = wrapperspb.String(pw)
		}
		ret, err := handlers.ProtoToStruct(attr)
		require.NoError(t, err, "Error converting proto to struct.")
		return ret
	}

	cases := []struct {
		name string
		req  *pbs.CreateAccountRequest
		res  *pbs.CreateAccountResponse
		err  error
	}{
		{
			name: "Create a valid Account",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: defaultAccount.GetAuthMethodId(),
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					Type:         "password",
					Attributes:   createAttr("validaccount", ""),
				},
			},
			res: &pbs.CreateAccountResponse{
				Uri: fmt.Sprintf("accounts/%s_", password.AccountPrefix),
				Item: &pb.Account{
					AuthMethodId: defaultAccount.GetAuthMethodId(),
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String()},
					Version:      1,
					Type:         "password",
					Attributes:   createAttr("validaccount", ""),
				},
			},
		},
		{
			name: "Create a valid Account without type defined",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: defaultAccount.GetAuthMethodId(),
					Attributes:   createAttr("notypedefined", ""),
				},
			},
			res: &pbs.CreateAccountResponse{
				Uri: fmt.Sprintf("accounts/%s_", password.AccountPrefix),
				Item: &pb.Account{
					AuthMethodId: defaultAccount.GetAuthMethodId(),
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String()},
					Version:      1,
					Type:         "password",
					Attributes:   createAttr("notypedefined", ""),
				},
			},
		},
		{
			name: "Create a valid Account with password defined",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: defaultAccount.GetAuthMethodId(),
					Name:         &wrapperspb.StringValue{Value: "name_with_password"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					Attributes:   createAttr("haspassword", "somepassword"),
				},
			},
			res: &pbs.CreateAccountResponse{
				Uri: fmt.Sprintf("accounts/%s_", password.AccountPrefix),
				Item: &pb.Account{
					AuthMethodId: defaultAccount.GetAuthMethodId(),
					Name:         &wrapperspb.StringValue{Value: "name_with_password"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String()},
					Version:      1,
					Type:         "password",
					Attributes:   createAttr("haspassword", ""),
				},
			},
		},
		{
			name: "Cant specify mismatching type",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: defaultAccount.GetAuthMethodId(),
					Type:         "wrong",
					Attributes:   createAttr("nopwprovided", ""),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: defaultAccount.GetAuthMethodId(),
					Id:           password.AccountPrefix + "_notallowed",
					Type:         "password",
					Attributes:   createAttr("cantprovideid", ""),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: defaultAccount.GetAuthMethodId(),
					CreatedTime:  ptypes.TimestampNow(),
					Type:         "password",
					Attributes:   createAttr("nocreatedtime", ""),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: defaultAccount.GetAuthMethodId(),
					UpdatedTime:  ptypes.TimestampNow(),
					Type:         "password",
					Attributes:   createAttr("noupdatetime", ""),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must specify login name for password type",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: defaultAccount.GetAuthMethodId(),
					Type:         "password",
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.CreateAccount(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateAccount(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
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
	kms := kms.TestKms(t, conn, wrap)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kms)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	tested, err := accounts.NewService(repoFn)
	require.NoError(t, err, "Error when getting new auth_method service.")

	defaultScopeInfo := &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType()}
	defaultAttributes := &structpb.Struct{Fields: map[string]*structpb.Value{
		"login_name": structpb.NewStringValue("default"),
	}}
	modifiedAttributes := &structpb.Struct{Fields: map[string]*structpb.Value{
		"login_name": structpb.NewStringValue("modified"),
	}}

	freshAccount := func(t *testing.T) (*pb.Account, func()) {
		t.Helper()
		acc, err := tested.CreateAccount(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())),
			&pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Name:         wrapperspb.String("default"),
					Description:  wrapperspb.String("default"),
					Type:         "password",
					Attributes:   defaultAttributes,
				}},
		)
		require.NoError(t, err)

		clean := func() {
			_, err := tested.DeleteAccount(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())),
				&pbs.DeleteAccountRequest{Id: acc.GetItem().GetId()})
			require.NoError(t, err)
		}

		return acc.GetItem(), clean
	}

	cases := []struct {
		name string
		req  *pbs.UpdateAccountRequest
		res  *pbs.UpdateAccountResponse
		err  error
	}{
		{
			name: "Update an Existing AuthMethod",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        "password",
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
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        "password",
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
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateAccountRequest{
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
					Attributes:  modifiedAttributes,
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant change type",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Account{
					Name: &wrapperspb.StringValue{Value: ""},
					Type: "oidc",
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "No Paths in Mask",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
					Attributes:  modifiedAttributes,
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Only non-existant paths in Mask",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
					Attributes:  modifiedAttributes,
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Account{
					Description: &wrapperspb.StringValue{Value: "ignored"},
					Attributes:  modifiedAttributes,
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
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
					Attributes:  modifiedAttributes,
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
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
					Attributes:  modifiedAttributes,
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
		},
		{
			name: "Update Only LoginName",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.login_name"},
				},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
					Attributes:  modifiedAttributes,
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "default"},
					Description:  &wrapperspb.StringValue{Value: "default"},
					Type:         "password",
					Attributes:   modifiedAttributes,
					Scope:        defaultScopeInfo,
				},
			},
		},
		{
			name: "Update a Non Existing Account",
			req: &pbs.UpdateAccountRequest{
				Id: password.AccountPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.Account{
					Id:          password.AccountPrefix + "_somethinge",
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "new desc"},
				}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.Account{
					CreatedTime: ptypes.TimestampNow(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.Account{
					UpdatedTime: ptypes.TimestampNow(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Type",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"type"},
				},
				Item: &pb.Account{
					Type: "oidc",
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			acc, cleanup := freshAccount(t)
			defer cleanup()

			tc.req.Item.Version = 1

			if tc.req.GetId() == "" {
				tc.req.Id = acc.GetId()
			}

			if tc.res != nil && tc.res.Item != nil {
				tc.res.Item.Id = acc.GetId()
				tc.res.Item.CreatedTime = acc.GetCreatedTime()
			}

			got, gErr := tested.UpdateAccount(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateAccount(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}

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

func TestSetPassword(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kms)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	tested, err := accounts.NewService(repoFn)
	require.NoError(t, err, "Error when getting new auth_method service.")

	createAccount := func(t *testing.T, pw string) *pb.Account {
		am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
		pwAttrs := &pb.PasswordAccountAttributes{
			LoginName: "testusername",
		}
		if pw != "" {
			pwAttrs.Password = wrapperspb.String(pw)
		}
		attrs, err := handlers.ProtoToStruct(pwAttrs)
		createResp, err := tested.CreateAccount(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), &pbs.CreateAccountRequest{
			Item: &pb.Account{
				AuthMethodId: am.GetPublicId(),
				Type:         "password",
				Attributes:   attrs,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, createResp)
		require.NotNil(t, createResp.GetItem())
		return createResp.GetItem()
	}

	cases := []struct {
		name  string
		oldPw string
		newPw string
	}{
		{
			name:  "has old set new",
			oldPw: "originalpassword",
			newPw: "a different password",
		},
		{
			name:  "has old unset new",
			oldPw: "originalpassword",
			newPw: "",
		},
		{
			name:  "no old password set new",
			oldPw: "",
			newPw: "a different password",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			acct := createAccount(t, tt.oldPw)

			setResp, err := tested.SetPassword(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), &pbs.SetPasswordRequest{
				Id:       acct.GetId(),
				Version:  acct.GetVersion(),
				Password: tt.newPw,
			})
			require.NoError(err)
			assert.Equal(acct.GetVersion()+1, setResp.GetItem().GetVersion())
			// clear uncomparable fields
			acct.Version, setResp.GetItem().Version = 0, 0
			acct.UpdatedTime, setResp.GetItem().UpdatedTime = nil, nil

			assert.Empty(cmp.Diff(acct, setResp.GetItem(), protocmp.Transform()))
		})
	}

	defaultAcct := createAccount(t, "")
	badRequestCases := []struct {
		name      string
		accountId string
		version   uint32
		password  string
	}{
		{
			name:      "empty account id",
			accountId: "",
			version:   defaultAcct.GetVersion(),
			password:  "somepassword",
		},
		{
			name:      "unset version",
			accountId: defaultAcct.GetId(),
			version:   0,
			password:  "somepassword",
		},
	}

	for _, tt := range badRequestCases {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			setResp, err := tested.SetPassword(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), &pbs.SetPasswordRequest{
				Id:       tt.accountId,
				Version:  tt.version,
				Password: tt.password,
			})
			assert.Error(err)
			assert.Nil(setResp)
		})
	}
}

func TestChangePassword(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kms)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	tested, err := accounts.NewService(repoFn)
	require.NoError(t, err, "Error when getting new auth_method service.")

	createAccount := func(t *testing.T, pw string) *pb.Account {
		am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
		pwAttrs := &pb.PasswordAccountAttributes{
			LoginName: "testusername",
		}
		if pw != "" {
			pwAttrs.Password = wrapperspb.String(pw)
		}
		attrs, err := handlers.ProtoToStruct(pwAttrs)
		createResp, err := tested.CreateAccount(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), &pbs.CreateAccountRequest{
			Item: &pb.Account{
				AuthMethodId: am.GetPublicId(),
				Type:         "password",
				Attributes:   attrs,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, createResp)
		require.NotNil(t, createResp.GetItem())
		return createResp.GetItem()
	}

	t.Run("valid update", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		acct := createAccount(t, "originalpassword")

		changeResp, err := tested.ChangePassword(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), &pbs.ChangePasswordRequest{
			Id:              acct.GetId(),
			Version:         acct.GetVersion(),
			CurrentPassword: "originalpassword",
			NewPassword:     "a different password",
		})
		require.NoError(err)
		assert.Equal(acct.GetVersion()+1, changeResp.GetItem().GetVersion())
		// clear uncomparable fields
		acct.Version, changeResp.GetItem().Version = 0, 0
		acct.UpdatedTime, changeResp.GetItem().UpdatedTime = nil, nil

		assert.Empty(cmp.Diff(acct, changeResp.GetItem(), protocmp.Transform()))
	})

	t.Run("unauthenticated update", func(t *testing.T) {
		assert := assert.New(t)
		acct := createAccount(t, "originalpassword")

		changeResp, err := tested.ChangePassword(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), &pbs.ChangePasswordRequest{
			Id:              acct.GetId(),
			Version:         acct.GetVersion(),
			CurrentPassword: "thewrongpassword",
			NewPassword:     "a different password",
		})
		assert.Error(err)
		assert.Nil(changeResp)
	})

	defaultAcct := createAccount(t, "")
	badRequestCases := []struct {
		name         string
		authMethodId string
		accountId    string
		version      uint32
		oldPW        string
		newPW        string
	}{
		{
			name:         "empty auth method",
			authMethodId: "",
			accountId:    defaultAcct.GetId(),
			version:      defaultAcct.GetVersion(),
			oldPW:        "somepassword",
			newPW:        "anewpassword",
		},
		{
			name:         "empty account id",
			authMethodId: defaultAcct.GetAuthMethodId(),
			accountId:    "",
			version:      defaultAcct.GetVersion(),
			oldPW:        "somepassword",
			newPW:        "anewpassword",
		},
		{
			name:         "unset version",
			authMethodId: defaultAcct.GetAuthMethodId(),
			accountId:    defaultAcct.GetId(),
			version:      0,
			oldPW:        "somepassword",
			newPW:        "anewpassword",
		},
		{
			name:         "no old password",
			authMethodId: defaultAcct.GetAuthMethodId(),
			accountId:    defaultAcct.GetId(),
			version:      defaultAcct.GetVersion(),
			oldPW:        "",
			newPW:        "anewpassword",
		},
		{
			name:         "no new password",
			authMethodId: defaultAcct.GetAuthMethodId(),
			accountId:    defaultAcct.GetId(),
			version:      defaultAcct.GetVersion(),
			oldPW:        "somepassword",
			newPW:        "",
		},
		{
			name:         "matching old and new passwords",
			authMethodId: defaultAcct.GetAuthMethodId(),
			accountId:    defaultAcct.GetId(),
			version:      defaultAcct.GetVersion(),
			oldPW:        "somepassword",
			newPW:        "somepassword",
		},
	}

	for _, tt := range badRequestCases {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			changeResp, err := tested.ChangePassword(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), &pbs.ChangePasswordRequest{
				Id:              tt.accountId,
				Version:         tt.version,
				CurrentPassword: tt.oldPW,
				NewPassword:     tt.newPW,
			})
			assert.Error(err)
			assert.Nil(changeResp)
		})
	}
}
