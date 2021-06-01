package managed_groups_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/managedgroups"
	scopepb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/managed_groups"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var oidcAuthorizedActions = []string{
	action.NoOp.String(),
	action.Read.String(),
	action.Update.String(),
	action.Delete.String(),
}

const testFakeManagedGroupFilter = `"/foo" == "bar"`

func TestNewService(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kmsCache)
	}

	cases := []struct {
		name     string
		oidcRepo common.OidcAuthRepoFactory
		wantErr  bool
	}{
		{
			name:    "nil-oidc-repo",
			wantErr: true,
		},
		{
			name:     "success",
			oidcRepo: oidcRepoFn,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := managed_groups.NewService(tc.oidcRepo)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGet(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kmsCache)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, kmsCache)
	}

	s, err := managed_groups.NewService(oidcRepoFn)
	require.NoError(t, err, "Couldn't create new managed groups service.")

	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	oidcAm := oidc.TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	omg := oidc.TestManagedGroup(t, conn, oidcAm, testFakeManagedGroupFilter)

	oidcWireManagedGroup := pb.ManagedGroup{
		Id:                omg.GetPublicId(),
		AuthMethodId:      omg.GetAuthMethodId(),
		CreatedTime:       omg.GetCreateTime().GetTimestamp(),
		UpdatedTime:       omg.GetUpdateTime().GetTimestamp(),
		Scope:             &scopepb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
		Version:           1,
		Type:              "password",
		Attributes:        &structpb.Struct{Fields: map[string]*structpb.Value{"filter": structpb.NewStringValue(omg.GetFilter())}},
		AuthorizedActions: oidcAuthorizedActions,
	}

	cases := []struct {
		name string
		req  *pbs.GetManagedGroupRequest
		res  *pbs.GetManagedGroupResponse
		err  error
	}{
		{
			name: "Get an oidc account",
			req:  &pbs.GetManagedGroupRequest{Id: oidcWireManagedGroup.GetId()},
			res:  &pbs.GetManagedGroupResponse{Item: &oidcWireManagedGroup},
		},
		{
			name: "Get a non existing oidc managed group",
			req:  &pbs.GetManagedGroupRequest{Id: oidc.ManagedGroupPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Wrong id prefix",
			req:  &pbs.GetManagedGroupRequest{Id: "j_1234567890"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "space in id",
			req:  &pbs.GetManagedGroupRequest{Id: authtoken.AuthTokenPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.GetManagedGroup(auth.DisabledAuthTestContext(iamRepoFn, org.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetManagedGroup(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetManagedGroup(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestListOidc(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kmsCache)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, kmsCache)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	amNoManagedGroups := oidc.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState, "noManagedGroups", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.nomanagedgroups.com")[0]), oidc.WithSigningAlgs(oidc.RS256), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]))
	amSomeManagedGroups := oidc.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState, "someManagedGroups", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.somemanagedgroups.com")[0]), oidc.WithSigningAlgs(oidc.RS256), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]))
	amOtherManagedGroups := oidc.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState, "otherManagedGroups", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.othermanagedgroups.com")[0]), oidc.WithSigningAlgs(oidc.RS256), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]))

	var wantSomeManagedGroups []*pb.ManagedGroup
	for i := 0; i < 3; i++ {
		mg := oidc.TestManagedGroup(t, conn, amSomeManagedGroups, testFakeManagedGroupFilter, oidc.WithName(strconv.Itoa(i)))
		wantSomeManagedGroups = append(wantSomeManagedGroups, &pb.ManagedGroup{
			Id:           mg.GetPublicId(),
			AuthMethodId: mg.GetAuthMethodId(),
			Name:         wrapperspb.String(strconv.Itoa(i)),
			CreatedTime:  mg.GetCreateTime().GetTimestamp(),
			UpdatedTime:  mg.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         auth.OidcSubtype.String(),
			Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
				"filter": structpb.NewStringValue(testFakeManagedGroupFilter),
			}},
			AuthorizedActions: oidcAuthorizedActions,
		})
	}

	var wantOtherManagedGroups []*pb.ManagedGroup
	for i := 0; i < 3; i++ {
		mg := oidc.TestManagedGroup(t, conn, amOtherManagedGroups, testFakeManagedGroupFilter, oidc.WithName(strconv.Itoa(i)))
		wantOtherManagedGroups = append(wantOtherManagedGroups, &pb.ManagedGroup{
			Id:           mg.GetPublicId(),
			AuthMethodId: mg.GetAuthMethodId(),
			Name:         wrapperspb.String(strconv.Itoa(i)),
			CreatedTime:  mg.GetCreateTime().GetTimestamp(),
			UpdatedTime:  mg.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         auth.OidcSubtype.String(),
			Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
				"filter": structpb.NewStringValue(testFakeManagedGroupFilter),
			}},
			AuthorizedActions: oidcAuthorizedActions,
		})
	}

	cases := []struct {
		name     string
		req      *pbs.ListManagedGroupsRequest
		res      *pbs.ListManagedGroupsResponse
		err      error
		skipAnon bool
	}{
		{
			name: "List Some ManagedGroups",
			req:  &pbs.ListManagedGroupsRequest{AuthMethodId: amSomeManagedGroups.GetPublicId()},
			res:  &pbs.ListManagedGroupsResponse{Items: wantSomeManagedGroups},
		},
		{
			name: "List Other ManagedGroups",
			req:  &pbs.ListManagedGroupsRequest{AuthMethodId: amOtherManagedGroups.GetPublicId()},
			res:  &pbs.ListManagedGroupsResponse{Items: wantOtherManagedGroups},
		},
		{
			name: "List No ManagedGroups",
			req:  &pbs.ListManagedGroupsRequest{AuthMethodId: amNoManagedGroups.GetPublicId()},
			res:  &pbs.ListManagedGroupsResponse{},
		},
		{
			name: "Unfound Auth Method",
			req:  &pbs.ListManagedGroupsRequest{AuthMethodId: oidc.AuthMethodPrefix + "_DoesntExis"},
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Filter Some ManagedGroups",
			req: &pbs.ListManagedGroupsRequest{
				AuthMethodId: amSomeManagedGroups.GetPublicId(),
				Filter:       fmt.Sprintf(`"/item/name"==%q`, wantSomeManagedGroups[1].Name.GetValue()),
			},
			res:      &pbs.ListManagedGroupsResponse{Items: wantSomeManagedGroups[1:2]},
			skipAnon: true,
		},
		{
			name: "Filter All ManagedGroups",
			req: &pbs.ListManagedGroupsRequest{
				AuthMethodId: amSomeManagedGroups.GetPublicId(),
				Filter:       `"/item/id"=="noManagedGroupmatchesthis"`,
			},
			res: &pbs.ListManagedGroupsResponse{},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListManagedGroupsRequest{AuthMethodId: amSomeManagedGroups.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := managed_groups.NewService(oidcRepoFn)
			require.NoError(err, "Couldn't create new managed group service.")

			got, gErr := s.ListManagedGroups(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListManagedGroups() with auth method %q got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			} else {
				require.NoError(gErr)
			}
			sort.Slice(got.Items, func(i, j int) bool {
				return strings.Compare(got.Items[i].GetName().GetValue(),
					got.Items[j].GetName().GetValue()) < 0
			})
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListManagedGroups() with scope %q got response %q, wanted %q", tc.req, got, tc.res)

			// Now test with anon
			if tc.skipAnon {
				return
			}
			got, gErr = s.ListManagedGroups(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId(), auth.WithUserId(auth.AnonymousUserId)), tc.req)
			require.NoError(gErr)
			assert.Len(got.Items, len(tc.res.Items))
			for _, g := range got.GetItems() {
				assert.Nil(g.Attributes)
				assert.Nil(g.CreatedTime)
				assert.Nil(g.UpdatedTime)
				assert.Empty(g.Version)
			}
		})
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kmsCache)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, kmsCache)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))

	databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	oidcAm := oidc.TestAuthMethod(
		t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	oidcMg := oidc.TestManagedGroup(t, conn, oidcAm, testFakeManagedGroupFilter)

	s, err := managed_groups.NewService(oidcRepoFn)
	require.NoError(t, err, "Error when getting new user service.")

	cases := []struct {
		name  string
		scope string
		req   *pbs.DeleteManagedGroupRequest
		res   *pbs.DeleteManagedGroupResponse
		err   error
	}{
		{
			name: "Delete an existing oidc managed group",
			req: &pbs.DeleteManagedGroupRequest{
				Id: oidcMg.GetPublicId(),
			},
		},
		{
			name: "Delete bad oidc managed group id",
			req: &pbs.DeleteManagedGroupRequest{
				Id: oidc.ManagedGroupPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Bad managed group id formatting",
			req: &pbs.DeleteManagedGroupRequest{
				Id: "bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteManagedGroup(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteManagedGroup(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.EqualValuesf(tc.res, got, "DeleteManagedGroup(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrap)

	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kmsCache)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, kmsCache)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), o.PublicId, kms.KeyPurposeDatabase)

	oidcAm := oidc.TestAuthMethod(
		t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	oidcMg := oidc.TestManagedGroup(t, conn, oidcAm, testFakeManagedGroupFilter)

	s, err := managed_groups.NewService(oidcRepoFn)
	require.NoError(err, "Error when getting new user service")
	req := &pbs.DeleteManagedGroupRequest{
		Id: oidcMg.GetPublicId(),
	}
	_, gErr := s.DeleteManagedGroup(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteManagedGroup(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")
}

/*
func TestCreatePassword(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kms)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, kms)
	}

	s, err := accounts.NewService(pwRepoFn, oidcRepoFn)
	require.NoError(t, err, "Error when getting new account service.")

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	defaultAccount := password.TestAccount(t, conn, am.GetPublicId(), "name1")
	defaultCreated := defaultAccount.GetCreateTime().GetTimestamp()
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
					AuthMethodId:      defaultAccount.GetAuthMethodId(),
					Name:              &wrapperspb.StringValue{Value: "name"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					Scope:             &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Version:           1,
					Type:              "password",
					Attributes:        createAttr("validaccount", ""),
					AuthorizedActions: pwAuthorizedActions,
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
					AuthMethodId:      defaultAccount.GetAuthMethodId(),
					Scope:             &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Version:           1,
					Type:              "password",
					Attributes:        createAttr("notypedefined", ""),
					AuthorizedActions: pwAuthorizedActions,
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
					AuthMethodId:      defaultAccount.GetAuthMethodId(),
					Name:              &wrapperspb.StringValue{Value: "name_with_password"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					Scope:             &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Version:           1,
					Type:              "password",
					Attributes:        createAttr("haspassword", ""),
					AuthorizedActions: pwAuthorizedActions,
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
					CreatedTime:  timestamppb.Now(),
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
					UpdatedTime:  timestamppb.Now(),
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
			got, gErr := s.CreateAccount(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateAccount(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				assert.True(strings.HasPrefix(got.GetItem().GetId(), password.AccountPrefix+"_"))
				gotCreateTime := got.GetItem().GetCreatedTime()
				require.NoError(err, "Error converting proto to timestamp.")
				gotUpdateTime := got.GetItem().GetUpdatedTime()
				require.NoError(err, "Error converting proto to timestamp.")
				// Verify it is a user created after the test setup's default user
				assert.True(gotCreateTime.AsTime().After(defaultCreated.AsTime()), "New account should have been created after default user. Was created %v, which is after %v", gotCreateTime, defaultCreated)
				assert.True(gotUpdateTime.AsTime().After(defaultCreated.AsTime()), "New account should have been updated after default user. Was updated %v, which is after %v", gotUpdateTime, defaultCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateAccount(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestCreateOidc(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kmsCache)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kmsCache)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, kmsCache)
	}

	s, err := accounts.NewService(pwRepoFn, oidcRepoFn)
	require.NoError(t, err, "Error when getting new account service.")

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	am := oidc.TestAuthMethod(
		t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	createAttr := func(sid string) *structpb.Struct {
		attr := &pb.OidcAccountAttributes{Subject: sid}
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
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					Type:         auth.OidcSubtype.String(),
					Attributes:   createAttr("valid-account"),
				},
			},
			res: &pbs.CreateAccountResponse{
				Uri: fmt.Sprintf("accounts/%s_", oidc.AccountPrefix),
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Version:      1,
					Type:         auth.OidcSubtype.String(),
					Attributes: func() *structpb.Struct {
						a := createAttr("valid-account")
						a.Fields["issuer"] = structpb.NewStringValue(am.GetIssuer())
						return a
					}(),
					AuthorizedActions: oidcAuthorizedActions,
				},
			},
		},
		{
			name: "Create a valid Account without type defined",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Attributes:   createAttr("no type defined"),
				},
			},
			res: &pbs.CreateAccountResponse{
				Uri: fmt.Sprintf("accounts/%s_", oidc.AccountPrefix),
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Version:      1,
					Type:         auth.OidcSubtype.String(),
					Attributes: func() *structpb.Struct {
						a := createAttr("no type defined")
						a.Fields["issuer"] = structpb.NewStringValue(am.GetIssuer())
						return a
					}(),
					AuthorizedActions: oidcAuthorizedActions,
				},
			},
		},
		{
			name: "Create Account With Overwritten Issuer",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "overwritten issuer"},
					Type:         auth.OidcSubtype.String(),
					Attributes: func() *structpb.Struct {
						a := createAttr("overwritten-issuer")
						a.Fields["issuer"] = structpb.NewStringValue("https://overwrite.com")
						return a
					}(),
				},
			},
			res: &pbs.CreateAccountResponse{
				Uri: fmt.Sprintf("accounts/%s_", oidc.AccountPrefix),
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "overwritten issuer"},
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Version:      1,
					Type:         auth.OidcSubtype.String(),
					Attributes: func() *structpb.Struct {
						a := createAttr("overwritten-issuer")
						a.Fields["issuer"] = structpb.NewStringValue("https://overwrite.com")
						return a
					}(),
					AuthorizedActions: oidcAuthorizedActions,
				},
			},
		},
		{
			name: "Cant specify mismatching type",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Type:         auth.PasswordSubtype.String(),
					Attributes:   createAttr("cant-specify-mismatching-type"),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Id:           oidc.AccountPrefix + "_notallowed",
					Type:         auth.OidcSubtype.String(),
					Attributes:   createAttr("cant-specify-id"),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					CreatedTime:  timestamppb.Now(),
					Type:         auth.OidcSubtype.String(),
					Attributes:   createAttr("cant-specify-created-time"),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					UpdatedTime:  timestamppb.Now(),
					Type:         auth.OidcSubtype.String(),
					Attributes:   createAttr("cant-specify-update-time"),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must specify subject",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Type:         auth.OidcSubtype.String(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.CreateAccount(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateAccount(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				assert.True(strings.HasPrefix(got.GetItem().GetId(), oidc.AccountPrefix+"_"))
				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateAccount(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestUpdatePassword(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kms)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, kms)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	tested, err := accounts.NewService(pwRepoFn, oidcRepoFn)
	require.NoError(t, err, "Error when getting new auth_method service.")

	defaultScopeInfo := &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType(), ParentScopeId: scope.Global.String()}
	defaultAttributes := &structpb.Struct{Fields: map[string]*structpb.Value{
		"login_name": structpb.NewStringValue("default"),
	}}
	modifiedAttributes := &structpb.Struct{Fields: map[string]*structpb.Value{
		"login_name": structpb.NewStringValue("modified"),
	}}

	freshAccount := func(t *testing.T) (*pb.Account, func()) {
		t.Helper()
		acc, err := tested.CreateAccount(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()),
			&pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Name:         wrapperspb.String("default"),
					Description:  wrapperspb.String("default"),
					Type:         "password",
					Attributes:   defaultAttributes,
				},
			},
		)
		require.NoError(t, err)

		clean := func() {
			_, err := tested.DeleteAccount(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()),
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
					Paths: []string{globals.NameField, globals.DescriptionField},
				},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        "password",
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "new"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					Type:              "password",
					Attributes:        defaultAttributes,
					Scope:             defaultScopeInfo,
					AuthorizedActions: pwAuthorizedActions,
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
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "new"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					Type:              "password",
					Attributes:        defaultAttributes,
					Scope:             defaultScopeInfo,
					AuthorizedActions: pwAuthorizedActions,
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
					Paths: []string{globals.NameField},
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
					Paths: []string{globals.NameField},
				},
				Item: &pb.Account{
					Description: &wrapperspb.StringValue{Value: "ignored"},
					Attributes:  modifiedAttributes,
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Description:       &wrapperspb.StringValue{Value: "default"},
					Type:              "password",
					Attributes:        defaultAttributes,
					Scope:             defaultScopeInfo,
					AuthorizedActions: pwAuthorizedActions,
				},
			},
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.NameField},
				},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
					Attributes:  modifiedAttributes,
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "updated"},
					Description:       &wrapperspb.StringValue{Value: "default"},
					Type:              "password",
					Attributes:        defaultAttributes,
					Scope:             defaultScopeInfo,
					AuthorizedActions: pwAuthorizedActions,
				},
			},
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.DescriptionField},
				},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
					Attributes:  modifiedAttributes,
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "default"},
					Description:       &wrapperspb.StringValue{Value: "notignored"},
					Type:              "password",
					Attributes:        defaultAttributes,
					Scope:             defaultScopeInfo,
					AuthorizedActions: pwAuthorizedActions,
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
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "default"},
					Description:       &wrapperspb.StringValue{Value: "default"},
					Type:              "password",
					Attributes:        modifiedAttributes,
					Scope:             defaultScopeInfo,
					AuthorizedActions: pwAuthorizedActions,
				},
			},
		},
		{
			name: "Update a Non Existing Account",
			req: &pbs.UpdateAccountRequest{
				Id: password.AccountPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.DescriptionField},
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
				},
			},
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
					CreatedTime: timestamppb.Now(),
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
					UpdatedTime: timestamppb.Now(),
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

			got, gErr := tested.UpdateAccount(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateAccount(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}

			if tc.res == nil {
				require.Nil(got)
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateAccount response to be nil, but was %v", got)
				gotUpdateTime := got.GetItem().GetUpdatedTime()
				require.NoError(err, "Error converting proto to timestamp")

				created := acc.GetCreatedTime()
				require.NoError(err, "Error converting proto to timestamp")

				// Verify it is a auth_method updated after it was created
				assert.True(gotUpdateTime.AsTime().After(created.AsTime()), "Updated account should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil

				assert.EqualValues(2, got.Item.Version)
				tc.res.Item.Version = 2
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "UpdateAccount(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestUpdateOidc(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kmsCache)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kmsCache)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, kmsCache)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))

	databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	am := oidc.TestAuthMethod(
		t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]))

	tested, err := accounts.NewService(pwRepoFn, oidcRepoFn)
	require.NoError(t, err, "Error when getting new auth_method service.")

	defaultScopeInfo := &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType(), ParentScopeId: scope.Global.String()}
	defaultAttributes := &structpb.Struct{Fields: map[string]*structpb.Value{
		"issuer":  structpb.NewStringValue("https://www.alice.com"),
		"subject": structpb.NewStringValue("test-subject"),
	}}
	modifiedAttributes := &structpb.Struct{Fields: map[string]*structpb.Value{
		"issuer":  structpb.NewStringValue("https://www.changed.com"),
		"subject": structpb.NewStringValue("changed"),
	}}

	freshAccount := func(t *testing.T) (*oidc.Account, func()) {
		t.Helper()
		acc := oidc.TestAccount(t, conn, am, "test-subject", oidc.WithName("default"), oidc.WithDescription("default"))

		clean := func() {
			_, err := tested.DeleteAccount(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()),
				&pbs.DeleteAccountRequest{Id: acc.GetPublicId()})
			require.NoError(t, err)
		}

		return acc, clean
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
					Paths: []string{globals.NameField, globals.DescriptionField},
				},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        auth.OidcSubtype.String(),
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "new"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					Type:              auth.OidcSubtype.String(),
					Attributes:        defaultAttributes,
					Scope:             defaultScopeInfo,
					AuthorizedActions: oidcAuthorizedActions,
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
					Type:        auth.OidcSubtype.String(),
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "new"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					Type:              auth.OidcSubtype.String(),
					Attributes:        defaultAttributes,
					Scope:             defaultScopeInfo,
					AuthorizedActions: oidcAuthorizedActions,
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
					Paths: []string{globals.NameField},
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
					Paths: []string{globals.NameField},
				},
				Item: &pb.Account{
					Description: &wrapperspb.StringValue{Value: "ignored"},
					Attributes:  modifiedAttributes,
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Description:       &wrapperspb.StringValue{Value: "default"},
					Type:              auth.OidcSubtype.String(),
					Attributes:        defaultAttributes,
					Scope:             defaultScopeInfo,
					AuthorizedActions: oidcAuthorizedActions,
				},
			},
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.NameField},
				},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
					Attributes:  modifiedAttributes,
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "updated"},
					Description:       &wrapperspb.StringValue{Value: "default"},
					Type:              auth.OidcSubtype.String(),
					Attributes:        defaultAttributes,
					Scope:             defaultScopeInfo,
					AuthorizedActions: oidcAuthorizedActions,
				},
			},
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.DescriptionField},
				},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
					Attributes:  modifiedAttributes,
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "default"},
					Description:       &wrapperspb.StringValue{Value: "notignored"},
					Type:              auth.OidcSubtype.String(),
					Attributes:        defaultAttributes,
					Scope:             defaultScopeInfo,
					AuthorizedActions: oidcAuthorizedActions,
				},
			},
		},
		{
			name: "Update LoginName",
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
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Update a Non Existing Account",
			req: &pbs.UpdateAccountRequest{
				Id: password.AccountPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.DescriptionField},
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
				},
			},
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
					CreatedTime: timestamppb.Now(),
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
					UpdatedTime: timestamppb.Now(),
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
		{
			name: "Update Issuer",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.issuer"},
				},
				Item: &pb.Account{
					Name:       &wrapperspb.StringValue{Value: "ignored"},
					Attributes: modifiedAttributes,
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Update Subject",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.subject"},
				},
				Item: &pb.Account{
					Name:       &wrapperspb.StringValue{Value: "ignored"},
					Attributes: modifiedAttributes,
				},
			},
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
				tc.req.Id = acc.GetPublicId()
			}

			if tc.res != nil && tc.res.Item != nil {
				tc.res.Item.Id = acc.GetPublicId()
				tc.res.Item.CreatedTime = acc.GetCreateTime().GetTimestamp()
			}

			got, gErr := tested.UpdateAccount(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateAccount(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}

			if tc.res == nil {
				require.Nil(got)
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateAccount response to be nil, but was %v", got)
				gotUpdateTime := got.GetItem().GetUpdatedTime()
				require.NoError(err, "Error converting proto to timestamp")

				created := acc.GetCreateTime().GetTimestamp()
				require.NoError(err, "Error converting proto to timestamp")

				// Verify it is a auth_method updated after it was created
				assert.True(gotUpdateTime.AsTime().After(created.AsTime()), "Updated account should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil

				assert.EqualValues(2, got.Item.Version)
				tc.res.Item.Version = 2
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "UpdateAccount(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

*/
