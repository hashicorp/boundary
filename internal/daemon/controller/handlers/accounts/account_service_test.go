// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package accounts_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	ldapstore "github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	oidcstore "github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/auth/password"
	pwstore "github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/authtoken"
	requestauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/accounts"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/accounts"
	scopepb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	pwAuthorizedActions = []string{
		action.NoOp.String(),
		action.Read.String(),
		action.Update.String(),
		action.Delete.String(),
		action.SetPassword.String(),
		action.ChangePassword.String(),
	}
	oidcAuthorizedActions = []string{
		action.NoOp.String(),
		action.Read.String(),
		action.Update.String(),
		action.Delete.String(),
	}
	ldapAuthorizedActions = []string{
		action.NoOp.String(),
		action.Read.String(),
		action.Update.String(),
		action.Delete.String(),
	}
)

func TestNewService(t *testing.T) {
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kmsCache)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kmsCache)
	}

	cases := []struct {
		name     string
		pwRepo   common.PasswordAuthRepoFactory
		oidcRepo common.OidcAuthRepoFactory
		wantErr  bool
	}{
		{
			name:    "nil-all",
			wantErr: true,
		},
		{
			name:     "nil-pw-repo",
			oidcRepo: oidcRepoFn,
			wantErr:  true,
		},
		{
			name:    "nil-oidc-repo",
			pwRepo:  pwRepoFn,
			wantErr: true,
		},
		{
			name:     "success",
			pwRepo:   pwRepoFn,
			oidcRepo: oidcRepoFn,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := accounts.NewService(ctx, tc.pwRepo, tc.oidcRepo, ldapRepoFn, 1000)
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
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kmsCache)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		// Use a small limit to test that membership lookup is explicitly unlimited
		return oidc.NewRepository(ctx, rw, rw, kmsCache, oidc.WithLimit(1))
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kmsCache)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		// Use a small limit to test that membership lookup is explicitly unlimited
		return ldap.NewRepository(ctx, rw, rw, kmsCache, ldap.WithLimit(ctx, 1))
	}

	s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err, "Couldn't create new auth token service.")

	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))

	am := password.TestAuthMethods(t, conn, org.GetPublicId(), 1)[0]
	pwA := password.TestAccount(t, conn, am.GetPublicId(), "name1")

	pwWireAccount := pb.Account{
		Id:           pwA.GetPublicId(),
		AuthMethodId: pwA.GetAuthMethodId(),
		CreatedTime:  pwA.GetCreateTime().GetTimestamp(),
		UpdatedTime:  pwA.GetUpdateTime().GetTimestamp(),
		Scope:        &scopepb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
		Version:      1,
		Type:         password.Subtype.String(),
		Attrs: &pb.Account_PasswordAccountAttributes{
			PasswordAccountAttributes: &pb.PasswordAccountAttributes{LoginName: pwA.GetLoginName()},
		},
		AuthorizedActions: pwAuthorizedActions,
	}

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	oidcAm := oidc.TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	oidcA := oidc.TestAccount(t, conn, oidcAm, "test-subject")
	// Create some managed groups that will always match, so we can test that it is
	// returned in results
	mg := oidc.TestManagedGroup(t, conn, oidcAm, `"/token/sub" matches ".*"`)
	mg2 := oidc.TestManagedGroup(t, conn, oidcAm, `"/token/sub" matches ".*"`)
	oidcWireAccount := pb.Account{
		Id:           oidcA.GetPublicId(),
		AuthMethodId: oidcA.GetAuthMethodId(),
		CreatedTime:  oidcA.GetCreateTime().GetTimestamp(),
		UpdatedTime:  oidcA.GetUpdateTime().GetTimestamp(),
		Scope:        &scopepb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
		Version:      1,
		Type:         oidc.Subtype.String(),
		Attrs: &pb.Account_OidcAccountAttributes{
			OidcAccountAttributes: &pb.OidcAccountAttributes{
				Issuer:  oidcAm.GetIssuer(),
				Subject: "test-subject",
			},
		},
		AuthorizedActions: oidcAuthorizedActions,
		ManagedGroupIds:   []string{mg.GetPublicId(), mg2.GetPublicId()},
	}

	ldapAm := ldap.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
	ldapAcct := ldap.TestAccount(t, conn, ldapAm, "test-acct",
		ldap.WithMemberOfGroups(ctx, "admin"),
		ldap.WithFullName(ctx, "test-name"),
		ldap.WithEmail(ctx, "test-email"),
		ldap.WithDn(ctx, "test-dn"),
	)
	ldapMg := ldap.TestManagedGroup(t, conn, ldapAm, []string{"admin"})
	ldapMg2 := ldap.TestManagedGroup(t, conn, ldapAm, []string{"admin"})
	ldapWireAccount := pb.Account{
		Id:           ldapAcct.GetPublicId(),
		AuthMethodId: ldapAm.GetPublicId(),
		CreatedTime:  ldapAcct.GetCreateTime().GetTimestamp(),
		UpdatedTime:  ldapAcct.GetUpdateTime().GetTimestamp(),
		Scope:        &scopepb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
		Version:      1,
		Attrs: &pb.Account_LdapAccountAttributes{
			LdapAccountAttributes: &pb.LdapAccountAttributes{
				LoginName:      ldapAcct.GetLoginName(),
				FullName:       ldapAcct.GetFullName(),
				Email:          ldapAcct.GetEmail(),
				Dn:             ldapAcct.GetDn(),
				MemberOfGroups: []string{"admin"},
			},
		},
		Type:              ldap.Subtype.String(),
		AuthorizedActions: ldapAuthorizedActions,
		ManagedGroupIds:   []string{ldapMg.GetPublicId(), ldapMg2.GetPublicId()},
	}

	cases := []struct {
		name string
		req  *pbs.GetAccountRequest
		res  *pbs.GetAccountResponse
		err  error
	}{
		{
			name: "Get an ldap account",
			req:  &pbs.GetAccountRequest{Id: ldapWireAccount.GetId()},
			res:  &pbs.GetAccountResponse{Item: &ldapWireAccount},
		},
		{
			name: "Get a password account",
			req:  &pbs.GetAccountRequest{Id: pwWireAccount.GetId()},
			res:  &pbs.GetAccountResponse{Item: &pwWireAccount},
		},
		{
			name: "Get an oidc account",
			req:  &pbs.GetAccountRequest{Id: oidcWireAccount.GetId()},
			res:  &pbs.GetAccountResponse{Item: &oidcWireAccount},
		},
		{
			name: "Get a non existing old password account",
			req:  &pbs.GetAccountRequest{Id: globals.PasswordAccountPreviousPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Get a non existing new password account",
			req:  &pbs.GetAccountRequest{Id: globals.PasswordAccountPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Get a non existing oidc account",
			req:  &pbs.GetAccountRequest{Id: globals.OidcAccountPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Get a non existing ldap account",
			req:  &pbs.GetAccountRequest{Id: globals.LdapAccountPrefix + "_DoesntExis"},
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
			req:  &pbs.GetAccountRequest{Id: globals.AuthTokenPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			if globals.ResourceInfoFromPrefix(tc.req.Id).Subtype == oidc.Subtype {
				// Set up managed groups before getting. First get the current
				// managed groups to make sure we have the right version.
				oidcRepo, err := oidcRepoFn()
				require.NoError(err)
				currMg, err := oidcRepo.LookupManagedGroup(ctx, mg.GetPublicId())
				require.NoError(err)
				currMg2, err := oidcRepo.LookupManagedGroup(ctx, mg2.GetPublicId())
				require.NoError(err)
				_, _, err = oidcRepo.SetManagedGroupMemberships(ctx, oidcAm, oidcA, []*oidc.ManagedGroup{currMg, currMg2})
				require.NoError(err)
			}

			got, gErr := s.GetAccount(requestauth.DisabledAuthTestContext(iamRepoFn, org.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetAccount(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "GetAccount(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestListPassword(t *testing.T) {
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kms)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kms)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kms)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	ams := password.TestAuthMethods(t, conn, o.GetPublicId(), 3)
	amNoAccounts, amSomeAccounts, amOtherAccounts := ams[0], ams[1], ams[2]

	var wantSomeAccounts []*pb.Account
	for _, aa := range password.TestMultipleAccounts(t, conn, amSomeAccounts.GetPublicId(), 3) {
		wantSomeAccounts = append(wantSomeAccounts, &pb.Account{
			Id:           aa.GetPublicId(),
			AuthMethodId: aa.GetAuthMethodId(),
			CreatedTime:  aa.GetCreateTime().GetTimestamp(),
			UpdatedTime:  aa.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         "password",
			Attrs: &pb.Account_PasswordAccountAttributes{
				PasswordAccountAttributes: &pb.PasswordAccountAttributes{LoginName: aa.GetLoginName()},
			},
			AuthorizedActions: pwAuthorizedActions,
		})
	}

	slices.Reverse(wantSomeAccounts)

	var wantOtherAccounts []*pb.Account
	for _, aa := range password.TestMultipleAccounts(t, conn, amOtherAccounts.GetPublicId(), 3) {
		wantOtherAccounts = append(wantOtherAccounts, &pb.Account{
			Id:           aa.GetPublicId(),
			AuthMethodId: aa.GetAuthMethodId(),
			CreatedTime:  aa.GetCreateTime().GetTimestamp(),
			UpdatedTime:  aa.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         "password",
			Attrs: &pb.Account_PasswordAccountAttributes{
				PasswordAccountAttributes: &pb.PasswordAccountAttributes{LoginName: aa.GetLoginName()},
			},
			AuthorizedActions: pwAuthorizedActions,
		})
	}

	slices.Reverse(wantOtherAccounts)

	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	cases := []struct {
		name     string
		req      *pbs.ListAccountsRequest
		res      *pbs.ListAccountsResponse
		err      error
		skipAnon bool
	}{
		{
			name: "List Some Accounts",
			req:  &pbs.ListAccountsRequest{AuthMethodId: amSomeAccounts.GetPublicId()},
			res: &pbs.ListAccountsResponse{
				Items:        wantSomeAccounts,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				EstItemCount: uint32(len(wantSomeAccounts)),
			},
		},
		{
			name: "List Other Accounts",
			req:  &pbs.ListAccountsRequest{AuthMethodId: amOtherAccounts.GetPublicId()},
			res: &pbs.ListAccountsResponse{
				Items:        wantOtherAccounts,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				EstItemCount: uint32(len(wantOtherAccounts)),
			},
		},
		{
			name: "List No Accounts",
			req:  &pbs.ListAccountsRequest{AuthMethodId: amNoAccounts.GetPublicId()},
			res: &pbs.ListAccountsResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				EstItemCount: 0,
			},
		},
		{
			name: "Unfound Auth Method",
			req:  &pbs.ListAccountsRequest{AuthMethodId: globals.PasswordAuthMethodPrefix + "_DoesntExis"},
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Filter Some Accounts",
			req: &pbs.ListAccountsRequest{
				AuthMethodId: amSomeAccounts.GetPublicId(),
				Filter:       fmt.Sprintf(`"/item/attributes/login_name"==%q`, wantSomeAccounts[1].GetPasswordAccountAttributes().LoginName),
			},
			res: &pbs.ListAccountsResponse{
				Items:        wantSomeAccounts[1:2],
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				EstItemCount: 1,
			},
			skipAnon: true,
		},
		{
			name: "Filter All Accounts",
			req: &pbs.ListAccountsRequest{
				AuthMethodId: amSomeAccounts.GetPublicId(),
				Filter:       `"/item/id"=="noaccountmatchesthis"`,
			},
			res: &pbs.ListAccountsResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListAccountsRequest{AuthMethodId: amSomeAccounts.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
			require.NoError(err, "Couldn't create new user service.")

			// Test non-anon first
			got, gErr := s.ListAccounts(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListAccounts() with auth method %q got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			} else {
				require.NoError(gErr)
			}
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			))

			// Now test with anon
			if tc.skipAnon {
				return
			}
			got, gErr = s.ListAccounts(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId(), requestauth.WithUserId(globals.AnonymousUserId)), tc.req)
			require.NoError(gErr)
			assert.Len(got.Items, len(tc.res.Items))
			for _, g := range got.GetItems() {
				assert.Nil(g.Attrs)
				assert.Nil(g.CreatedTime)
				assert.Nil(g.UpdatedTime)
				assert.Empty(g.Version)
			}
		})
	}
}

func TestListOidc(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kmsCache)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kmsCache)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kmsCache)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	amNoAccounts := oidc.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState, "noAccounts", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.noaccounts.com")[0]), oidc.WithSigningAlgs(oidc.RS256), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]))
	amSomeAccounts := oidc.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState, "someAccounts", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.someaccounts.com")[0]), oidc.WithSigningAlgs(oidc.RS256), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]))
	amOtherAccounts := oidc.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState, "otherAccounts", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.otheraccounts.com")[0]), oidc.WithSigningAlgs(oidc.RS256), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]))

	var wantSomeAccounts []*pb.Account
	for i := 0; i < 3; i++ {
		subId := fmt.Sprintf("test-subject%d", i)
		aa := oidc.TestAccount(t, conn, amSomeAccounts, subId)
		wantSomeAccounts = append(wantSomeAccounts, &pb.Account{
			Id:           aa.GetPublicId(),
			AuthMethodId: aa.GetAuthMethodId(),
			CreatedTime:  aa.GetCreateTime().GetTimestamp(),
			UpdatedTime:  aa.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         oidc.Subtype.String(),
			Attrs: &pb.Account_OidcAccountAttributes{
				OidcAccountAttributes: &pb.OidcAccountAttributes{
					Issuer:  amSomeAccounts.GetIssuer(),
					Subject: subId,
				},
			},
			AuthorizedActions: oidcAuthorizedActions,
		})
	}

	slices.Reverse(wantSomeAccounts)

	var wantOtherAccounts []*pb.Account
	for i := 0; i < 3; i++ {
		subId := fmt.Sprintf("test-subject%d", i)
		aa := oidc.TestAccount(t, conn, amOtherAccounts, subId)
		wantOtherAccounts = append(wantOtherAccounts, &pb.Account{
			Id:           aa.GetPublicId(),
			AuthMethodId: aa.GetAuthMethodId(),
			CreatedTime:  aa.GetCreateTime().GetTimestamp(),
			UpdatedTime:  aa.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         oidc.Subtype.String(),
			Attrs: &pb.Account_OidcAccountAttributes{
				OidcAccountAttributes: &pb.OidcAccountAttributes{
					Issuer:  amOtherAccounts.GetIssuer(),
					Subject: subId,
				},
			},
			AuthorizedActions: oidcAuthorizedActions,
		})
	}

	slices.Reverse(wantOtherAccounts)

	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	cases := []struct {
		name     string
		req      *pbs.ListAccountsRequest
		res      *pbs.ListAccountsResponse
		err      error
		skipAnon bool
	}{
		{
			name: "List Some Accounts",
			req:  &pbs.ListAccountsRequest{AuthMethodId: amSomeAccounts.GetPublicId()},
			res: &pbs.ListAccountsResponse{
				Items:        wantSomeAccounts,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				EstItemCount: uint32(len(wantSomeAccounts)),
			},
		},
		{
			name: "List Other Accounts",
			req:  &pbs.ListAccountsRequest{AuthMethodId: amOtherAccounts.GetPublicId()},
			res: &pbs.ListAccountsResponse{
				Items:        wantOtherAccounts,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				EstItemCount: uint32(len(wantOtherAccounts)),
			},
		},
		{
			name: "List No Accounts",
			req:  &pbs.ListAccountsRequest{AuthMethodId: amNoAccounts.GetPublicId()},
			res: &pbs.ListAccountsResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "Unfound Auth Method",
			req:  &pbs.ListAccountsRequest{AuthMethodId: globals.OidcAuthMethodPrefix + "_DoesntExis"},
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Filter Some Accounts",
			req: &pbs.ListAccountsRequest{
				AuthMethodId: amSomeAccounts.GetPublicId(),
				Filter:       fmt.Sprintf(`"/item/attributes/subject"==%q`, wantSomeAccounts[1].GetOidcAccountAttributes().Subject),
			},
			res: &pbs.ListAccountsResponse{
				Items:        wantSomeAccounts[1:2],
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				EstItemCount: 1,
			},
			skipAnon: true,
		},
		{
			name: "Filter All Accounts",
			req: &pbs.ListAccountsRequest{
				AuthMethodId: amSomeAccounts.GetPublicId(),
				Filter:       `"/item/id"=="noaccountmatchesthis"`,
			},
			res: &pbs.ListAccountsResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListAccountsRequest{AuthMethodId: amSomeAccounts.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
			require.NoError(err, "Couldn't create new user service.")

			got, gErr := s.ListAccounts(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListAccounts() with auth method %q got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			} else {
				require.NoError(gErr)
			}
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			))

			// Now test with anon
			if tc.skipAnon {
				return
			}
			got, gErr = s.ListAccounts(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId(), requestauth.WithUserId(globals.AnonymousUserId)), tc.req)
			require.NoError(gErr)
			assert.Len(got.Items, len(tc.res.Items))
			for _, g := range got.GetItems() {
				assert.Nil(g.Attrs)
				assert.Nil(g.CreatedTime)
				assert.Nil(g.UpdatedTime)
				assert.Empty(g.Version)
			}
		})
	}
}

func TestListLdap(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kmsCache)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kmsCache)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kmsCache)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	amNoAccounts := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://no-accounts"})
	amSomeAccounts := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://some-accounts"})
	amOtherAccounts := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://other-accounts"})

	var wantSomeAccounts []*pb.Account
	for i := 0; i < 3; i++ {
		loginName := fmt.Sprintf("test-login-name%d", i)
		aa := ldap.TestAccount(t, conn, amSomeAccounts, loginName)
		wantSomeAccounts = append(wantSomeAccounts, &pb.Account{
			Id:           aa.GetPublicId(),
			AuthMethodId: aa.GetAuthMethodId(),
			CreatedTime:  aa.GetCreateTime().GetTimestamp(),
			UpdatedTime:  aa.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         ldap.Subtype.String(),
			Attrs: &pb.Account_LdapAccountAttributes{
				LdapAccountAttributes: &pb.LdapAccountAttributes{
					LoginName: loginName,
				},
			},
			AuthorizedActions: ldapAuthorizedActions,
		})
	}

	slices.Reverse(wantSomeAccounts)

	var wantOtherAccounts []*pb.Account
	for i := 0; i < 3; i++ {
		loginName := fmt.Sprintf("test-login-name%d", i)
		aa := ldap.TestAccount(t, conn, amOtherAccounts, loginName)
		wantOtherAccounts = append(wantOtherAccounts, &pb.Account{
			Id:           aa.GetPublicId(),
			AuthMethodId: aa.GetAuthMethodId(),
			CreatedTime:  aa.GetCreateTime().GetTimestamp(),
			UpdatedTime:  aa.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         ldap.Subtype.String(),
			Attrs: &pb.Account_LdapAccountAttributes{
				LdapAccountAttributes: &pb.LdapAccountAttributes{
					LoginName: loginName,
				},
			},
			AuthorizedActions: ldapAuthorizedActions,
		})
	}

	slices.Reverse(wantOtherAccounts)

	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	cases := []struct {
		name     string
		req      *pbs.ListAccountsRequest
		res      *pbs.ListAccountsResponse
		err      error
		skipAnon bool
	}{
		{
			name: "List Some Accounts",
			req:  &pbs.ListAccountsRequest{AuthMethodId: amSomeAccounts.GetPublicId()},
			res: &pbs.ListAccountsResponse{
				Items:        wantSomeAccounts,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				EstItemCount: uint32(len(wantSomeAccounts)),
			},
		},
		{
			name: "List Other Accounts",
			req:  &pbs.ListAccountsRequest{AuthMethodId: amOtherAccounts.GetPublicId()},
			res: &pbs.ListAccountsResponse{
				Items:        wantOtherAccounts,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				EstItemCount: uint32(len(wantOtherAccounts)),
			},
		},
		{
			name: "List No Accounts",
			req:  &pbs.ListAccountsRequest{AuthMethodId: amNoAccounts.GetPublicId()},
			res: &pbs.ListAccountsResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "Unfound Auth Method",
			req:  &pbs.ListAccountsRequest{AuthMethodId: globals.OidcAuthMethodPrefix + "_DoesntExis"},
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Filter Some Accounts",
			req: &pbs.ListAccountsRequest{
				AuthMethodId: amSomeAccounts.GetPublicId(),
				Filter:       fmt.Sprintf(`"/item/attributes/login_name"==%q`, wantSomeAccounts[1].GetLdapAccountAttributes().LoginName),
			},
			res: &pbs.ListAccountsResponse{
				Items:        wantSomeAccounts[1:2],
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				EstItemCount: 1,
			},
			skipAnon: true,
		},
		{
			name: "Filter All Accounts",
			req: &pbs.ListAccountsRequest{
				AuthMethodId: amSomeAccounts.GetPublicId(),
				Filter:       `"/item/id"=="noaccountmatchesthis"`,
			},
			res: &pbs.ListAccountsResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListAccountsRequest{AuthMethodId: amSomeAccounts.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
			require.NoError(err, "Couldn't create new user service.")

			got, gErr := s.ListAccounts(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListAccounts() with auth method %q got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			} else {
				require.NoError(gErr)
			}
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			))

			// Now test with anon
			if tc.skipAnon {
				return
			}
			got, gErr = s.ListAccounts(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId(), requestauth.WithUserId(globals.AnonymousUserId)), tc.req)
			require.NoError(gErr)
			assert.Len(got.Items, len(tc.res.Items))
			for _, g := range got.GetItems() {
				assert.Nil(g.Attrs)
				assert.Nil(g.CreatedTime)
				assert.Nil(g.UpdatedTime)
				assert.Empty(g.Version)
			}
		})
	}
}

func TestListPagination(t *testing.T) {
	// Set database read timeout to avoid duplicates in response
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})

	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDB, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kmsCache)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kmsCache)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kmsCache)
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kmsCache)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsCache)
	}

	s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err)

	iamRepo := iam.TestRepo(t, conn, wrap)
	tokenRepo, _ := tokenRepoFn()
	pwRepo, _ := pwRepoFn()
	oidcRepo, _ := oidcRepoFn()
	ldapRepo, _ := ldapRepoFn()
	o, pwt := iam.TestScopes(t, iamRepo)

	t.Run("password", func(t *testing.T) {
		authMethod := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

		var accounts []*pb.Account
		for _, aa := range password.TestMultipleAccounts(t, conn, authMethod.GetPublicId(), 9) {
			accounts = append(accounts, &pb.Account{
				Id:           aa.GetPublicId(),
				AuthMethodId: aa.GetAuthMethodId(),
				CreatedTime:  aa.GetCreateTime().GetTimestamp(),
				UpdatedTime:  aa.GetUpdateTime().GetTimestamp(),
				Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
				Version:      1,
				Type:         "password",
				Attrs: &pb.Account_PasswordAccountAttributes{
					PasswordAccountAttributes: &pb.PasswordAccountAttributes{LoginName: aa.GetLoginName()},
				},
				AuthorizedActions: pwAuthorizedActions,
			})
		}

		acct := password.TestAccount(t, conn, authMethod.GetPublicId(), "test-login-last")
		u := iam.TestUser(t, iamRepo, o.GetPublicId(), iam.WithAccountIds(acct.PublicId))

		privProjRole := iam.TestRole(t, conn, pwt.GetPublicId())
		iam.TestRoleGrant(t, conn, privProjRole.GetPublicId(), "ids=*;type=*;actions=*")
		iam.TestUserRole(t, conn, privProjRole.GetPublicId(), u.GetPublicId())
		privOrgRole := iam.TestRole(t, conn, o.GetPublicId())
		iam.TestRoleGrant(t, conn, privOrgRole.GetPublicId(), "ids=*;type=*;actions=*")
		iam.TestUserRole(t, conn, privOrgRole.GetPublicId(), u.GetPublicId())

		accounts = append(accounts, &pb.Account{
			Id:           acct.GetPublicId(),
			AuthMethodId: acct.GetAuthMethodId(),
			CreatedTime:  acct.GetCreateTime().GetTimestamp(),
			UpdatedTime:  acct.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         "password",
			Attrs: &pb.Account_PasswordAccountAttributes{
				PasswordAccountAttributes: &pb.PasswordAccountAttributes{LoginName: acct.GetLoginName()},
			},
			AuthorizedActions: pwAuthorizedActions,
		})

		// Since we sort by created_time descending, we reverse the slice
		slices.Reverse(accounts)

		at, _ := tokenRepo.CreateAuthToken(ctx, u, acct.GetPublicId())

		requestInfo := authpb.RequestInfo{
			TokenFormat: uint32(requestauth.AuthTokenTypeBearer),
			PublicId:    at.GetPublicId(),
			Token:       at.GetToken(),
		}
		requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
		ctx = requestauth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kmsCache, &requestInfo)

		req := &pbs.ListAccountsRequest{
			AuthMethodId: authMethod.GetPublicId(),
			Filter:       "",
			ListToken:    "",
			PageSize:     2,
		}

		// Run analyze in the DB to update the estimate tables
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		got, err := s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 2)

		// all comparisons will be done without list token
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        accounts[0:2],
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)

		// second page
		req.ListToken = got.ListToken
		got, err = s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 2)

		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        accounts[2:4],
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)

		// remainder of results
		req.ListToken = got.ListToken
		req.PageSize = 6
		got, err = s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 6)

		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        accounts[4:],
					ResponseType: "complete",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)

		// create another acct
		aa := password.TestAccount(t, conn, authMethod.GetPublicId(), "test-login-new-last")
		newAccount := &pb.Account{
			Id:           aa.GetPublicId(),
			AuthMethodId: aa.GetAuthMethodId(),
			CreatedTime:  aa.GetCreateTime().GetTimestamp(),
			UpdatedTime:  aa.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         "password",
			Attrs: &pb.Account_PasswordAccountAttributes{
				PasswordAccountAttributes: &pb.PasswordAccountAttributes{LoginName: aa.GetLoginName()},
			},
			AuthorizedActions: pwAuthorizedActions,
		}
		// Append new account to the front of the slice, since it's the most recently updated
		accounts = append([]*pb.Account{newAccount}, accounts...)

		// delete different acct
		_, err = pwRepo.DeleteAccount(ctx, o.GetPublicId(), accounts[len(accounts)-1].Id)
		require.NoError(t, err)
		deletedAccount := accounts[len(accounts)-1]
		accounts = accounts[:len(accounts)-1]

		// update another acct
		accounts[1].Name = wrapperspb.String("new-name")
		accounts[1].Version = 2
		a := &password.Account{
			Account: &pwstore.Account{
				PublicId:     accounts[1].Id,
				AuthMethodId: accounts[1].AuthMethodId,
				Name:         accounts[1].Name.GetValue(),
			},
		}
		ua, _, err := pwRepo.UpdateAccount(ctx, o.GetPublicId(), a, 1, []string{"name"})
		require.NoError(t, err)
		accounts[1].UpdatedTime = ua.GetUpdateTime().GetTimestamp()
		accounts[1].Version = ua.GetVersion()
		// Add to the front since it's most recently updated
		accounts = append(
			[]*pb.Account{accounts[1]},
			append(
				[]*pb.Account{accounts[0]},
				accounts[2:]...,
			)...,
		)

		// Run analyze to update postgres estimates
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request updated results
		req.ListToken = got.ListToken
		req.PageSize = 1
		got, err = s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        []*pb.Account{accounts[0]},
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "updated_time",
					SortDir:      "desc",
					RemovedIds:   []string{deletedAccount.Id},
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)

		// Get the next page
		req.ListToken = got.ListToken
		got, err = s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        []*pb.Account{accounts[1]},
					ResponseType: "complete",
					ListToken:    "",
					SortBy:       "updated_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)

		// Request new page with filter requiring looping
		// to fill the page.
		req.ListToken = ""
		req.Filter = fmt.Sprintf(`"/item/id"==%q or "/item/id"==%q`, accounts[len(accounts)-2].Id, accounts[len(accounts)-1].Id)
		got, err = s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        []*pb.Account{accounts[len(accounts)-2]},
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					// Should be empty again
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)
		req.ListToken = got.ListToken
		// Get the second page
		got, err = s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        []*pb.Account{accounts[len(accounts)-1]},
					ResponseType: "complete",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)

		// Create unauthenticated user
		unauthAt := authtoken.TestAuthToken(t, conn, kmsCache, o.GetPublicId())
		unauthR := iam.TestRole(t, conn, pwt.GetPublicId())
		_ = iam.TestUserRole(t, conn, unauthR.GetPublicId(), unauthAt.GetIamUserId())

		// Make a request with the unauthenticated user,
		// ensure the response is 403 forbidden.
		requestInfo = authpb.RequestInfo{
			TokenFormat: uint32(requestauth.AuthTokenTypeBearer),
			PublicId:    unauthAt.GetPublicId(),
			Token:       unauthAt.GetToken(),
		}
		requestContext = context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
		ctx = requestauth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kmsCache, &requestInfo)

		_, err = s.ListAccounts(ctx, &pbs.ListAccountsRequest{
			AuthMethodId: authMethod.GetPublicId(),
		})
		require.Error(t, err)
		assert.Equal(t, handlers.ForbiddenError(), err)
	})

	t.Run("oidc", func(t *testing.T) {
		o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
		databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
		require.NoError(t, err)
		authMethod := oidc.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState, "someAccounts", "fido",
			oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.someaccounts.com")[0]), oidc.WithSigningAlgs(oidc.RS256), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]))

		var accounts []*pb.Account
		for i := 0; i < 9; i++ {
			subId := fmt.Sprintf("test-subject%d", i)
			aa := oidc.TestAccount(t, conn, authMethod, subId)
			accounts = append(accounts, &pb.Account{
				Id:           aa.GetPublicId(),
				AuthMethodId: aa.GetAuthMethodId(),
				CreatedTime:  aa.GetCreateTime().GetTimestamp(),
				UpdatedTime:  aa.GetUpdateTime().GetTimestamp(),
				Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
				Version:      1,
				Type:         oidc.Subtype.String(),
				Attrs: &pb.Account_OidcAccountAttributes{
					OidcAccountAttributes: &pb.OidcAccountAttributes{
						Issuer:  authMethod.GetIssuer(),
						Subject: subId,
					},
				},
				AuthorizedActions: oidcAuthorizedActions,
			})
		}

		acct := oidc.TestAccount(t, conn, authMethod, "test-login-last")
		u := iam.TestUser(t, iamRepo, o.GetPublicId(), iam.WithAccountIds(acct.PublicId))

		privProjRole := iam.TestRole(t, conn, pwt.GetPublicId())
		iam.TestRoleGrant(t, conn, privProjRole.GetPublicId(), "ids=*;type=*;actions=*")
		iam.TestUserRole(t, conn, privProjRole.GetPublicId(), u.GetPublicId())
		privOrgRole := iam.TestRole(t, conn, o.GetPublicId())
		iam.TestRoleGrant(t, conn, privOrgRole.GetPublicId(), "ids=*;type=*;actions=*")
		iam.TestUserRole(t, conn, privOrgRole.GetPublicId(), u.GetPublicId())

		accounts = append(accounts, &pb.Account{
			Id:           acct.GetPublicId(),
			AuthMethodId: acct.GetAuthMethodId(),
			CreatedTime:  acct.GetCreateTime().GetTimestamp(),
			UpdatedTime:  acct.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         oidc.Subtype.String(),
			Attrs: &pb.Account_OidcAccountAttributes{
				OidcAccountAttributes: &pb.OidcAccountAttributes{
					Issuer:  authMethod.GetIssuer(),
					Subject: "test-login-last",
				},
			},
			AuthorizedActions: oidcAuthorizedActions,
		})

		// Since we sort by created_time descending, we reverse the slice
		slices.Reverse(accounts)

		at, _ := tokenRepo.CreateAuthToken(ctx, u, acct.GetPublicId())

		requestInfo := authpb.RequestInfo{
			TokenFormat: uint32(requestauth.AuthTokenTypeBearer),
			PublicId:    at.GetPublicId(),
			Token:       at.GetToken(),
		}
		requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
		ctx = requestauth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kmsCache, &requestInfo)

		req := &pbs.ListAccountsRequest{
			AuthMethodId: authMethod.GetPublicId(),
			Filter:       "",
			ListToken:    "",
			PageSize:     2,
		}

		// Run analyze in the DB to update the estimate tables
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		got, err := s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 2)

		// all comparisons will be done without list token
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        accounts[0:2],
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)

		// second page
		req.ListToken = got.ListToken
		got, err = s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 2)

		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        accounts[2:4],
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)

		// remainder of results
		req.ListToken = got.ListToken
		req.PageSize = 6
		got, err = s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 6)

		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        accounts[4:],
					ResponseType: "complete",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)

		// create another acct
		aa := oidc.TestAccount(t, conn, authMethod, "test-login-new-last")
		newAccount := &pb.Account{
			Id:           aa.GetPublicId(),
			AuthMethodId: aa.GetAuthMethodId(),
			CreatedTime:  aa.GetCreateTime().GetTimestamp(),
			UpdatedTime:  aa.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         oidc.Subtype.String(),
			Attrs: &pb.Account_OidcAccountAttributes{
				OidcAccountAttributes: &pb.OidcAccountAttributes{
					Issuer:  authMethod.GetIssuer(),
					Subject: "test-login-new-last",
				},
			},
			AuthorizedActions: oidcAuthorizedActions,
		}
		// Add to front since it's the latest updated
		accounts = append([]*pb.Account{newAccount}, accounts...)

		// delete different acct
		_, err = oidcRepo.DeleteAccount(ctx, o.GetPublicId(), accounts[len(accounts)-1].Id)
		require.NoError(t, err)
		deletedAccount := accounts[len(accounts)-1]
		accounts = accounts[:len(accounts)-1]

		// update another acct
		accounts[1].Name = wrapperspb.String("new-name")
		accounts[1].Version = 2
		a := &oidc.Account{
			Account: &oidcstore.Account{
				PublicId:     accounts[1].Id,
				AuthMethodId: accounts[1].AuthMethodId,
				Name:         accounts[1].Name.GetValue(),
			},
		}
		ua, _, err := oidcRepo.UpdateAccount(ctx, o.GetPublicId(), a, 1, []string{"name"})
		require.NoError(t, err)
		accounts[1].UpdatedTime = ua.GetUpdateTime().GetTimestamp()
		accounts[1].Version = ua.GetVersion()
		// Add to the front since it's most recently updated
		accounts = append(
			[]*pb.Account{accounts[1]},
			append(
				[]*pb.Account{accounts[0]},
				accounts[2:]...,
			)...,
		)

		// Run analyze to update postgres estimates
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request updated results
		req.ListToken = got.ListToken
		req.PageSize = 1
		got, err = s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        []*pb.Account{accounts[0]},
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "updated_time",
					SortDir:      "desc",
					RemovedIds:   []string{deletedAccount.Id},
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)

		// Get next page
		req.ListToken = got.ListToken
		got, err = s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        []*pb.Account{accounts[1]},
					ResponseType: "complete",
					ListToken:    "",
					SortBy:       "updated_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)

		// Request new page with filter requiring looping
		// to fill the page.
		req.ListToken = ""
		req.PageSize = 1
		req.Filter = fmt.Sprintf(`"/item/id"==%q or "/item/id"==%q`, accounts[len(accounts)-2].Id, accounts[len(accounts)-1].Id)
		got, err = s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        []*pb.Account{accounts[len(accounts)-2]},
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					// Should be empty again
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)
		req.ListToken = got.ListToken
		// Get the second page
		got, err = s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        []*pb.Account{accounts[len(accounts)-1]},
					ResponseType: "complete",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)

		// Create unauthenticated user
		unauthAt := authtoken.TestAuthToken(t, conn, kmsCache, o.GetPublicId())
		unauthR := iam.TestRole(t, conn, pwt.GetPublicId())
		_ = iam.TestUserRole(t, conn, unauthR.GetPublicId(), unauthAt.GetIamUserId())

		// Make a request with the unauthenticated user,
		// ensure the response is 403 forbidden.
		requestInfo = authpb.RequestInfo{
			TokenFormat: uint32(requestauth.AuthTokenTypeBearer),
			PublicId:    unauthAt.GetPublicId(),
			Token:       unauthAt.GetToken(),
		}
		requestContext = context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
		ctx = requestauth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kmsCache, &requestInfo)

		_, err = s.ListAccounts(ctx, &pbs.ListAccountsRequest{
			AuthMethodId: authMethod.GetPublicId(),
		})
		require.Error(t, err)
		assert.Equal(t, handlers.ForbiddenError(), err)
	})

	t.Run("ldap", func(t *testing.T) {
		o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
		databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
		require.NoError(t, err)
		authMethod := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://some-accounts"})

		var accounts []*pb.Account
		for i := 0; i < 9; i++ {
			loginName := fmt.Sprintf("test-login-name%d", i)
			aa := ldap.TestAccount(t, conn, authMethod, loginName)
			accounts = append(accounts, &pb.Account{
				Id:           aa.GetPublicId(),
				AuthMethodId: aa.GetAuthMethodId(),
				CreatedTime:  aa.GetCreateTime().GetTimestamp(),
				UpdatedTime:  aa.GetUpdateTime().GetTimestamp(),
				Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
				Version:      1,
				Type:         ldap.Subtype.String(),
				Attrs: &pb.Account_LdapAccountAttributes{
					LdapAccountAttributes: &pb.LdapAccountAttributes{
						LoginName: loginName,
					},
				},
				AuthorizedActions: ldapAuthorizedActions,
			})
		}

		acct := ldap.TestAccount(t, conn, authMethod, "test-login-last")
		u := iam.TestUser(t, iamRepo, o.GetPublicId(), iam.WithAccountIds(acct.PublicId))

		privProjRole := iam.TestRole(t, conn, pwt.GetPublicId())
		iam.TestRoleGrant(t, conn, privProjRole.GetPublicId(), "ids=*;type=*;actions=*")
		iam.TestUserRole(t, conn, privProjRole.GetPublicId(), u.GetPublicId())
		privOrgRole := iam.TestRole(t, conn, o.GetPublicId())
		iam.TestRoleGrant(t, conn, privOrgRole.GetPublicId(), "ids=*;type=*;actions=*")
		iam.TestUserRole(t, conn, privOrgRole.GetPublicId(), u.GetPublicId())

		accounts = append(accounts, &pb.Account{
			Id:           acct.GetPublicId(),
			AuthMethodId: acct.GetAuthMethodId(),
			CreatedTime:  acct.GetCreateTime().GetTimestamp(),
			UpdatedTime:  acct.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         ldap.Subtype.String(),
			Attrs: &pb.Account_LdapAccountAttributes{
				LdapAccountAttributes: &pb.LdapAccountAttributes{
					LoginName: "test-login-last",
				},
			},
			AuthorizedActions: ldapAuthorizedActions,
		})

		// Since we sort by created_time descending, we reverse the slice
		slices.Reverse(accounts)

		at, _ := tokenRepo.CreateAuthToken(ctx, u, acct.GetPublicId())

		requestInfo := authpb.RequestInfo{
			TokenFormat: uint32(requestauth.AuthTokenTypeBearer),
			PublicId:    at.GetPublicId(),
			Token:       at.GetToken(),
		}
		requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
		ctx = requestauth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kmsCache, &requestInfo)

		req := &pbs.ListAccountsRequest{
			AuthMethodId: authMethod.GetPublicId(),
			Filter:       "",
			ListToken:    "",
			PageSize:     2,
		}

		// Run analyze in the DB to update the estimate tables
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		got, err := s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 2)

		// all comparisons will be done without list token
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        accounts[0:2],
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)

		// second page
		req.ListToken = got.ListToken
		got, err = s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 2)

		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        accounts[2:4],
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)

		// remainder of results
		req.ListToken = got.ListToken
		req.PageSize = 6
		got, err = s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 6)

		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        accounts[4:],
					ResponseType: "complete",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)

		// create another acct
		aa := ldap.TestAccount(t, conn, authMethod, "test-login-new-last")
		newAccount := &pb.Account{
			Id:           aa.GetPublicId(),
			AuthMethodId: aa.GetAuthMethodId(),
			CreatedTime:  aa.GetCreateTime().GetTimestamp(),
			UpdatedTime:  aa.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         ldap.Subtype.String(),
			Attrs: &pb.Account_LdapAccountAttributes{
				LdapAccountAttributes: &pb.LdapAccountAttributes{
					LoginName: "test-login-new-last",
				},
			},
			AuthorizedActions: ldapAuthorizedActions,
		}
		// Add to front since it's the latest updated
		accounts = append([]*pb.Account{newAccount}, accounts...)

		// delete different acct
		_, err = ldapRepo.DeleteAccount(ctx, accounts[len(accounts)-1].Id)
		require.NoError(t, err)
		deletedAccount := accounts[len(accounts)-1]
		accounts = accounts[:len(accounts)-1]

		// update another acct
		accounts[1].Name = wrapperspb.String("new-name")
		accounts[1].Version = 2
		a := &ldap.Account{
			Account: &ldapstore.Account{
				PublicId:     accounts[1].Id,
				AuthMethodId: accounts[1].AuthMethodId,
				Name:         accounts[1].Name.GetValue(),
				ScopeId:      accounts[1].Scope.Id,
			},
		}
		ua, _, err := ldapRepo.UpdateAccount(ctx, o.GetPublicId(), a, 1, []string{"name"})
		require.NoError(t, err)
		accounts[1].UpdatedTime = ua.GetUpdateTime().GetTimestamp()
		accounts[1].Version = ua.GetVersion()
		// Add to the front since it's most recently updated
		accounts = append(
			[]*pb.Account{accounts[1]},
			append(
				[]*pb.Account{accounts[0]},
				accounts[2:]...,
			)...,
		)

		// Run analyze to update postgres estimates
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request updated results
		req.ListToken = got.ListToken
		req.PageSize = 1
		got, err = s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        []*pb.Account{accounts[0]},
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "updated_time",
					SortDir:      "desc",
					RemovedIds:   []string{deletedAccount.Id},
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)

		// Get next page
		req.ListToken = got.ListToken
		got, err = s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        []*pb.Account{accounts[1]},
					ResponseType: "complete",
					ListToken:    "",
					SortBy:       "updated_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)

		// Request new page with filter requiring looping
		// to fill the page.
		req.ListToken = ""
		req.PageSize = 1
		req.Filter = fmt.Sprintf(`"/item/id"==%q or "/item/id"==%q`, accounts[len(accounts)-2].Id, accounts[len(accounts)-1].Id)
		got, err = s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        []*pb.Account{accounts[len(accounts)-2]},
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					// Should be empty again
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)
		req.ListToken = got.ListToken
		// Get the second page
		got, err = s.ListAccounts(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListAccountsResponse{
					Items:        []*pb.Account{accounts[len(accounts)-1]},
					ResponseType: "complete",
					ListToken:    "",
					SortBy:       "created_time",
					SortDir:      "desc",
					RemovedIds:   nil,
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListAccountsResponse{}, "list_token"),
			),
		)

		// Create unauthenticated user
		unauthAt := authtoken.TestAuthToken(t, conn, kmsCache, o.GetPublicId())
		unauthR := iam.TestRole(t, conn, pwt.GetPublicId())
		_ = iam.TestUserRole(t, conn, unauthR.GetPublicId(), unauthAt.GetIamUserId())

		// Make a request with the unauthenticated user,
		// ensure the response is 403 forbidden.
		requestInfo = authpb.RequestInfo{
			TokenFormat: uint32(requestauth.AuthTokenTypeBearer),
			PublicId:    unauthAt.GetPublicId(),
			Token:       unauthAt.GetToken(),
		}
		requestContext = context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
		ctx = requestauth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kmsCache, &requestInfo)

		_, err = s.ListAccounts(ctx, &pbs.ListAccountsRequest{
			AuthMethodId: authMethod.GetPublicId(),
		})
		require.Error(t, err)
		assert.Equal(t, handlers.ForbiddenError(), err)
	})
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kmsCache)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kmsCache)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kmsCache)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	am1 := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	ac := password.TestAccount(t, conn, am1.GetPublicId(), "name1")

	databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	oidcAm := oidc.TestAuthMethod(
		t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	oidcA := oidc.TestAccount(t, conn, oidcAm, "test-subject")

	ldapAm := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://ldap1"})
	ldapAcct := ldap.TestAccount(t, conn, ldapAm, "test-account")

	s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err, "Error when getting new user service.")

	cases := []struct {
		name        string
		scope       string
		req         *pbs.DeleteAccountRequest
		res         *pbs.DeleteAccountResponse
		err         error
		errContains string
	}{
		{
			name: "Delete an existing pw account",
			req: &pbs.DeleteAccountRequest{
				Id: ac.GetPublicId(),
			},
		},
		{
			name: "Delete an existing oidc account",
			req: &pbs.DeleteAccountRequest{
				Id: oidcA.GetPublicId(),
			},
		},
		{
			name: "Delete an existing ldap account",
			req: &pbs.DeleteAccountRequest{
				Id: ldapAcct.GetPublicId(),
			},
		},
		{
			name: "Delete bad old pw account id",
			req: &pbs.DeleteAccountRequest{
				Id: globals.PasswordAccountPreviousPrefix + "_doesntexis",
			},
			err:         handlers.ApiErrorWithCode(codes.NotFound),
			errContains: "Resource not found.",
		},
		{
			name: "Delete bad new pw account id",
			req: &pbs.DeleteAccountRequest{
				Id: globals.PasswordAccountPrefix + "_doesntexis",
			},
			err:         handlers.ApiErrorWithCode(codes.NotFound),
			errContains: "Resource not found.",
		},
		{
			name: "Delete bad oidc account id",
			req: &pbs.DeleteAccountRequest{
				Id: globals.OidcAccountPrefix + "_doesntexis",
			},
			err:         handlers.ApiErrorWithCode(codes.NotFound),
			errContains: "Resource not found.",
		},
		{
			name: "Delete bad ldap account id",
			req: &pbs.DeleteAccountRequest{
				Id: globals.LdapAccountPrefix + "_doesntexis",
			},
			err:         handlers.ApiErrorWithCode(codes.NotFound),
			errContains: "Resource not found.",
		},
		{
			name: "Bad account id formatting",
			req: &pbs.DeleteAccountRequest{
				Id: "bad_format",
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "Incorrectly formatted identifier.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteAccount(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteAccount(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				require.NotEmpty(tc.errContains)
				assert.Contains(gErr.Error(), tc.errContains)
			}
			assert.EqualValuesf(tc.res, got, "DeleteAccount(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	ctx := context.TODO()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kms)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kms)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kms)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	ac := password.TestAccount(t, conn, am.GetPublicId(), "name1")

	s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(err, "Error when getting new user service")
	req := &pbs.DeleteAccountRequest{
		Id: ac.GetPublicId(),
	}
	_, gErr := s.DeleteAccount(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteAccount(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected not found for the second delete.")
}

func TestCreatePassword(t *testing.T) {
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kms)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kms)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kms)
	}

	s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err, "Error when getting new account service.")

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	defaultAccount := password.TestAccount(t, conn, am.GetPublicId(), "name1")
	defaultCreated := defaultAccount.GetCreateTime().GetTimestamp()
	require.NoError(t, err, "Error converting proto to timestamp.")

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
					Attrs: &pb.Account_PasswordAccountAttributes{
						PasswordAccountAttributes: &pb.PasswordAccountAttributes{
							LoginName: "validaccount",
							Password:  nil,
						},
					},
				},
			},
			res: &pbs.CreateAccountResponse{
				Uri: fmt.Sprintf("accounts/%s_", globals.PasswordAccountPrefix),
				Item: &pb.Account{
					AuthMethodId: defaultAccount.GetAuthMethodId(),
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Version:      1,
					Type:         "password",
					Attrs: &pb.Account_PasswordAccountAttributes{
						PasswordAccountAttributes: &pb.PasswordAccountAttributes{
							LoginName: "validaccount",
							Password:  nil,
						},
					},
					AuthorizedActions: pwAuthorizedActions,
				},
			},
		},
		{
			name: "Create a valid Account without type defined",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: defaultAccount.GetAuthMethodId(),
					Attrs: &pb.Account_PasswordAccountAttributes{
						PasswordAccountAttributes: &pb.PasswordAccountAttributes{
							LoginName: "notypedefined",
							Password:  nil,
						},
					},
				},
			},
			res: &pbs.CreateAccountResponse{
				Uri: fmt.Sprintf("accounts/%s_", globals.PasswordAccountPrefix),
				Item: &pb.Account{
					AuthMethodId: defaultAccount.GetAuthMethodId(),
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Version:      1,
					Type:         "password",
					Attrs: &pb.Account_PasswordAccountAttributes{
						PasswordAccountAttributes: &pb.PasswordAccountAttributes{
							LoginName: "notypedefined",
							Password:  nil,
						},
					},
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
					Attrs: &pb.Account_PasswordAccountAttributes{
						PasswordAccountAttributes: &pb.PasswordAccountAttributes{
							LoginName: "haspassword",
							Password:  &wrapperspb.StringValue{Value: "somepassword"},
						},
					},
				},
			},
			res: &pbs.CreateAccountResponse{
				Uri: fmt.Sprintf("accounts/%s_", globals.PasswordAccountPrefix),
				Item: &pb.Account{
					AuthMethodId: defaultAccount.GetAuthMethodId(),
					Name:         &wrapperspb.StringValue{Value: "name_with_password"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Version:      1,
					Type:         "password",
					Attrs: &pb.Account_PasswordAccountAttributes{
						PasswordAccountAttributes: &pb.PasswordAccountAttributes{
							LoginName: "haspassword",
							Password:  nil,
						},
					},
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
					Attrs: &pb.Account_PasswordAccountAttributes{
						PasswordAccountAttributes: &pb.PasswordAccountAttributes{
							LoginName: "nopwprovided",
							Password:  nil,
						},
					},
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
					Id:           globals.PasswordAccountPrefix + "_notallowed",
					Type:         "password",
					Attrs: &pb.Account_PasswordAccountAttributes{
						PasswordAccountAttributes: &pb.PasswordAccountAttributes{
							LoginName: "cantprovideid",
							Password:  nil,
						},
					},
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
					Attrs: &pb.Account_PasswordAccountAttributes{
						PasswordAccountAttributes: &pb.PasswordAccountAttributes{
							LoginName: "nocreatedtime",
							Password:  nil,
						},
					},
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
					Attrs: &pb.Account_PasswordAccountAttributes{
						PasswordAccountAttributes: &pb.PasswordAccountAttributes{
							LoginName: "noupdatetime",
							Password:  nil,
						},
					},
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
			got, gErr := s.CreateAccount(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateAccount(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			} else {
				require.NoError(gErr)
			}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				assert.True(strings.HasPrefix(got.GetItem().GetId(), globals.PasswordAccountPrefix+"_"))
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
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "CreateAccount(%q) got response %q, wanted %q", tc.req, got, tc.res)
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
		return password.NewRepository(ctx, rw, rw, kmsCache)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kmsCache)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kmsCache)
	}

	s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
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
					Type:         oidc.Subtype.String(),
					Attrs: &pb.Account_OidcAccountAttributes{
						OidcAccountAttributes: &pb.OidcAccountAttributes{
							Subject: "valid-account",
						},
					},
				},
			},
			res: &pbs.CreateAccountResponse{
				Uri: fmt.Sprintf("accounts/%s_", globals.OidcAccountPrefix),
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Version:      1,
					Type:         oidc.Subtype.String(),
					Attrs: &pb.Account_OidcAccountAttributes{
						OidcAccountAttributes: &pb.OidcAccountAttributes{
							Subject: "valid-account",
							Issuer:  am.GetIssuer(),
						},
					},
					AuthorizedActions: oidcAuthorizedActions,
				},
			},
		},
		{
			name: "Create a valid Account with IPv6 issuer address",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "name-ipv6-iss"},
					Description:  &wrapperspb.StringValue{Value: "desc-ipv6-iss"},
					Type:         oidc.Subtype.String(),
					Attrs: &pb.Account_OidcAccountAttributes{
						OidcAccountAttributes: &pb.OidcAccountAttributes{
							Issuer:  "https://[2001:BEEF:0000:0000:0000:0000:0000:0001]:44344/v1/myissuer",
							Subject: "valid-account-ipv6-iss",
						},
					},
				},
			},
			res: &pbs.CreateAccountResponse{
				Uri: fmt.Sprintf("accounts/%s_", globals.OidcAccountPrefix),
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "name-ipv6-iss"},
					Description:  &wrapperspb.StringValue{Value: "desc-ipv6-iss"},
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Version:      1,
					Type:         oidc.Subtype.String(),
					Attrs: &pb.Account_OidcAccountAttributes{
						OidcAccountAttributes: &pb.OidcAccountAttributes{
							Subject: "valid-account-ipv6-iss",
							Issuer:  "https://[2001:beef::1]:44344/v1/myissuer",
						},
					},
					AuthorizedActions: oidcAuthorizedActions,
				},
			},
		},
		{
			name: "Create a valid Account without type defined",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Attrs: &pb.Account_OidcAccountAttributes{
						OidcAccountAttributes: &pb.OidcAccountAttributes{
							Subject: "no type defined",
						},
					},
				},
			},
			res: &pbs.CreateAccountResponse{
				Uri: fmt.Sprintf("accounts/%s_", globals.OidcAccountPrefix),
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Version:      1,
					Type:         oidc.Subtype.String(),
					Attrs: &pb.Account_OidcAccountAttributes{
						OidcAccountAttributes: &pb.OidcAccountAttributes{
							Subject: "no type defined",
							Issuer:  am.GetIssuer(),
						},
					},
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
					Type:         oidc.Subtype.String(),
					Attrs: &pb.Account_OidcAccountAttributes{
						OidcAccountAttributes: &pb.OidcAccountAttributes{
							Subject: "overwritten-issuer",
							Issuer:  "https://overwrite.com",
						},
					},
				},
			},
			res: &pbs.CreateAccountResponse{
				Uri: fmt.Sprintf("accounts/%s_", globals.OidcAccountPrefix),
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "overwritten issuer"},
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Version:      1,
					Type:         oidc.Subtype.String(),
					Attrs: &pb.Account_OidcAccountAttributes{
						OidcAccountAttributes: &pb.OidcAccountAttributes{
							Subject: "overwritten-issuer",
							Issuer:  "https://overwrite.com",
						},
					},
					AuthorizedActions: oidcAuthorizedActions,
				},
			},
		},
		{
			name: "Cant specify mismatching type",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Type:         password.Subtype.String(),
					Attrs: &pb.Account_OidcAccountAttributes{
						OidcAccountAttributes: &pb.OidcAccountAttributes{
							Subject: "cant-specify-mismatching-type",
						},
					},
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
					Id:           globals.OidcAccountPrefix + "_notallowed",
					Type:         oidc.Subtype.String(),
					Attrs: &pb.Account_OidcAccountAttributes{
						OidcAccountAttributes: &pb.OidcAccountAttributes{
							Subject: "cant-specify-id",
						},
					},
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
					Type:         oidc.Subtype.String(),
					Attrs: &pb.Account_OidcAccountAttributes{
						OidcAccountAttributes: &pb.OidcAccountAttributes{
							Subject: "cant-specify-created-time",
						},
					},
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
					Type:         oidc.Subtype.String(),
					Attrs: &pb.Account_OidcAccountAttributes{
						OidcAccountAttributes: &pb.OidcAccountAttributes{
							Subject: "cant-specify-update-time",
						},
					},
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
					Type:         oidc.Subtype.String(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Malformed issuer url",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "name-ipv6-iss"},
					Description:  &wrapperspb.StringValue{Value: "desc-ipv6-iss"},
					Type:         oidc.Subtype.String(),
					Attrs: &pb.Account_OidcAccountAttributes{
						OidcAccountAttributes: &pb.OidcAccountAttributes{
							Issuer:  "https://2000:0005::0001]", // missing '[' after https://
							Subject: "valid-account-ipv6-iss",
						},
					},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, `Error: "Error in provided request.", Details: {{name: "attributes.issuer", desc: "Cannot be parsed as a url. parse \"https://2000:0005::0001]\": invalid port \":0001]\" after host"}}`),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.CreateAccount(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateAccount(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				assert.True(strings.HasPrefix(got.GetItem().GetId(), globals.OidcAccountPrefix+"_"))
				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "CreateAccount(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestCreateLdap(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kmsCache)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kmsCache)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kmsCache)
	}

	s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err, "Error when getting new account service.")

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	am := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://ldap1"})

	cases := []struct {
		name        string
		req         *pbs.CreateAccountRequest
		res         *pbs.CreateAccountResponse
		err         error
		errContains string
	}{
		{
			name: "Create a valid Account",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					Type:         ldap.Subtype.String(),
					Attrs: &pb.Account_LdapAccountAttributes{
						LdapAccountAttributes: &pb.LdapAccountAttributes{
							LoginName: "valid-account",
						},
					},
				},
			},
			res: &pbs.CreateAccountResponse{
				Uri: fmt.Sprintf("accounts/%s_", globals.LdapAccountPrefix),
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Version:      1,
					Type:         ldap.Subtype.String(),
					Attrs: &pb.Account_LdapAccountAttributes{
						LdapAccountAttributes: &pb.LdapAccountAttributes{
							LoginName: "valid-account",
						},
					},
					AuthorizedActions: ldapAuthorizedActions,
				},
			},
		},
		{
			name: "Create a valid Account without type defined",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Attrs: &pb.Account_LdapAccountAttributes{
						LdapAccountAttributes: &pb.LdapAccountAttributes{
							LoginName: "no type defined",
						},
					},
				},
			},
			res: &pbs.CreateAccountResponse{
				Uri: fmt.Sprintf("accounts/%s_", globals.LdapAccountPrefix),
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Version:      1,
					Type:         ldap.Subtype.String(),
					Attrs: &pb.Account_LdapAccountAttributes{
						LdapAccountAttributes: &pb.LdapAccountAttributes{
							LoginName: "no type defined",
						},
					},
					AuthorizedActions: ldapAuthorizedActions,
				},
			},
		},
		{
			name: "Cant specify mismatching type",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Type:         password.Subtype.String(),
					Attrs: &pb.Account_LdapAccountAttributes{
						LdapAccountAttributes: &pb.LdapAccountAttributes{
							LoginName: "cant-specify-mismatching-type",
						},
					},
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "Doesn't match the parent resource's type",
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Id:           globals.LdapAccountPrefix + "_notallowed",
					Type:         ldap.Subtype.String(),
					Attrs: &pb.Account_LdapAccountAttributes{
						LdapAccountAttributes: &pb.LdapAccountAttributes{
							LoginName: "cant-specify-mismatching-type",
						},
					},
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"id\", desc: \"This is a read only field.\"",
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					CreatedTime:  timestamppb.Now(),
					Type:         oidc.Subtype.String(),
					Attrs: &pb.Account_LdapAccountAttributes{
						LdapAccountAttributes: &pb.LdapAccountAttributes{
							LoginName: "cant-specify-mismatching-type",
						},
					},
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"created_time\", desc: \"This is a read only field.\"",
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					UpdatedTime:  timestamppb.Now(),
					Type:         ldap.Subtype.String(),
					Attrs: &pb.Account_LdapAccountAttributes{
						LdapAccountAttributes: &pb.LdapAccountAttributes{
							LoginName: "cant-specify-mismatching-type",
						},
					},
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"updated_time\", desc: \"This is a read only field.\"",
		},
		{
			name: "Must specify login name",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Type:         ldap.Subtype.String(),
					Attrs: &pb.Account_LdapAccountAttributes{
						LdapAccountAttributes: &pb.LdapAccountAttributes{},
					},
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"attributes.login_name\", desc: \"This is a required field for this type.",
		},
		{
			name: "Can't specify full name",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Type:         ldap.Subtype.String(),
					Attrs: &pb.Account_LdapAccountAttributes{
						LdapAccountAttributes: &pb.LdapAccountAttributes{
							LoginName: "cant-specify-full-name",
							FullName:  "something",
						},
					},
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"attributes.full_name\", desc: \"This is a read only field.\"",
		},
		{
			name: "Can't specify email",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Type:         ldap.Subtype.String(),
					Attrs: &pb.Account_LdapAccountAttributes{
						LdapAccountAttributes: &pb.LdapAccountAttributes{
							LoginName: "cant-specify-email",
							Email:     "something",
						},
					},
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"attributes.email\", desc: \"This is a read only field.\"",
		},
		{
			name: "Can't specify dn",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Type:         ldap.Subtype.String(),
					Attrs: &pb.Account_LdapAccountAttributes{
						LdapAccountAttributes: &pb.LdapAccountAttributes{
							LoginName: "cant-specify-dn",
							Dn:        "something",
						},
					},
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"attributes.dn\", desc: \"This is a read only field.\"",
		},
		{
			name: "Can't specify member of groups",
			req: &pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Type:         ldap.Subtype.String(),
					Attrs: &pb.Account_LdapAccountAttributes{
						LdapAccountAttributes: &pb.LdapAccountAttributes{
							LoginName:      "cant-specify-member-of",
							MemberOfGroups: []string{"something"},
						},
					},
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"attributes.member_of_groups\", desc: \"This is a read only field.\"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.CreateAccount(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateAccount(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				require.NotEmpty(tc.errContains)
				assert.Contains(gErr.Error(), tc.errContains)
				return
			}
			require.NoError(gErr)
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				assert.True(strings.HasPrefix(got.GetItem().GetId(), globals.LdapAccountPrefix+"_"))
				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "CreateAccount(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestUpdatePassword(t *testing.T) {
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kms)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kms)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kms)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	tested, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err, "Error when getting new accounts service.")

	defaultScopeInfo := &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType(), ParentScopeId: scope.Global.String()}
	defaultAttributes := &pb.Account_PasswordAccountAttributes{
		PasswordAccountAttributes: &pb.PasswordAccountAttributes{
			LoginName: "default",
		},
	}
	modifiedAttributes := &pb.Account_PasswordAccountAttributes{
		PasswordAccountAttributes: &pb.PasswordAccountAttributes{
			LoginName: "modified",
		},
	}

	freshAccount := func(t *testing.T) (*pb.Account, func()) {
		t.Helper()
		acc, err := tested.CreateAccount(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()),
			&pbs.CreateAccountRequest{
				Item: &pb.Account{
					AuthMethodId: am.GetPublicId(),
					Name:         wrapperspb.String("default"),
					Description:  wrapperspb.String("default"),
					Type:         "password",
					Attrs:        defaultAttributes,
				},
			},
		)
		require.NoError(t, err)

		clean := func() {
			_, err := tested.DeleteAccount(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()),
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
					Attrs:             defaultAttributes,
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
					Attrs:             defaultAttributes,
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
					Attrs:       modifiedAttributes,
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
					Attrs:       modifiedAttributes,
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Only non-existent paths in Mask",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistent_field"}},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
					Attrs:       modifiedAttributes,
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
					Attrs:       modifiedAttributes,
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Description:       &wrapperspb.StringValue{Value: "default"},
					Type:              "password",
					Attrs:             defaultAttributes,
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
					Attrs:       modifiedAttributes,
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "updated"},
					Description:       &wrapperspb.StringValue{Value: "default"},
					Type:              "password",
					Attrs:             defaultAttributes,
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
					Attrs:       modifiedAttributes,
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "default"},
					Description:       &wrapperspb.StringValue{Value: "notignored"},
					Type:              "password",
					Attrs:             defaultAttributes,
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
					Attrs:       modifiedAttributes,
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "default"},
					Description:       &wrapperspb.StringValue{Value: "default"},
					Type:              "password",
					Attrs:             modifiedAttributes,
					Scope:             defaultScopeInfo,
					AuthorizedActions: pwAuthorizedActions,
				},
			},
		},
		{
			name: "Update a Non Existing Old ID Account",
			req: &pbs.UpdateAccountRequest{
				Id: globals.PasswordAccountPreviousPrefix + "_DoesntExis",
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
			name: "Update a Non Existing New ID Account",
			req: &pbs.UpdateAccountRequest{
				Id: globals.PasswordAccountPrefix + "_DoesntExis",
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
					Id:          globals.PasswordAccountPrefix + "_somethinge",
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

			got, gErr := tested.UpdateAccount(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateAccount(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			} else {
				require.NoError(gErr)
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
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "UpdateAccount(%q) got response %q, wanted %q", tc.req, got, tc.res)
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
		return password.NewRepository(ctx, rw, rw, kmsCache)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kmsCache)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kmsCache)
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

	tested, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err, "Error when getting new auth_method service.")

	defaultScopeInfo := &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType(), ParentScopeId: scope.Global.String()}
	defaultAttributes := &pb.Account_OidcAccountAttributes{
		OidcAccountAttributes: &pb.OidcAccountAttributes{
			Issuer:  "https://www.alice.com",
			Subject: "test-subject",
		},
	}
	modifiedAttributes := &pb.Account_OidcAccountAttributes{
		OidcAccountAttributes: &pb.OidcAccountAttributes{
			Issuer:  "https://www.changed.com",
			Subject: "changed",
		},
	}

	freshAccount := func(t *testing.T) (*oidc.Account, func()) {
		t.Helper()
		acc := oidc.TestAccount(t, conn, am, "test-subject", oidc.WithName("default"), oidc.WithDescription("default"))

		clean := func() {
			_, err := tested.DeleteAccount(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()),
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
					Type:        oidc.Subtype.String(),
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "new"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					Type:              oidc.Subtype.String(),
					Attrs:             defaultAttributes,
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
					Type:        oidc.Subtype.String(),
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "new"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					Type:              oidc.Subtype.String(),
					Attrs:             defaultAttributes,
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
					Attrs:       modifiedAttributes,
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
					Attrs:       modifiedAttributes,
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Only non-existent paths in Mask",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistent_field"}},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
					Attrs:       modifiedAttributes,
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
					Attrs:       modifiedAttributes,
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Description:       &wrapperspb.StringValue{Value: "default"},
					Type:              oidc.Subtype.String(),
					Attrs:             defaultAttributes,
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
					Attrs:       modifiedAttributes,
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "updated"},
					Description:       &wrapperspb.StringValue{Value: "default"},
					Type:              oidc.Subtype.String(),
					Attrs:             defaultAttributes,
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
					Attrs:       modifiedAttributes,
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "default"},
					Description:       &wrapperspb.StringValue{Value: "notignored"},
					Type:              oidc.Subtype.String(),
					Attrs:             defaultAttributes,
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
					Attrs:       modifiedAttributes,
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Update a Non Existing Account",
			req: &pbs.UpdateAccountRequest{
				Id: globals.PasswordAccountPrefix + "_DoesntExis",
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
					Id:          globals.PasswordAccountPrefix + "_somethinge",
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
					Name:  &wrapperspb.StringValue{Value: "ignored"},
					Attrs: modifiedAttributes,
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
					Name:  &wrapperspb.StringValue{Value: "ignored"},
					Attrs: modifiedAttributes,
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

			got, gErr := tested.UpdateAccount(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
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
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "UpdateAccount(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestUpdateLdap(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kmsCache)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kmsCache)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kmsCache)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))

	databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	am := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://ldap"})

	tested, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err, "Error when getting new auth_method service.")

	defaultScopeInfo := &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType(), ParentScopeId: scope.Global.String()}
	defaultAttributes := &pb.Account_LdapAccountAttributes{
		LdapAccountAttributes: &pb.LdapAccountAttributes{
			LoginName: "test-login",
		},
	}

	freshAccount := func(t *testing.T) (*ldap.Account, func()) {
		t.Helper()
		acc := ldap.TestAccount(t, conn, am, "test-login", ldap.WithName(ctx, "default"), ldap.WithDescription(ctx, "default"))

		clean := func() {
			_, err := tested.DeleteAccount(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()),
				&pbs.DeleteAccountRequest{Id: acc.GetPublicId()})
			require.NoError(t, err)
		}

		return acc, clean
	}

	cases := []struct {
		name        string
		req         *pbs.UpdateAccountRequest
		res         *pbs.UpdateAccountResponse
		err         error
		errContains string
	}{
		{
			name: "update-existing",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.NameField, globals.DescriptionField},
				},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        ldap.Subtype.String(),
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "new"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					Type:              ldap.Subtype.String(),
					Attrs:             defaultAttributes,
					Scope:             defaultScopeInfo,
					AuthorizedActions: ldapAuthorizedActions,
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
					Type:        ldap.Subtype.String(),
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "new"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					Type:              ldap.Subtype.String(),
					Attrs:             defaultAttributes,
					Scope:             defaultScopeInfo,
					AuthorizedActions: ldapAuthorizedActions,
				},
			},
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateAccountRequest{
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "UpdateMask not provided but is required to update this resource",
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
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "Cannot modify the resource type",
		},
		{
			name: "No Paths in Mask",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "missing mask",
		},
		{
			name: "Only non-existent paths in Mask",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistent_field"}},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "No valid fields included in the update mask",
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.NameField},
				},
				Item: &pb.Account{
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Description:       &wrapperspb.StringValue{Value: "default"},
					Type:              ldap.Subtype.String(),
					Attrs:             defaultAttributes,
					Scope:             defaultScopeInfo,
					AuthorizedActions: ldapAuthorizedActions,
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
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "updated"},
					Description:       &wrapperspb.StringValue{Value: "default"},
					Type:              ldap.Subtype.String(),
					Attrs:             defaultAttributes,
					Scope:             defaultScopeInfo,
					AuthorizedActions: ldapAuthorizedActions,
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
				},
			},
			res: &pbs.UpdateAccountResponse{
				Item: &pb.Account{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "default"},
					Description:       &wrapperspb.StringValue{Value: "notignored"},
					Type:              ldap.Subtype.String(),
					Attrs:             defaultAttributes,
					Scope:             defaultScopeInfo,
					AuthorizedActions: ldapAuthorizedActions,
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
				},
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "Field cannot be updated.",
		},
		{
			name: "Update a Non Existing Account",
			req: &pbs.UpdateAccountRequest{
				Id: globals.LdapAccountPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.DescriptionField},
				},
				Item: &pb.Account{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			err:         handlers.ApiErrorWithCode(codes.NotFound),
			errContains: "Resource not found.",
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.Account{
					Id:          globals.LdapAccountPrefix + "_somethinge",
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "new desc"},
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"id\", desc: \"This is a read only field and cannot be specified in an update request.",
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
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"created_time\", desc: \"This is a read only field and cannot be specified in an update request.",
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
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"updated_time\", desc: \"This is a read only field and cannot be specified in an update request.",
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
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"type\", desc: \"Cannot modify the resource type.",
		},
		{
			name: "Update Login name",
			req: &pbs.UpdateAccountRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.login_name"},
				},
				Item: &pb.Account{
					Name: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"attributes.login_name\", desc: \"Field cannot be updated.",
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

			got, gErr := tested.UpdateAccount(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateAccount(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				require.NotEmpty(tc.errContains)
				assert.Contains(gErr.Error(), tc.errContains)
				return
			}

			require.NoError(gErr)

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
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "UpdateAccount(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestSetPassword(t *testing.T) {
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kms)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kms)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kms)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	tested, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err, "Error when getting new auth_method service.")

	createAccount := func(t *testing.T, pw string) *pb.Account {
		am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
		pwAttrs := &pb.Account_PasswordAccountAttributes{
			PasswordAccountAttributes: &pb.PasswordAccountAttributes{
				LoginName: "testusername",
			},
		}
		if pw != "" {
			pwAttrs.PasswordAccountAttributes.Password = wrapperspb.String(pw)
		}
		createResp, err := tested.CreateAccount(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), &pbs.CreateAccountRequest{
			Item: &pb.Account{
				AuthMethodId: am.GetPublicId(),
				Type:         "password",
				Attrs:        pwAttrs,
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

			setResp, err := tested.SetPassword(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), &pbs.SetPasswordRequest{
				Id:       acct.GetId(),
				Version:  acct.GetVersion(),
				Password: tt.newPw,
			})
			require.NoError(err)
			assert.Equal(acct.GetVersion()+1, setResp.GetItem().GetVersion())
			// clear uncomparable fields
			acct.Version, setResp.GetItem().Version = 0, 0
			acct.UpdatedTime, setResp.GetItem().UpdatedTime = nil, nil

			assert.Empty(cmp.Diff(
				acct,
				setResp.GetItem(),
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			))
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
		{
			name:      "notfound old account id",
			accountId: globals.PasswordAccountPreviousPrefix + "_DoesntExis",
			version:   defaultAcct.GetVersion(),
			password:  "anewpassword",
		},
		{
			name:      "notfound new account id",
			accountId: globals.PasswordAccountPrefix + "_DoesntExis",
			version:   defaultAcct.GetVersion(),
			password:  "anewpassword",
		},
		{
			name:      "password too short",
			accountId: defaultAcct.GetId(),
			version:   defaultAcct.GetVersion(),
			password:  "123",
		},
	}

	for _, tt := range badRequestCases {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			setResp, err := tested.SetPassword(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), &pbs.SetPasswordRequest{
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
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kms)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kms)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kms)
	}

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	tested, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err, "Error when getting new auth_method service.")

	createAccount := func(t *testing.T, pw string) *pb.Account {
		am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
		pwAttrs := &pb.Account_PasswordAccountAttributes{
			PasswordAccountAttributes: &pb.PasswordAccountAttributes{
				LoginName: "testusername",
			},
		}
		if pw != "" {
			pwAttrs.PasswordAccountAttributes.Password = wrapperspb.String(pw)
		}
		createResp, err := tested.CreateAccount(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), &pbs.CreateAccountRequest{
			Item: &pb.Account{
				AuthMethodId: am.GetPublicId(),
				Type:         "password",
				Attrs:        pwAttrs,
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

		changeResp, err := tested.ChangePassword(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), &pbs.ChangePasswordRequest{
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

		assert.Empty(cmp.Diff(
			acct,
			changeResp.GetItem(),
			protocmp.Transform(),
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
		))
	})

	t.Run("unauthenticated update", func(t *testing.T) {
		assert := assert.New(t)
		acct := createAccount(t, "originalpassword")

		changeResp, err := tested.ChangePassword(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), &pbs.ChangePasswordRequest{
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
		{
			name:         "notfound old account id",
			authMethodId: defaultAcct.GetAuthMethodId(),
			accountId:    globals.PasswordAccountPreviousPrefix + "_DoesntExis",
			version:      defaultAcct.GetVersion(),
			oldPW:        "somepassword",
			newPW:        "anewpassword",
		},
		{
			name:         "notfound new account id",
			authMethodId: defaultAcct.GetAuthMethodId(),
			accountId:    globals.PasswordAccountPrefix + "_DoesntExis",
			version:      defaultAcct.GetVersion(),
			oldPW:        "somepassword",
			newPW:        "anewpassword",
		},
		{
			name:         "new password too short",
			authMethodId: defaultAcct.GetAuthMethodId(),
			accountId:    defaultAcct.GetId(),
			version:      defaultAcct.GetVersion(),
			oldPW:        "somepassword",
			newPW:        "123",
		},
	}

	for _, tt := range badRequestCases {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			changeResp, err := tested.ChangePassword(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), &pbs.ChangePasswordRequest{
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

// The purpose of this test is mainly to ensure that we are properly fetching
// membership information in GrantsForUser across managed group types
func TestGrantsAcrossManagedGroups(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)

	org, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	oidcAm := oidc.TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	oidcAcct := oidc.TestAccount(t, conn, oidcAm, "test-subject")
	// Create a managed group that will always match, so we can test that it is
	// returned in results
	oidcMg := oidc.TestManagedGroup(t, conn, oidcAm, `"/token/sub" matches ".*"`)
	oidc.TestManagedGroupMember(t, conn, oidcMg.GetPublicId(), oidcAcct.GetPublicId())

	ldapAm := ldap.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
	ldapAcct := ldap.TestAccount(t, conn, ldapAm, "test-acct",
		ldap.WithMemberOfGroups(ctx, "admin"),
		ldap.WithFullName(ctx, "test-name"),
		ldap.WithEmail(ctx, "test-email"),
		ldap.WithDn(ctx, "test-dn"),
	)
	ldapMg := ldap.TestManagedGroup(t, conn, ldapAm, []string{"admin"})

	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kmsCache)
	}
	iamRepo, err := iamRepoFn()
	require.NoError(t, err)

	user := iam.TestUser(t, iamRepo, org.PublicId, iam.WithAccountIds(oidcAcct.GetPublicId(), ldapAcct.GetPublicId()))

	// Create two roles, each containing a single managed group, and add a
	// unique grant to each
	oidcRole := iam.TestRole(t, conn, org.GetPublicId(), iam.WithGrantScopeIds([]string{globals.GrantScopeChildren}))
	iam.TestManagedGroupRole(t, conn, oidcRole.GetPublicId(), oidcMg.GetPublicId())
	iam.TestRoleGrant(t, conn, oidcRole.GetPublicId(), "ids=ttcp_oidc;actions=read")
	ldapRole := iam.TestRole(t, conn, org.GetPublicId(), iam.WithGrantScopeIds([]string{globals.GrantScopeChildren}))
	iam.TestManagedGroupRole(t, conn, ldapRole.GetPublicId(), ldapMg.GetPublicId())
	iam.TestRoleGrant(t, conn, ldapRole.GetPublicId(), "ids=ttcp_ldap;actions=read")

	// targets must be in a project scope so we're passing in a scope ID which we expect the user to have access to
	// which is the project under the role's org
	grants, err := iamRepo.GrantsForUser(ctx, user.GetPublicId(), []resource.Type{resource.Target}, proj.PublicId)
	require.NoError(t, err)

	// Verify we see both grants
	var foundOidc, foundLdap bool
	for _, grant := range grants {
		if grant.Grant == "ids=ttcp_oidc;actions=read" {
			foundOidc = true
		}
		if grant.Grant == "ids=ttcp_ldap;actions=read" {
			foundLdap = true
		}
	}
	assert.True(t, foundOidc)
	assert.True(t, foundLdap)

	// Delete the ldap managed group
	ldapRepo, err := ldap.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	numDeleted, err := ldapRepo.DeleteManagedGroup(ctx, org.GetPublicId(), ldapMg.GetPublicId())
	require.NoError(t, err)
	assert.Equal(t, 1, numDeleted)

	// Verify we don't see the ldap grant anymore
	grants, err = iamRepo.GrantsForUser(ctx, user.GetPublicId(), []resource.Type{resource.Target}, proj.PublicId)
	require.NoError(t, err)
	foundOidc = false
	foundLdap = false
	for _, grant := range grants {
		if grant.Grant == "ids=ttcp_oidc;actions=read" {
			foundOidc = true
		}
		if grant.Grant == "ids=ttcp_ldap;actions=read" {
			foundLdap = true
		}
	}
	assert.True(t, foundOidc)
	assert.False(t, foundLdap)

	// Delete the oidc managed group
	oidcRepo, err := oidc.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	numDeleted, err = oidcRepo.DeleteManagedGroup(ctx, org.GetPublicId(), oidcMg.GetPublicId())
	require.NoError(t, err)
	assert.Equal(t, 1, numDeleted)

	// Verify we don't see the oidc grant anymore
	grants, err = iamRepo.GrantsForUser(ctx, user.GetPublicId(), []resource.Type{resource.Target}, proj.PublicId)
	require.NoError(t, err)
	foundOidc = false
	foundLdap = false
	for _, grant := range grants {
		if grant.Grant == "ids=ttcp_oidc;actions=read" {
			foundOidc = true
		}
		if grant.Grant == "ids=ttcp_ldap;actions=read" {
			foundLdap = true
		}
	}
	assert.False(t, foundOidc)
	assert.False(t, foundLdap)
}
