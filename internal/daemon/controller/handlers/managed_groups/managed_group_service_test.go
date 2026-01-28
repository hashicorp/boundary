// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package managed_groups_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
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
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/managed_groups"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/managedgroups"
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
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kmsCache)
	}

	cases := []struct {
		name            string
		oidcRepo        common.OidcAuthRepoFactory
		ldapRepo        common.LdapAuthRepoFactory
		wantErr         bool
		wantErrContains string
	}{
		{
			name:            "nil-oidc-repo",
			ldapRepo:        ldapRepoFn,
			wantErr:         true,
			wantErrContains: "missing oidc repository",
		},
		{
			name:            "missing-ldap-repo",
			oidcRepo:        oidcRepoFn,
			wantErr:         true,
			wantErrContains: "missing ldap repository",
		},
		{
			name:     "success",
			oidcRepo: oidcRepoFn,
			ldapRepo: ldapRepoFn,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := managed_groups.NewService(ctx, tc.oidcRepo, tc.ldapRepo, 1000)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrContains)
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

	s, err := managed_groups.NewService(ctx, oidcRepoFn, ldapRepoFn, 1000)
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
	oidcA := oidc.TestAccount(t, conn, oidcAm, "test-subject")
	oidcB := oidc.TestAccount(t, conn, oidcAm, "test-subject-2")
	omg := oidc.TestManagedGroup(t, conn, oidcAm, oidc.TestFakeManagedGroupFilter)

	// Set up managed group before getting. First get the current
	// managed group to make sure we have the right version, then ensure
	// the account is a member so we can test that return value.
	oidcRepo, err := oidcRepoFn()
	require.NoError(t, err)
	currMg, err := oidcRepo.LookupManagedGroup(ctx, omg.GetPublicId())
	require.NoError(t, err)
	_, _, err = oidcRepo.SetManagedGroupMemberships(ctx, oidcAm, oidcA, []*oidc.ManagedGroup{currMg})
	require.NoError(t, err)
	currMg, err = oidcRepo.LookupManagedGroup(ctx, omg.GetPublicId())
	require.NoError(t, err)
	_, _, err = oidcRepo.SetManagedGroupMemberships(ctx, oidcAm, oidcB, []*oidc.ManagedGroup{currMg})
	require.NoError(t, err)
	// Fetch the group once more to get the updated time
	currMg, err = oidcRepo.LookupManagedGroup(ctx, omg.GetPublicId())
	require.NoError(t, err)

	oidcWireManagedGroup := pb.ManagedGroup{
		Id:           omg.GetPublicId(),
		AuthMethodId: omg.GetAuthMethodId(),
		CreatedTime:  omg.GetCreateTime().GetTimestamp(),
		UpdatedTime:  currMg.GetUpdateTime().GetTimestamp(),
		Scope:        &scopepb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
		Version:      currMg.Version,
		Type:         "oidc",
		Attrs: &pb.ManagedGroup_OidcManagedGroupAttributes{
			OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
				Filter: omg.GetFilter(),
			},
		},
		AuthorizedActions: oidcAuthorizedActions,
		MemberIds:         []string{oidcA.GetPublicId(), oidcB.GetPublicId()},
	}

	ldapAm := ldap.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
	ldapAcct := ldap.TestAccount(t, conn, ldapAm, "test-login-name", ldap.WithMemberOfGroups(ctx, "admin"))
	ldapAcct2 := ldap.TestAccount(t, conn, ldapAm, "test-login-name-2", ldap.WithMemberOfGroups(ctx, "admin"))
	ldapMg := ldap.TestManagedGroup(t, conn, ldapAm, []string{"admin"})
	ldapWireManagedGroup := pb.ManagedGroup{
		Id:           ldapMg.GetPublicId(),
		AuthMethodId: ldapAm.GetPublicId(),
		CreatedTime:  ldapMg.GetCreateTime().GetTimestamp(),
		UpdatedTime:  ldapMg.GetUpdateTime().GetTimestamp(),
		Scope:        &scopepb.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
		Version:      ldapMg.GetVersion(),
		Type:         "ldap",
		Attrs: &pb.ManagedGroup_LdapManagedGroupAttributes{
			LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
				GroupNames: []string{"admin"},
			},
		},
		AuthorizedActions: ldapAuthorizedActions,
		MemberIds:         []string{ldapAcct.GetPublicId(), ldapAcct2.GetPublicId()},
	}

	cases := []struct {
		name        string
		req         *pbs.GetManagedGroupRequest
		res         *pbs.GetManagedGroupResponse
		err         error
		errContains string
	}{
		{
			name: "Get an oidc managed group",
			req:  &pbs.GetManagedGroupRequest{Id: oidcWireManagedGroup.GetId()},
			res:  &pbs.GetManagedGroupResponse{Item: &oidcWireManagedGroup},
		},
		{
			name:        "Get a non existing oidc managed group",
			req:         &pbs.GetManagedGroupRequest{Id: globals.OidcManagedGroupPrefix + "_DoesntExis"},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.NotFound),
			errContains: "Resource not found.",
		},
		{
			name: "Get an ldap managed group",
			req:  &pbs.GetManagedGroupRequest{Id: ldapWireManagedGroup.GetId()},
			res:  &pbs.GetManagedGroupResponse{Item: &ldapWireManagedGroup},
		},
		{
			name:        "space in id",
			req:         &pbs.GetManagedGroupRequest{Id: globals.AuthTokenPrefix + "_1 23456789"},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "Invalid formatted identifier",
		},
		{
			name:        "Get a non existing ldap managed group",
			req:         &pbs.GetManagedGroupRequest{Id: globals.LdapManagedGroupPrefix + "_DoesntExis"},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.NotFound),
			errContains: "Resource not found.",
		},
		{
			name:        "Wrong id prefix",
			req:         &pbs.GetManagedGroupRequest{Id: "j_1234567890"},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "Invalid formatted identifier.",
		},
		{
			name:        "space in id",
			req:         &pbs.GetManagedGroupRequest{Id: globals.AuthTokenPrefix + "_1 23456789"},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "Invalid formatted identifier.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.GetManagedGroup(auth.DisabledAuthTestContext(iamRepoFn, org.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetManagedGroup(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				require.NotEmpty(tc.errContains)
				assert.Contains(gErr.Error(), tc.errContains)
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
			), "GetManagedGroup(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestListOidc(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
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
	amNoManagedGroups := oidc.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState, "noManagedGroups", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.nomanagedgroups.com")[0]), oidc.WithSigningAlgs(oidc.RS256), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]))
	amSomeManagedGroups := oidc.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState, "someManagedGroups", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.somemanagedgroups.com")[0]), oidc.WithSigningAlgs(oidc.RS256), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]))
	amOtherManagedGroups := oidc.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState, "otherManagedGroups", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.othermanagedgroups.com")[0]), oidc.WithSigningAlgs(oidc.RS256), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]))

	var wantSomeManagedGroups []*pb.ManagedGroup
	for i := 0; i < 3; i++ {
		mg := oidc.TestManagedGroup(t, conn, amSomeManagedGroups, oidc.TestFakeManagedGroupFilter, oidc.WithName(strconv.Itoa(i)))
		wantSomeManagedGroups = append(wantSomeManagedGroups, &pb.ManagedGroup{
			Id:           mg.GetPublicId(),
			AuthMethodId: mg.GetAuthMethodId(),
			Name:         wrapperspb.String(strconv.Itoa(i)),
			CreatedTime:  mg.GetCreateTime().GetTimestamp(),
			UpdatedTime:  mg.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         oidc.Subtype.String(),
			Attrs: &pb.ManagedGroup_OidcManagedGroupAttributes{
				OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
					Filter: oidc.TestFakeManagedGroupFilter,
				},
			},
			AuthorizedActions: oidcAuthorizedActions,
		})
	}

	var wantOtherManagedGroups []*pb.ManagedGroup
	for i := 0; i < 3; i++ {
		mg := oidc.TestManagedGroup(t, conn, amOtherManagedGroups, oidc.TestFakeManagedGroupFilter, oidc.WithName(strconv.Itoa(i)))
		wantOtherManagedGroups = append(wantOtherManagedGroups, &pb.ManagedGroup{
			Id:           mg.GetPublicId(),
			AuthMethodId: mg.GetAuthMethodId(),
			Name:         wrapperspb.String(strconv.Itoa(i)),
			CreatedTime:  mg.GetCreateTime().GetTimestamp(),
			UpdatedTime:  mg.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         oidc.Subtype.String(),
			Attrs: &pb.ManagedGroup_OidcManagedGroupAttributes{
				OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
					Filter: oidc.TestFakeManagedGroupFilter,
				},
			},
			AuthorizedActions: oidcAuthorizedActions,
		})
	}

	slices.Reverse(wantSomeManagedGroups)
	slices.Reverse(wantOtherManagedGroups)

	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

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
			res: &pbs.ListManagedGroupsResponse{
				Items:        wantSomeManagedGroups,
				EstItemCount: 3,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "List Other ManagedGroups",
			req:  &pbs.ListManagedGroupsRequest{AuthMethodId: amOtherManagedGroups.GetPublicId()},
			res: &pbs.ListManagedGroupsResponse{
				Items:        wantOtherManagedGroups,
				EstItemCount: 3,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "List No ManagedGroups",
			req:  &pbs.ListManagedGroupsRequest{AuthMethodId: amNoManagedGroups.GetPublicId()},
			res: &pbs.ListManagedGroupsResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "Unfound Auth Method",
			req:  &pbs.ListManagedGroupsRequest{AuthMethodId: globals.OidcAuthMethodPrefix + "_DoesntExis"},
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Filter Some ManagedGroups",
			req: &pbs.ListManagedGroupsRequest{
				AuthMethodId: amSomeManagedGroups.GetPublicId(),
				Filter:       fmt.Sprintf(`"/item/name"==%q`, wantSomeManagedGroups[1].Name.GetValue()),
			},
			res: &pbs.ListManagedGroupsResponse{
				Items:        wantSomeManagedGroups[1:2],
				EstItemCount: 1,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
			skipAnon: true,
		},
		{
			name: "Filter All ManagedGroups",
			req: &pbs.ListManagedGroupsRequest{
				AuthMethodId: amSomeManagedGroups.GetPublicId(),
				Filter:       `"/item/id"=="noManagedGroupmatchesthis"`,
			},
			res: &pbs.ListManagedGroupsResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
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
			s, err := managed_groups.NewService(ctx, oidcRepoFn, ldapRepoFn, 1000)
			require.NoError(err, "Couldn't create new managed group service.")

			got, gErr := s.ListManagedGroups(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListManagedGroups() with auth method %q got error %v, wanted %v", tc.req, gErr, tc.err)
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
				protocmp.IgnoreFields(&pbs.ListManagedGroupsResponse{}, "list_token"),
			), "ListManagedGroups() with scope %q got response %q, wanted %q", tc.req, got, tc.res)

			// Now test with anon
			if tc.skipAnon {
				return
			}
			got, gErr = s.ListManagedGroups(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId(), auth.WithUserId(globals.AnonymousUserId)), tc.req)
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
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
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
	amNoManagedGroups := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://no-managed-groups"})
	amSomeManagedGroups := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://some-managed-groups"})
	amOtherManagedGroups := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://other-managed-groups"})

	testGroups := []string{"admin", "users"}
	var wantSomeManagedGroups []*pb.ManagedGroup
	for i := 0; i < 3; i++ {
		mg := ldap.TestManagedGroup(t, conn, amSomeManagedGroups, testGroups, ldap.WithName(ctx, strconv.Itoa(i)))
		wantSomeManagedGroups = append(wantSomeManagedGroups, &pb.ManagedGroup{
			Id:           mg.GetPublicId(),
			AuthMethodId: mg.GetAuthMethodId(),
			Name:         wrapperspb.String(strconv.Itoa(i)),
			CreatedTime:  mg.GetCreateTime().GetTimestamp(),
			UpdatedTime:  mg.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         ldap.Subtype.String(),
			Attrs: &pb.ManagedGroup_LdapManagedGroupAttributes{
				LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
					GroupNames: testGroups,
				},
			},
			AuthorizedActions: ldapAuthorizedActions,
		})
	}

	var wantOtherManagedGroups []*pb.ManagedGroup
	for i := 0; i < 3; i++ {
		mg := ldap.TestManagedGroup(t, conn, amOtherManagedGroups, testGroups, ldap.WithName(ctx, strconv.Itoa(i)))
		wantOtherManagedGroups = append(wantOtherManagedGroups, &pb.ManagedGroup{
			Id:           mg.GetPublicId(),
			AuthMethodId: mg.GetAuthMethodId(),
			Name:         wrapperspb.String(strconv.Itoa(i)),
			CreatedTime:  mg.GetCreateTime().GetTimestamp(),
			UpdatedTime:  mg.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         ldap.Subtype.String(),
			Attrs: &pb.ManagedGroup_LdapManagedGroupAttributes{
				LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
					GroupNames: testGroups,
				},
			},
			AuthorizedActions: ldapAuthorizedActions,
		})
	}

	slices.Reverse(wantSomeManagedGroups)
	slices.Reverse(wantOtherManagedGroups)

	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	cases := []struct {
		name        string
		req         *pbs.ListManagedGroupsRequest
		res         *pbs.ListManagedGroupsResponse
		err         error
		errContains string
		skipAnon    bool
	}{
		{
			name: "List Some ManagedGroups",
			req:  &pbs.ListManagedGroupsRequest{AuthMethodId: amSomeManagedGroups.GetPublicId()},
			res: &pbs.ListManagedGroupsResponse{
				Items:        wantSomeManagedGroups,
				EstItemCount: 3,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "List Other ManagedGroups",
			req:  &pbs.ListManagedGroupsRequest{AuthMethodId: amOtherManagedGroups.GetPublicId()},
			res: &pbs.ListManagedGroupsResponse{
				Items:        wantOtherManagedGroups,
				EstItemCount: 3,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name: "List No ManagedGroups",
			req:  &pbs.ListManagedGroupsRequest{AuthMethodId: amNoManagedGroups.GetPublicId()},
			res: &pbs.ListManagedGroupsResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name:        "Unfound Auth Method",
			req:         &pbs.ListManagedGroupsRequest{AuthMethodId: globals.OidcAuthMethodPrefix + "_DoesntExis"},
			err:         handlers.ApiErrorWithCode(codes.NotFound),
			errContains: "Resource not found.",
		},
		{
			name: "Filter Some ManagedGroups",
			req: &pbs.ListManagedGroupsRequest{
				AuthMethodId: amSomeManagedGroups.GetPublicId(),
				Filter:       fmt.Sprintf(`"/item/name"==%q`, wantSomeManagedGroups[1].Name.GetValue()),
			},
			res: &pbs.ListManagedGroupsResponse{
				Items:        wantSomeManagedGroups[1:2],
				EstItemCount: 1,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
			skipAnon: true,
		},
		{
			name: "Filter All ManagedGroups",
			req: &pbs.ListManagedGroupsRequest{
				AuthMethodId: amSomeManagedGroups.GetPublicId(),
				Filter:       `"/item/id"=="noManagedGroupmatchesthis"`,
			},
			res: &pbs.ListManagedGroupsResponse{
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
			},
		},
		{
			name:        "Filter Bad Format",
			req:         &pbs.ListManagedGroupsRequest{AuthMethodId: amSomeManagedGroups.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:         handlers.InvalidArgumentErrorf("bad format", nil),
			errContains: "name: \"filter\", desc: \"This field could not be parsed.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := managed_groups.NewService(ctx, oidcRepoFn, ldapRepoFn, 1000)
			require.NoError(err, "Couldn't create new managed group service.")

			got, gErr := s.ListManagedGroups(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListManagedGroups() with auth method %q got error %v, wanted %v", tc.req, gErr, tc.err)
				require.NotEmpty(tc.errContains)
				assert.Contains(gErr.Error(), tc.errContains)
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
				protocmp.IgnoreFields(&pbs.ListManagedGroupsResponse{}, "list_token"),
			), "ListManagedGroups() with scope %q got response %q, wanted %q", tc.req, got, tc.res)

			// Now test with anon
			if tc.skipAnon {
				return
			}
			got, gErr = s.ListManagedGroups(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId(), auth.WithUserId(globals.AnonymousUserId)), tc.req)
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

	s, err := managed_groups.NewService(ctx, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err)

	iamRepo := iam.TestRepo(t, conn, wrap)
	tokenRepo, _ := tokenRepoFn()
	oidcRepo, _ := oidcRepoFn()
	ldapRepo, _ := ldapRepoFn()
	o, pwt := iam.TestScopes(t, iamRepo)

	t.Run("oidc", func(t *testing.T) {
		databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
		require.NoError(t, err)
		authMethod := oidc.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState, "somemgs", "fido",
			oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.somemgs.com")[0]), oidc.WithSigningAlgs(oidc.RS256), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]))

		var mgs []*pb.ManagedGroup
		for i := 0; i < 10; i++ {
			mg := oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter, oidc.WithName(strconv.Itoa(i)))
			mgs = append(mgs, &pb.ManagedGroup{
				Id:           mg.GetPublicId(),
				AuthMethodId: mg.GetAuthMethodId(),
				Name:         wrapperspb.String(strconv.Itoa(i)),
				CreatedTime:  mg.GetCreateTime().GetTimestamp(),
				UpdatedTime:  mg.GetUpdateTime().GetTimestamp(),
				Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
				Version:      1,
				Type:         oidc.Subtype.String(),
				Attrs: &pb.ManagedGroup_OidcManagedGroupAttributes{
					OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
						Filter: oidc.TestFakeManagedGroupFilter,
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

		// Since we sort by created_time descending, we reverse the slice
		slices.Reverse(mgs)

		at, _ := tokenRepo.CreateAuthToken(ctx, u, acct.GetPublicId())

		requestInfo := authpb.RequestInfo{
			TokenFormat: uint32(auth.AuthTokenTypeBearer),
			PublicId:    at.GetPublicId(),
			Token:       at.GetToken(),
		}
		requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
		ctx = auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kmsCache, &requestInfo)

		req := &pbs.ListManagedGroupsRequest{
			AuthMethodId: authMethod.GetPublicId(),
			Filter:       "",
			ListToken:    "",
			PageSize:     2,
		}

		// Run analyze in the DB to update the estimate tables
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		got, err := s.ListManagedGroups(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 2)

		// all comparisons will be done without list token
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListManagedGroupsResponse{
					Items:        mgs[0:2],
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
				protocmp.IgnoreFields(&pbs.ListManagedGroupsResponse{}, "list_token"),
			),
		)

		// second page
		req.ListToken = got.ListToken
		got, err = s.ListManagedGroups(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 2)

		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListManagedGroupsResponse{
					Items:        mgs[2:4],
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
				protocmp.IgnoreFields(&pbs.ListManagedGroupsResponse{}, "list_token"),
			),
		)

		// remainder of results
		req.ListToken = got.ListToken
		req.PageSize = 6
		got, err = s.ListManagedGroups(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 6)

		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListManagedGroupsResponse{
					Items:        mgs[4:],
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
				protocmp.IgnoreFields(&pbs.ListManagedGroupsResponse{}, "list_token"),
			),
		)

		// create another managed group
		mg := oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter, oidc.WithName("new-oidc-mg"))
		newMg := &pb.ManagedGroup{
			Id:           mg.GetPublicId(),
			AuthMethodId: mg.GetAuthMethodId(),
			Name:         wrapperspb.String("new-oidc-mg"),
			CreatedTime:  mg.GetCreateTime().GetTimestamp(),
			UpdatedTime:  mg.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         oidc.Subtype.String(),
			Attrs: &pb.ManagedGroup_OidcManagedGroupAttributes{
				OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
					Filter: oidc.TestFakeManagedGroupFilter,
				},
			},
			AuthorizedActions: oidcAuthorizedActions,
		}
		// Add to front since it's the latest updated
		mgs = append([]*pb.ManagedGroup{newMg}, mgs...)

		// delete different mg
		_, err = oidcRepo.DeleteManagedGroup(ctx, o.GetPublicId(), mgs[len(mgs)-1].Id)
		require.NoError(t, err)
		deletedMg := mgs[len(mgs)-1]
		mgs = mgs[:len(mgs)-1]

		// update another mg
		mgs[1].Name = wrapperspb.String("new-name")
		mgs[1].Version = 2
		m := &oidc.ManagedGroup{
			ManagedGroup: &oidcstore.ManagedGroup{
				PublicId:     mgs[1].Id,
				AuthMethodId: mgs[1].AuthMethodId,
				Name:         mgs[1].Name.GetValue(),
			},
		}
		um, _, err := oidcRepo.UpdateManagedGroup(ctx, o.GetPublicId(), m, 1, []string{"name"})
		require.NoError(t, err)
		mgs[1].UpdatedTime = um.GetUpdateTime().GetTimestamp()
		mgs[1].Version = um.GetVersion()
		// Add to the front since it's most recently updated
		mgs = append(
			[]*pb.ManagedGroup{mgs[1]},
			append(
				[]*pb.ManagedGroup{mgs[0]},
				mgs[2:]...,
			)...,
		)

		// Run analyze to update postgres estimates
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request updated results
		req.ListToken = got.ListToken
		req.PageSize = 1
		got, err = s.ListManagedGroups(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListManagedGroupsResponse{
					Items:        []*pb.ManagedGroup{mgs[0]},
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "updated_time",
					SortDir:      "desc",
					RemovedIds:   []string{deletedMg.Id},
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListManagedGroupsResponse{}, "list_token"),
			),
		)

		// Get next page
		req.ListToken = got.ListToken
		got, err = s.ListManagedGroups(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListManagedGroupsResponse{
					Items:        []*pb.ManagedGroup{mgs[1]},
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
				protocmp.IgnoreFields(&pbs.ListManagedGroupsResponse{}, "list_token"),
			),
		)

		// Request new page with filter requiring looping
		// to fill the page.
		req.ListToken = ""
		req.PageSize = 1
		req.Filter = fmt.Sprintf(`"/item/id"==%q or "/item/id"==%q`, mgs[len(mgs)-2].Id, mgs[len(mgs)-1].Id)
		got, err = s.ListManagedGroups(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListManagedGroupsResponse{
					Items:        []*pb.ManagedGroup{mgs[len(mgs)-2]},
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
				protocmp.IgnoreFields(&pbs.ListManagedGroupsResponse{}, "list_token"),
			),
		)
		req.ListToken = got.ListToken
		// Get the second page
		got, err = s.ListManagedGroups(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListManagedGroupsResponse{
					Items:        []*pb.ManagedGroup{mgs[len(mgs)-1]},
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
				protocmp.IgnoreFields(&pbs.ListManagedGroupsResponse{}, "list_token"),
			),
		)

		// Create unauthenticated user
		unauthAt := authtoken.TestAuthToken(t, conn, kmsCache, o.GetPublicId())
		unauthR := iam.TestRole(t, conn, pwt.GetPublicId())
		_ = iam.TestUserRole(t, conn, unauthR.GetPublicId(), unauthAt.GetIamUserId())

		// Make a request with the unauthenticated user,
		// ensure the response contains the pagination parameters.
		requestInfo = authpb.RequestInfo{
			TokenFormat: uint32(auth.AuthTokenTypeBearer),
			PublicId:    unauthAt.GetPublicId(),
			Token:       unauthAt.GetToken(),
		}
		requestContext = context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
		ctx = auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kmsCache, &requestInfo)

		_, err = s.ListManagedGroups(ctx, &pbs.ListManagedGroupsRequest{
			AuthMethodId: authMethod.GetPublicId(),
		})
		require.Error(t, err)
		assert.ErrorIs(t, handlers.ForbiddenError(), err)
	})

	t.Run("ldap", func(t *testing.T) {
		o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
		databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
		require.NoError(t, err)
		authMethod := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://some-mgs"})

		testGroups := []string{"admin", "users"}
		var mgs []*pb.ManagedGroup
		for i := 0; i < 10; i++ {
			mg := ldap.TestManagedGroup(t, conn, authMethod, testGroups, ldap.WithName(ctx, strconv.Itoa(i)))
			mgs = append(mgs, &pb.ManagedGroup{
				Id:           mg.GetPublicId(),
				AuthMethodId: mg.GetAuthMethodId(),
				Name:         wrapperspb.String(strconv.Itoa(i)),
				CreatedTime:  mg.GetCreateTime().GetTimestamp(),
				UpdatedTime:  mg.GetUpdateTime().GetTimestamp(),
				Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
				Version:      1,
				Type:         ldap.Subtype.String(),
				Attrs: &pb.ManagedGroup_LdapManagedGroupAttributes{
					LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
						GroupNames: testGroups,
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

		// Since we sort by created_time descending, we reverse the slice
		slices.Reverse(mgs)

		at, _ := tokenRepo.CreateAuthToken(ctx, u, acct.GetPublicId())

		requestInfo := authpb.RequestInfo{
			TokenFormat: uint32(auth.AuthTokenTypeBearer),
			PublicId:    at.GetPublicId(),
			Token:       at.GetToken(),
		}
		requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
		ctx = auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kmsCache, &requestInfo)

		req := &pbs.ListManagedGroupsRequest{
			AuthMethodId: authMethod.GetPublicId(),
			Filter:       "",
			ListToken:    "",
			PageSize:     2,
		}

		// Run analyze in the DB to update the estimate tables
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		got, err := s.ListManagedGroups(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 2)

		// all comparisons will be done without list token
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListManagedGroupsResponse{
					Items:        mgs[0:2],
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
				protocmp.IgnoreFields(&pbs.ListManagedGroupsResponse{}, "list_token"),
			),
		)

		// second page
		req.ListToken = got.ListToken
		got, err = s.ListManagedGroups(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 2)

		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListManagedGroupsResponse{
					Items:        mgs[2:4],
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
				protocmp.IgnoreFields(&pbs.ListManagedGroupsResponse{}, "list_token"),
			),
		)

		// remainder of results
		req.ListToken = got.ListToken
		req.PageSize = 6
		got, err = s.ListManagedGroups(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 6)

		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListManagedGroupsResponse{
					Items:        mgs[4:],
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
				protocmp.IgnoreFields(&pbs.ListManagedGroupsResponse{}, "list_token"),
			),
		)

		// create another mg
		mg := ldap.TestManagedGroup(t, conn, authMethod, testGroups, ldap.WithName(ctx, "new-ldap-name"))
		newMg := &pb.ManagedGroup{
			Id:           mg.GetPublicId(),
			AuthMethodId: mg.GetAuthMethodId(),
			Name:         wrapperspb.String("new-ldap-name"),
			CreatedTime:  mg.GetCreateTime().GetTimestamp(),
			UpdatedTime:  mg.GetUpdateTime().GetTimestamp(),
			Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:      1,
			Type:         ldap.Subtype.String(),
			Attrs: &pb.ManagedGroup_LdapManagedGroupAttributes{
				LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
					GroupNames: testGroups,
				},
			},
			AuthorizedActions: ldapAuthorizedActions,
		}
		// Add to front since it's the latest updated
		mgs = append([]*pb.ManagedGroup{newMg}, mgs...)

		// delete different mg
		_, err = ldapRepo.DeleteManagedGroup(ctx, o.GetPublicId(), mgs[len(mgs)-1].Id)
		require.NoError(t, err)
		deletedMg := mgs[len(mgs)-1]
		mgs = mgs[:len(mgs)-1]

		// update another mg
		mgs[1].Name = wrapperspb.String("new-name")
		mgs[1].Version = 2
		m := &ldap.ManagedGroup{
			ManagedGroup: &ldapstore.ManagedGroup{
				PublicId:     mgs[1].Id,
				AuthMethodId: mgs[1].AuthMethodId,
				Name:         mgs[1].Name.GetValue(),
			},
		}
		um, _, err := ldapRepo.UpdateManagedGroup(ctx, o.GetPublicId(), m, 1, []string{"name"})
		require.NoError(t, err)
		mgs[1].UpdatedTime = um.GetUpdateTime().GetTimestamp()
		mgs[1].Version = um.GetVersion()
		// Add to the front since it's most recently updated
		mgs = append(
			[]*pb.ManagedGroup{mgs[1]},
			append(
				[]*pb.ManagedGroup{mgs[0]},
				mgs[2:]...,
			)...,
		)

		// Run analyze to update postgres estimates
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request updated results
		req.ListToken = got.ListToken
		req.PageSize = 1
		got, err = s.ListManagedGroups(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListManagedGroupsResponse{
					Items:        []*pb.ManagedGroup{mgs[0]},
					ResponseType: "delta",
					ListToken:    "",
					SortBy:       "updated_time",
					SortDir:      "desc",
					RemovedIds:   []string{deletedMg.Id},
					EstItemCount: 10,
				},
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				protocmp.Transform(),
				protocmp.IgnoreFields(&pbs.ListManagedGroupsResponse{}, "list_token"),
			),
		)

		// Get next page
		req.ListToken = got.ListToken
		got, err = s.ListManagedGroups(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListManagedGroupsResponse{
					Items:        []*pb.ManagedGroup{mgs[1]},
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
				protocmp.IgnoreFields(&pbs.ListManagedGroupsResponse{}, "list_token"),
			),
		)

		// Request new page with filter requiring looping
		// to fill the page.
		req.ListToken = ""
		req.PageSize = 1
		req.Filter = fmt.Sprintf(`"/item/id"==%q or "/item/id"==%q`, mgs[len(mgs)-2].Id, mgs[len(mgs)-1].Id)
		got, err = s.ListManagedGroups(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListManagedGroupsResponse{
					Items:        []*pb.ManagedGroup{mgs[len(mgs)-2]},
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
				protocmp.IgnoreFields(&pbs.ListManagedGroupsResponse{}, "list_token"),
			),
		)
		req.ListToken = got.ListToken
		// Get the second page
		got, err = s.ListManagedGroups(ctx, req)
		require.NoError(t, err)
		require.Len(t, got.GetItems(), 1)
		assert.Empty(t,
			cmp.Diff(
				got,
				&pbs.ListManagedGroupsResponse{
					Items:        []*pb.ManagedGroup{mgs[len(mgs)-1]},
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
				protocmp.IgnoreFields(&pbs.ListManagedGroupsResponse{}, "list_token"),
			),
		)

		// Create unauthenticated user
		unauthAt := authtoken.TestAuthToken(t, conn, kmsCache, o.GetPublicId())
		unauthR := iam.TestRole(t, conn, pwt.GetPublicId())
		_ = iam.TestUserRole(t, conn, unauthR.GetPublicId(), unauthAt.GetIamUserId())

		// Make a request with the unauthenticated user,
		// ensure the response contains the pagination parameters.
		requestInfo = authpb.RequestInfo{
			TokenFormat: uint32(auth.AuthTokenTypeBearer),
			PublicId:    unauthAt.GetPublicId(),
			Token:       unauthAt.GetToken(),
		}
		requestContext = context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
		ctx = auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kmsCache, &requestInfo)

		_, err = s.ListManagedGroups(ctx, &pbs.ListManagedGroupsRequest{
			AuthMethodId: authMethod.GetPublicId(),
		})
		require.Error(t, err)
		assert.ErrorIs(t, handlers.ForbiddenError(), err)
	})
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
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
	oidcAm := oidc.TestAuthMethod(
		t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	oidcMg := oidc.TestManagedGroup(t, conn, oidcAm, oidc.TestFakeManagedGroupFilter)

	ldapAm := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://ldap1"})
	ldapMg := ldap.TestManagedGroup(t, conn, ldapAm, []string{"admin", "users"})

	s, err := managed_groups.NewService(ctx, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err, "Error when getting new user service.")

	cases := []struct {
		name        string
		scope       string
		req         *pbs.DeleteManagedGroupRequest
		res         *pbs.DeleteManagedGroupResponse
		err         error
		errContains string
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
				Id: globals.OidcManagedGroupPrefix + "_doesntexis",
			},
			err:         handlers.ApiErrorWithCode(codes.NotFound),
			errContains: "Resource not found.",
		},
		{
			name: "Delete an existing ldap managed group",
			req: &pbs.DeleteManagedGroupRequest{
				Id: ldapMg.GetPublicId(),
			},
		},
		{
			name: "Delete bad ldap managed group id",
			req: &pbs.DeleteManagedGroupRequest{
				Id: globals.LdapManagedGroupPrefix + "_doesntexis",
			},
			err:         handlers.ApiErrorWithCode(codes.NotFound),
			errContains: "Resource not found.",
		},
		{
			name: "Bad managed group id formatting",
			req: &pbs.DeleteManagedGroupRequest{
				Id: "bad_format",
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "Incorrectly formatted identifier.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteManagedGroup(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteManagedGroup(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				require.NotEmpty(tc.errContains)
				assert.Contains(gErr.Error(), tc.errContains)
			}
			assert.EqualValuesf(tc.res, got, "DeleteManagedGroup(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	ctx := context.TODO()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrap)

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

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(err)

	oidcAm := oidc.TestAuthMethod(
		t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	oidcMg := oidc.TestManagedGroup(t, conn, oidcAm, oidc.TestFakeManagedGroupFilter)

	s, err := managed_groups.NewService(ctx, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(err, "Error when getting new user service")
	req := &pbs.DeleteManagedGroupRequest{
		Id: oidcMg.GetPublicId(),
	}
	_, gErr := s.DeleteManagedGroup(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteManagedGroup(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected not found for the second delete.")
}

func TestCreateOidc(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kmsCache)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kmsCache)
	}

	s, err := managed_groups.NewService(ctx, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err, "Error when getting new managed group service.")

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
		req  *pbs.CreateManagedGroupRequest
		res  *pbs.CreateManagedGroupResponse
		err  error
	}{
		{
			name: "Create a valid ManagedGroup",
			req: &pbs.CreateManagedGroupRequest{
				Item: &pb.ManagedGroup{
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					Type:         oidc.Subtype.String(),
					Attrs: &pb.ManagedGroup_OidcManagedGroupAttributes{
						OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
							Filter: oidc.TestFakeManagedGroupFilter,
						},
					},
				},
			},
			res: &pbs.CreateManagedGroupResponse{
				Uri: fmt.Sprintf("managed-groups/%s_", globals.OidcManagedGroupPrefix),
				Item: &pb.ManagedGroup{
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Version:      1,
					Type:         oidc.Subtype.String(),
					Attrs: &pb.ManagedGroup_OidcManagedGroupAttributes{
						OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
							Filter: oidc.TestFakeManagedGroupFilter,
						},
					},
					AuthorizedActions: oidcAuthorizedActions,
				},
			},
		},
		{
			name: "Create a valid ManagedGroup without type defined",
			req: &pbs.CreateManagedGroupRequest{
				Item: &pb.ManagedGroup{
					AuthMethodId: am.GetPublicId(),
					Attrs: &pb.ManagedGroup_OidcManagedGroupAttributes{
						OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
							Filter: oidc.TestFakeManagedGroupFilter,
						},
					},
				},
			},
			res: &pbs.CreateManagedGroupResponse{
				Uri: fmt.Sprintf("managed-groups/%s_", globals.OidcManagedGroupPrefix),
				Item: &pb.ManagedGroup{
					AuthMethodId: am.GetPublicId(),
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Version:      1,
					Type:         oidc.Subtype.String(),
					Attrs: &pb.ManagedGroup_OidcManagedGroupAttributes{
						OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
							Filter: oidc.TestFakeManagedGroupFilter,
						},
					},
					AuthorizedActions: oidcAuthorizedActions,
				},
			},
		},
		{
			name: "Cant specify mismatching type",
			req: &pbs.CreateManagedGroupRequest{
				Item: &pb.ManagedGroup{
					AuthMethodId: am.GetPublicId(),
					Type:         password.Subtype.String(),
					Attrs: &pb.ManagedGroup_OidcManagedGroupAttributes{
						OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
							Filter: oidc.TestFakeManagedGroupFilter,
						},
					},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateManagedGroupRequest{
				Item: &pb.ManagedGroup{
					AuthMethodId: am.GetPublicId(),
					Id:           globals.OidcManagedGroupPrefix + "_notallowed",
					Type:         oidc.Subtype.String(),
					Attrs: &pb.ManagedGroup_OidcManagedGroupAttributes{
						OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
							Filter: oidc.TestFakeManagedGroupFilter,
						},
					},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateManagedGroupRequest{
				Item: &pb.ManagedGroup{
					AuthMethodId: am.GetPublicId(),
					CreatedTime:  timestamppb.Now(),
					Type:         oidc.Subtype.String(),
					Attrs: &pb.ManagedGroup_OidcManagedGroupAttributes{
						OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
							Filter: oidc.TestFakeManagedGroupFilter,
						},
					},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateManagedGroupRequest{
				Item: &pb.ManagedGroup{
					AuthMethodId: am.GetPublicId(),
					UpdatedTime:  timestamppb.Now(),
					Type:         oidc.Subtype.String(),
					Attrs: &pb.ManagedGroup_OidcManagedGroupAttributes{
						OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
							Filter: oidc.TestFakeManagedGroupFilter,
						},
					},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify bad filter",
			req: &pbs.CreateManagedGroupRequest{
				Item: &pb.ManagedGroup{
					AuthMethodId: am.GetPublicId(),
					UpdatedTime:  timestamppb.Now(),
					Type:         oidc.Subtype.String(),
					Attrs: &pb.ManagedGroup_OidcManagedGroupAttributes{
						OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
							Filter: "foobar",
						},
					},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.CreateManagedGroup(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateManagedGroup(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				assert.True(strings.HasPrefix(got.GetItem().GetId(), globals.OidcManagedGroupPrefix+"_"))
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
			), "CreateManagedGroup(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestCreateLdap(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kmsCache)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kmsCache)
	}

	s, err := managed_groups.NewService(ctx, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err, "Error when getting new managed group service.")

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	am := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://ldap1"})

	cases := []struct {
		name        string
		req         *pbs.CreateManagedGroupRequest
		res         *pbs.CreateManagedGroupResponse
		err         error
		errContains string
	}{
		{
			name: "Create a valid ManagedGroup",
			req: &pbs.CreateManagedGroupRequest{
				Item: &pb.ManagedGroup{
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					Type:         ldap.Subtype.String(),
					Attrs: &pb.ManagedGroup_LdapManagedGroupAttributes{
						LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
							GroupNames: []string{"admin", "users"},
						},
					},
				},
			},
			res: &pbs.CreateManagedGroupResponse{
				Uri: fmt.Sprintf("managed-groups/%s_", globals.LdapManagedGroupPrefix),
				Item: &pb.ManagedGroup{
					AuthMethodId: am.GetPublicId(),
					Name:         &wrapperspb.StringValue{Value: "name"},
					Description:  &wrapperspb.StringValue{Value: "desc"},
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Version:      1,
					Type:         ldap.Subtype.String(),
					Attrs: &pb.ManagedGroup_LdapManagedGroupAttributes{
						LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
							GroupNames: []string{"admin", "users"},
						},
					},
					AuthorizedActions: ldapAuthorizedActions,
				},
			},
		},
		{
			name: "Create a valid ManagedGroup without type defined",
			req: &pbs.CreateManagedGroupRequest{
				Item: &pb.ManagedGroup{
					AuthMethodId: am.GetPublicId(),
					Attrs: &pb.ManagedGroup_LdapManagedGroupAttributes{
						LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
							GroupNames: []string{"admin", "users"},
						},
					},
				},
			},
			res: &pbs.CreateManagedGroupResponse{
				Uri: fmt.Sprintf("managed-groups/%s_", globals.LdapManagedGroupPrefix),
				Item: &pb.ManagedGroup{
					AuthMethodId: am.GetPublicId(),
					Scope:        &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Version:      1,
					Type:         ldap.Subtype.String(),
					Attrs: &pb.ManagedGroup_LdapManagedGroupAttributes{
						LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
							GroupNames: []string{"admin", "users"},
						},
					},
					AuthorizedActions: oidcAuthorizedActions,
				},
			},
		},
		{
			name: "Cant specify mismatching type",
			req: &pbs.CreateManagedGroupRequest{
				Item: &pb.ManagedGroup{
					AuthMethodId: am.GetPublicId(),
					Type:         password.Subtype.String(),
					Attrs: &pb.ManagedGroup_LdapManagedGroupAttributes{
						LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
							GroupNames: []string{"admin", "users"},
						},
					},
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "Doesn't match the parent resource's type.",
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateManagedGroupRequest{
				Item: &pb.ManagedGroup{
					AuthMethodId: am.GetPublicId(),
					Id:           globals.LdapManagedGroupPrefix + "_notallowed",
					Type:         oidc.Subtype.String(),
					Attrs: &pb.ManagedGroup_LdapManagedGroupAttributes{
						LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
							GroupNames: []string{"admin", "users"},
						},
					},
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"id\", desc: \"This is a read only field.",
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateManagedGroupRequest{
				Item: &pb.ManagedGroup{
					AuthMethodId: am.GetPublicId(),
					CreatedTime:  timestamppb.Now(),
					Type:         ldap.Subtype.String(),
					Attrs: &pb.ManagedGroup_LdapManagedGroupAttributes{
						LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
							GroupNames: []string{"admin", "users"},
						},
					},
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"created_time\", desc: \"This is a read only field.",
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateManagedGroupRequest{
				Item: &pb.ManagedGroup{
					AuthMethodId: am.GetPublicId(),
					UpdatedTime:  timestamppb.Now(),
					Type:         ldap.Subtype.String(),
					Attrs: &pb.ManagedGroup_LdapManagedGroupAttributes{
						LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
							GroupNames: []string{"admin", "users"},
						},
					},
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"updated_time\", desc: \"This is a read only field.",
		},
		{
			name: "Can't specify group names",
			req: &pbs.CreateManagedGroupRequest{
				Item: &pb.ManagedGroup{
					AuthMethodId: am.GetPublicId(),
					Type:         oidc.Subtype.String(),
					Attrs: &pb.ManagedGroup_LdapManagedGroupAttributes{
						LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
							GroupNames: []string{},
						},
					},
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"attributes.group_names\", desc: \"This field is required.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.CreateManagedGroup(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateManagedGroup(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				require.NotEmpty(tc.errContains)
				assert.Contains(gErr.Error(), tc.errContains)
				return
			}
			require.NoError(gErr)
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				assert.True(strings.HasPrefix(got.GetItem().GetId(), globals.LdapManagedGroupPrefix+"_"))
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
			), "CreateManagedGroup(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestUpdateOidc(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
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

	tested, err := managed_groups.NewService(ctx, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err, "Error when getting new managed_groups service.")

	defaultScopeInfo := &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType(), ParentScopeId: scope.Global.String()}
	defaultAttributes := &pb.ManagedGroup_OidcManagedGroupAttributes{
		OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
			Filter: oidc.TestFakeManagedGroupFilter,
		},
	}

	modifiedAttributes := &pb.ManagedGroup_OidcManagedGroupAttributes{
		OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
			Filter: `"/token/zip" == "zap"`,
		},
	}

	badAttributes := &pb.ManagedGroup_OidcManagedGroupAttributes{
		OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
			Filter: `"foobar"`,
		},
	}

	freshManagedGroup := func(t *testing.T) (*oidc.ManagedGroup, func()) {
		t.Helper()
		mg := oidc.TestManagedGroup(t, conn, am, oidc.TestFakeManagedGroupFilter, oidc.WithName("default"), oidc.WithDescription("default"))

		clean := func() {
			_, err := tested.DeleteManagedGroup(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()),
				&pbs.DeleteManagedGroupRequest{Id: mg.GetPublicId()})
			require.NoError(t, err)
		}

		return mg, clean
	}

	cases := []struct {
		name string
		req  *pbs.UpdateManagedGroupRequest
		res  *pbs.UpdateManagedGroupResponse
		err  error
	}{
		{
			name: "Update an Existing AuthMethod",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.NameField, globals.DescriptionField},
				},
				Item: &pb.ManagedGroup{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        oidc.Subtype.String(),
				},
			},
			res: &pbs.UpdateManagedGroupResponse{
				Item: &pb.ManagedGroup{
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
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.ManagedGroup{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        oidc.Subtype.String(),
				},
			},
			res: &pbs.UpdateManagedGroupResponse{
				Item: &pb.ManagedGroup{
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
			req: &pbs.UpdateManagedGroupRequest{
				Item: &pb.ManagedGroup{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
					Attrs:       modifiedAttributes,
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant change type",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.NameField},
				},
				Item: &pb.ManagedGroup{
					Name: &wrapperspb.StringValue{Value: ""},
					Type: "oidc",
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "No Paths in Mask",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.ManagedGroup{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
					Attrs:       modifiedAttributes,
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Only non-existent paths in Mask",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistent_field"}},
				Item: &pb.ManagedGroup{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
					Attrs:       modifiedAttributes,
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.NameField},
				},
				Item: &pb.ManagedGroup{
					Description: &wrapperspb.StringValue{Value: "ignored"},
					Attrs:       modifiedAttributes,
				},
			},
			res: &pbs.UpdateManagedGroupResponse{
				Item: &pb.ManagedGroup{
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
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.NameField},
				},
				Item: &pb.ManagedGroup{
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
					Attrs:       modifiedAttributes,
				},
			},
			res: &pbs.UpdateManagedGroupResponse{
				Item: &pb.ManagedGroup{
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
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.DescriptionField},
				},
				Item: &pb.ManagedGroup{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
					Attrs:       modifiedAttributes,
				},
			},
			res: &pbs.UpdateManagedGroupResponse{
				Item: &pb.ManagedGroup{
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
			name: "Update a Non Existing ManagedGroup",
			req: &pbs.UpdateManagedGroupRequest{
				Id: globals.OidcManagedGroupPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.DescriptionField},
				},
				Item: &pb.ManagedGroup{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.ManagedGroup{
					Id:          globals.OidcManagedGroupPrefix + "_somethinge",
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "new desc"},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.ManagedGroup{
					CreatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.ManagedGroup{
					UpdatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Type",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"type"},
				},
				Item: &pb.ManagedGroup{
					Type: "oidc",
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Update Filter with Bad Value",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.filter"},
				},
				Item: &pb.ManagedGroup{
					Attrs: badAttributes,
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Update Filter With Good Value",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.filter"},
				},
				Item: &pb.ManagedGroup{
					Attrs: modifiedAttributes,
				},
			},
			res: &pbs.UpdateManagedGroupResponse{
				Item: &pb.ManagedGroup{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "default"},
					Description:       &wrapperspb.StringValue{Value: "default"},
					Type:              oidc.Subtype.String(),
					Attrs:             modifiedAttributes,
					Scope:             defaultScopeInfo,
					AuthorizedActions: oidcAuthorizedActions,
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			mg, cleanup := freshManagedGroup(t)
			defer cleanup()

			tc.req.Item.Version = 1

			if tc.req.GetId() == "" {
				tc.req.Id = mg.GetPublicId()
			}

			if tc.res != nil && tc.res.Item != nil {
				tc.res.Item.Id = mg.GetPublicId()
				tc.res.Item.CreatedTime = mg.GetCreateTime().GetTimestamp()
			}

			got, gErr := tested.UpdateManagedGroup(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateManagedGroup(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			} else {
				require.NoError(gErr)
			}

			if tc.res == nil {
				require.Nil(got)
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateManagedGroup response to be nil, but was %v", got)
				gotUpdateTime := got.GetItem().GetUpdatedTime()
				require.NoError(err, "Error converting proto to timestamp")

				created := mg.GetCreateTime().GetTimestamp()
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
			), "UpdateManagedGroup(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestUpdateLdap(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
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
	am := ldap.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, []string{"ldaps://ldap1"})

	tested, err := managed_groups.NewService(ctx, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err, "Error when getting new managed_groups service.")

	testGroups := []string{"test", "admin"}
	testGroupsUpdated := []string{"users"}

	defaultScopeInfo := &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType(), ParentScopeId: scope.Global.String()}
	defaultAttributes := &pb.ManagedGroup_LdapManagedGroupAttributes{
		LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
			GroupNames: testGroups,
		},
	}

	modifiedAttributes := &pb.ManagedGroup_LdapManagedGroupAttributes{
		LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
			GroupNames: testGroupsUpdated,
		},
	}

	badAttributes := &pb.ManagedGroup_LdapManagedGroupAttributes{
		LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{},
	}

	freshManagedGroup := func(t *testing.T) (*ldap.ManagedGroup, func()) {
		t.Helper()
		mg := ldap.TestManagedGroup(t, conn, am, testGroups, ldap.WithName(ctx, "default"), ldap.WithDescription(ctx, "default"))

		clean := func() {
			_, err := tested.DeleteManagedGroup(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()),
				&pbs.DeleteManagedGroupRequest{Id: mg.GetPublicId()})
			require.NoError(t, err)
		}

		return mg, clean
	}

	cases := []struct {
		name        string
		req         *pbs.UpdateManagedGroupRequest
		res         *pbs.UpdateManagedGroupResponse
		err         error
		errContains string
	}{
		{
			name: "Update an Existing Group",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.NameField, globals.DescriptionField},
				},
				Item: &pb.ManagedGroup{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        ldap.Subtype.String(),
				},
			},
			res: &pbs.UpdateManagedGroupResponse{
				Item: &pb.ManagedGroup{
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
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.ManagedGroup{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        ldap.Subtype.String(),
				},
			},
			res: &pbs.UpdateManagedGroupResponse{
				Item: &pb.ManagedGroup{
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
			req: &pbs.UpdateManagedGroupRequest{
				Item: &pb.ManagedGroup{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
					Attrs:       modifiedAttributes,
				},
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "UpdateMask not provided but is required to update this resource.",
		},
		{
			name: "Cant change type",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"name", "type"}},
				Item: &pb.ManagedGroup{
					Type: "oidc",
				},
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "Cannot modify the resource type.",
		},
		{
			name: "No Paths in Mask",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.ManagedGroup{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
					Attrs:       modifiedAttributes,
				},
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "No valid fields included in the update mask.",
		},
		{
			name: "Only non-existent paths in Mask",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistent_field"}},
				Item: &pb.ManagedGroup{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
					Attrs:       modifiedAttributes,
				},
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "No valid fields included in the update mask.",
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.NameField},
				},
				Item: &pb.ManagedGroup{
					Description: &wrapperspb.StringValue{Value: "ignored"},
					Attrs:       modifiedAttributes,
				},
			},
			res: &pbs.UpdateManagedGroupResponse{
				Item: &pb.ManagedGroup{
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
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.NameField},
				},
				Item: &pb.ManagedGroup{
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
					Attrs:       modifiedAttributes,
				},
			},
			res: &pbs.UpdateManagedGroupResponse{
				Item: &pb.ManagedGroup{
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
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.DescriptionField},
				},
				Item: &pb.ManagedGroup{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
					Attrs:       modifiedAttributes,
				},
			},
			res: &pbs.UpdateManagedGroupResponse{
				Item: &pb.ManagedGroup{
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
			name: "Update a Non Existing ManagedGroup",
			req: &pbs.UpdateManagedGroupRequest{
				Id: globals.LdapManagedGroupPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{globals.DescriptionField},
				},
				Item: &pb.ManagedGroup{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			err:         handlers.ApiErrorWithCode(codes.NotFound),
			errContains: "Resource not found.",
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.ManagedGroup{
					Id:          globals.OidcManagedGroupPrefix + "_somethinge",
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
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.ManagedGroup{
					CreatedTime: timestamppb.Now(),
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"created_time\", desc: \"This is a read only field and cannot be specified in an update request.",
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.ManagedGroup{
					UpdatedTime: timestamppb.Now(),
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"updated_time\", desc: \"This is a read only field and cannot be specified in an update request.",
		},
		{
			name: "Cant specify Type",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"type"},
				},
				Item: &pb.ManagedGroup{
					Type: "ldap",
				},
			},
			res:         nil,
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "No valid fields included in the update mask.",
		},
		{
			name: "Update group names with Bad Value",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.group_names"},
				},
				Item: &pb.ManagedGroup{
					Attrs: badAttributes,
				},
			},
			err:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			errContains: "name: \"attributes.filter\", desc: \"Field cannot be empty.",
		},
		{
			name: "Update group names With Good Value",
			req: &pbs.UpdateManagedGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.group_names"},
				},
				Item: &pb.ManagedGroup{
					Attrs: modifiedAttributes,
				},
			},
			res: &pbs.UpdateManagedGroupResponse{
				Item: &pb.ManagedGroup{
					AuthMethodId:      am.GetPublicId(),
					Name:              &wrapperspb.StringValue{Value: "default"},
					Description:       &wrapperspb.StringValue{Value: "default"},
					Type:              ldap.Subtype.String(),
					Attrs:             modifiedAttributes,
					Scope:             defaultScopeInfo,
					AuthorizedActions: ldapAuthorizedActions,
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			mg, cleanup := freshManagedGroup(t)
			defer cleanup()

			tc.req.Item.Version = 1

			if tc.req.GetId() == "" {
				tc.req.Id = mg.GetPublicId()
			}

			if tc.res != nil && tc.res.Item != nil {
				tc.res.Item.Id = mg.GetPublicId()
				tc.res.Item.CreatedTime = mg.GetCreateTime().GetTimestamp()
			}

			got, gErr := tested.UpdateManagedGroup(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateManagedGroup(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				require.NotEmpty(tc.errContains)
				assert.Contains(gErr.Error(), tc.errContains)
			} else {
				require.NoError(gErr)
			}

			if tc.res == nil {
				require.Nil(got)
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateManagedGroup response to be nil, but was %v", got)
				gotUpdateTime := got.GetItem().GetUpdatedTime()
				require.NoError(err, "Error converting proto to timestamp")

				created := mg.GetCreateTime().GetTimestamp()
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
			), "UpdateManagedGroup(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}
