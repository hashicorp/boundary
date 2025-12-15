// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package managed_groups_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/globals"
	a "github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/managed_groups"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/managedgroups"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// TestGrants_ReadActions tests read actions to assert that grants are being applied properly
//
//	Role - which scope the role is created in
//		 - global level
//		 - org level
//		 - proj level
//	Grant - what IAM grant scope is set for the permission
//		  - global: descendant
//		  - org: children
//		  - project: this
//	Scopes [resource]:
//		  - global
//			- org1
//			  - proj1
func TestGrants_ReadActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	oidcRepoFn := func() (*oidc.Repository, error) {
		// Use a small limit to test that membership lookup is explicitly unlimited
		return oidc.NewRepository(ctx, rw, rw, kmsCache, oidc.WithLimit(1))
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		// Use a small limit to test that membership lookup is explicitly unlimited
		return ldap.NewRepository(ctx, rw, rw, kmsCache, ldap.WithLimit(ctx, 1))
	}
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	s, err := managed_groups.NewService(ctx, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err)

	org, _ := iam.TestScopes(t, iamRepo)

	globalDBWrapper, err := kmsCache.GetWrapper(ctx, globals.GlobalPrefix, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	orgDBWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	globalOidcAm := oidc.TestAuthMethod(
		t, conn, globalDBWrapper, globals.GlobalPrefix, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	globalOidcAm2 := oidc.TestAuthMethod(
		t, conn, globalDBWrapper, globals.GlobalPrefix, oidc.ActivePrivateState,
		"alice-rp-global2", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	orgOidcAm := oidc.TestAuthMethod(
		t, conn, orgDBWrapper, org.PublicId, oidc.ActivePrivateState,
		"alice_rp_2", "alices-dogs-name",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice-org.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api.com")[0]),
	)

	_ = oidc.TestAccount(t, conn, globalOidcAm, "test-subject-1", oidc.WithName("global-1"), oidc.WithDescription("global-1"))
	_ = oidc.TestAccount(t, conn, globalOidcAm, "test-subject-2", oidc.WithName("global-2"), oidc.WithDescription("global-2"))
	_ = oidc.TestAccount(t, conn, globalOidcAm2, "test-subject-3", oidc.WithName("global-3"), oidc.WithDescription("global-3"))
	_ = oidc.TestAccount(t, conn, orgOidcAm, "org-subject-1", oidc.WithName("org-1"), oidc.WithDescription("org-1"))
	globalMg1 := oidc.TestManagedGroup(t, conn, globalOidcAm, oidc.TestFakeManagedGroupFilter, oidc.WithName("global-1"), oidc.WithDescription("global-1"))
	globalMg2 := oidc.TestManagedGroup(t, conn, globalOidcAm, oidc.TestFakeManagedGroupFilter, oidc.WithName("global-2"), oidc.WithDescription("global-2"))
	globalMg3 := oidc.TestManagedGroup(t, conn, globalOidcAm2, oidc.TestFakeManagedGroupFilter, oidc.WithName("global-3"), oidc.WithDescription("global-3"))
	orgOidcMg := oidc.TestManagedGroup(t, conn, orgOidcAm, oidc.TestFakeManagedGroupFilter, oidc.WithName("org-1"), oidc.WithDescription("org-1"))

	globalLdapAm := ldap.TestAuthMethod(t, conn, globalDBWrapper, globals.GlobalPrefix, []string{"ldaps://ldap1"}, ldap.WithName(ctx, "global"), ldap.WithDescription(ctx, "global"))
	orgLdapAm := ldap.TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://ldap2"}, ldap.WithName(ctx, "org"), ldap.WithDescription(ctx, "org"))
	orgLdapAm2 := ldap.TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://ldap3"}, ldap.WithName(ctx, "org2"), ldap.WithDescription(ctx, "org2"))

	_ = ldap.TestAccount(t, conn, orgLdapAm, "test-login-name-1", ldap.WithMemberOfGroups(ctx, "admin"), ldap.WithName(ctx, "org-1"), ldap.WithDescription(ctx, "org-1"))
	_ = ldap.TestAccount(t, conn, orgLdapAm2, "test-login-name-2", ldap.WithMemberOfGroups(ctx, "admin"), ldap.WithName(ctx, "org-2"), ldap.WithDescription(ctx, "org-2"))
	_ = ldap.TestManagedGroup(t, conn, orgLdapAm2, []string{"admin", "users"})
	orgLdapMg := ldap.TestManagedGroup(t, conn, orgLdapAm, []string{"admin", "users"}, ldap.WithName(ctx, "ldap-name"), ldap.WithDescription(ctx, "ldap-desc"))
	globalLdapMg := ldap.TestManagedGroup(t, conn, globalLdapAm, []string{"admin", "users"}, ldap.WithName(ctx, "globaldap-name"), ldap.WithDescription(ctx, "globaldap-desc"))

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name            string
			input           *pbs.ListManagedGroupsRequest
			userFunc        func() (*iam.User, a.Account)
			wantErr         error
			wantIDs         []string
			expectOutfields []string
		}{
			// oidc
			{
				name: "global role grant this returns all global oidc managed groups",
				input: &pbs.ListManagedGroupsRequest{
					AuthMethodId: globalOidcAm.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=managed-group;actions=list,read;output_fields=id,name,description"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr:         nil,
				wantIDs:         []string{globalMg1.PublicId, globalMg2.PublicId},
				expectOutfields: []string{globals.IdField, globals.NameField, globals.DescriptionField},
			},
			{
				name: "global role grant this and children only returns global oidc managed groups",
				input: &pbs.ListManagedGroupsRequest{
					AuthMethodId: globalOidcAm.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=managed-group;actions=list,read;output_fields=id,scope,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr:         nil,
				wantIDs:         []string{globalMg1.PublicId, globalMg2.PublicId},
				expectOutfields: []string{globals.IdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField},
			},
			{
				name: "global role grant this and descendents only returns global oidc managed groups",
				input: &pbs.ListManagedGroupsRequest{
					AuthMethodId: globalOidcAm.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=managed-group;actions=list,read;output_fields=id,version,type,auth_method_id"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantErr:         nil,
				wantIDs:         []string{globalMg1.PublicId, globalMg2.PublicId},
				expectOutfields: []string{globals.IdField, globals.VersionField, globals.TypeField, globals.AuthMethodIdField},
			},
			{
				name: "global role grant this everything only returns global oidc managed groups",
				input: &pbs.ListManagedGroupsRequest{
					AuthMethodId: globalOidcAm.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,attrs,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr:         nil,
				wantIDs:         []string{globalMg1.PublicId, globalMg2.PublicId},
				expectOutfields: []string{globals.IdField, "attrs", globals.AuthorizedActionsField},
			},
			{
				name: "global role grant this pinned id returns specific global oidc managed group",
				input: &pbs.ListManagedGroupsRequest{
					AuthMethodId: globalOidcAm2.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;type=managed-group;actions=*", globalOidcAm2.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: []string{globalMg3.PublicId},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
					globals.VersionField,
					globals.TypeField,
					globals.AuthMethodIdField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					"attrs",
					globals.AuthorizedActionsField,
					"oidc_managed_group_attributes",
				},
			},
			{
				name: "org role grant this only returns org oidc managed groups",
				input: &pbs.ListManagedGroupsRequest{
					AuthMethodId: orgOidcAm.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=managed-group;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: []string{orgOidcMg.PublicId},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
					globals.VersionField,
					globals.TypeField,
					globals.AuthMethodIdField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					"attrs",
					globals.AuthorizedActionsField,
					"oidc_managed_group_attributes",
				},
			},
			{
				name: "no list permission returns error",
				input: &pbs.ListManagedGroupsRequest{
					AuthMethodId: orgOidcAm.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=managed-group;actions=read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr:         handlers.ForbiddenError(),
				wantIDs:         nil,
				expectOutfields: nil,
			},
			{
				name: "global role not granted group resources returns error",
				input: &pbs.ListManagedGroupsRequest{
					AuthMethodId: orgOidcAm.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=target;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr:         handlers.ForbiddenError(),
				wantIDs:         nil,
				expectOutfields: nil,
			},
			// ldap
			{
				name: "global role grant this returns global created ldap managed group",
				input: &pbs.ListManagedGroupsRequest{
					AuthMethodId: globalLdapAm.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=managed-group;actions=list,read;output_fields=id,name,description"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: []string{
					globalLdapMg.PublicId,
				},
				expectOutfields: []string{globals.IdField, globals.NameField, globals.DescriptionField},
			},
			{
				name: "global role grant this pinned id returns global created ldap managed group",
				input: &pbs.ListManagedGroupsRequest{
					AuthMethodId: globalLdapAm.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;type=managed-group;actions=list,read;output_fields=id,scope,created_time,updated_time", globalLdapAm.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: []string{
					globalLdapMg.PublicId,
				},
				expectOutfields: []string{globals.IdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField},
			},
			{
				name: "global role grant this and children returns global created ldap managed group",
				input: &pbs.ListManagedGroupsRequest{
					AuthMethodId: globalLdapAm.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=managed-group;actions=list,read;output_fields=id,version,type,auth_method_id"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				wantIDs: []string{
					globalLdapMg.PublicId,
				},
				expectOutfields: []string{globals.IdField, globals.VersionField, globals.TypeField, globals.AuthMethodIdField},
			},
			{
				name: "global role grant this and descendants returns global created ldap managed group",
				input: &pbs.ListManagedGroupsRequest{
					AuthMethodId: globalLdapAm.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=managed-group;actions=list,read;output_fields=id,attrs,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantErr: nil,
				wantIDs: []string{
					globalLdapMg.PublicId,
				},
				expectOutfields: []string{globals.IdField, "attrs", globals.AuthorizedActionsField},
			},
			{
				name: "org role grant this returns all org ldap managed groups",
				input: &pbs.ListManagedGroupsRequest{
					AuthMethodId: orgLdapAm.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=managed-group;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				wantIDs: []string{
					orgLdapMg.PublicId,
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
					globals.VersionField,
					globals.TypeField,
					globals.AuthMethodIdField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					"attrs",
					globals.AuthorizedActionsField,
					"ldap_managed_group_attributes",
				},
			},
			{
				name: "no list permission returns error",
				input: &pbs.ListManagedGroupsRequest{
					AuthMethodId: orgOidcAm.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=managed-group;actions=read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr:         handlers.ForbiddenError(),
				wantIDs:         nil,
				expectOutfields: nil,
			},
			{
				name: "global role not granted group resources returns error",
				input: &pbs.ListManagedGroupsRequest{
					AuthMethodId: orgLdapAm.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=target;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr:         handlers.ForbiddenError(),
				wantIDs:         nil,
				expectOutfields: nil,
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, acct := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, finalErr := s.ListManagedGroups(fullGrantAuthCtx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, finalErr, tc.wantErr)
					return
				}
				require.NoError(t, finalErr)
				var gotIDs []string
				for _, g := range got.Items {
					gotIDs = append(gotIDs, g.GetId())
				}
				require.ElementsMatch(t, tc.wantIDs, gotIDs)
				for _, item := range got.Items {
					handlers.TestAssertOutputFields(t, item, tc.expectOutfields)
				}
			})
		}
	})
	t.Run("Get", func(t *testing.T) {
		testcases := []struct {
			name     string
			input    *pbs.GetManagedGroupRequest
			userFunc func() (*iam.User, a.Account)
			wantErr  error
			wantID   string
		}{
			// oidc
			{
				name: "global role grant this returns specific global oidc managed group",
				input: &pbs.GetManagedGroupRequest{
					Id: globalMg1.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantID:  globalMg1.PublicId,
			},
			{
				name: "global role grant pinned id returns specific global oidc managed group",
				input: &pbs.GetManagedGroupRequest{
					Id: globalMg2.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;type=managed-group;actions=read", globalOidcAm.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantID:  globalMg2.PublicId,
			},
			{
				name: "global role grant wrong pinned id returns error",
				input: &pbs.GetManagedGroupRequest{
					Id: globalMg2.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;type=managed-group;actions=list,read", globalOidcAm2.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
				wantID:  "",
			},
			{
				name: "org role grant this only returns error",
				input: &pbs.GetManagedGroupRequest{
					Id: orgOidcMg.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=managed-group;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
				wantID:  "",
			},
			{
				name: "org role grant this and children returns org",
				input: &pbs.GetManagedGroupRequest{
					Id: orgOidcMg.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=managed-group;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				wantID:  orgOidcMg.PublicId,
			},
			{
				name: "org role grant this and descendants returns org",
				input: &pbs.GetManagedGroupRequest{
					Id: orgOidcMg.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=managed-group;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantErr: nil,
				wantID:  orgOidcMg.PublicId,
			},
			// ldap
			{
				name: "global role grant this returns specific global ldap managed group",
				input: &pbs.GetManagedGroupRequest{
					Id: globalLdapMg.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantID:  globalLdapMg.PublicId,
			},
			{
				name: "global role grant pinned id returns specific global ldap managed group",
				input: &pbs.GetManagedGroupRequest{
					Id: globalLdapMg.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;type=managed-group;actions=read", globalLdapAm.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantID:  globalLdapMg.PublicId,
			},
			{
				name: "global role grant wrong pinned id returns error",
				input: &pbs.GetManagedGroupRequest{
					Id: globalLdapMg.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;type=managed-group;actions=list,read", globalOidcAm2.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
				wantID:  "",
			},
			{
				name: "org role grant this only returns error",
				input: &pbs.GetManagedGroupRequest{
					Id: orgLdapMg.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=managed-group;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
				wantID:  "",
			},
			{
				name: "org role grant this and children returns org",
				input: &pbs.GetManagedGroupRequest{
					Id: orgLdapMg.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=managed-group;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				wantID:  orgLdapMg.PublicId,
			},
			{
				name: "org role grant this and descendants returns org",
				input: &pbs.GetManagedGroupRequest{
					Id: orgLdapMg.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=managed-group;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantErr: nil,
				wantID:  orgLdapMg.PublicId,
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, acct := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, finalErr := s.GetManagedGroup(fullGrantAuthCtx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, finalErr, tc.wantErr)
					return
				}
				require.NoError(t, finalErr)
				require.Equal(t, tc.wantID, got.Item.Id)
			})
		}
	})
}

func TestGrants_WriteActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	oidcRepoFn := func() (*oidc.Repository, error) {
		// Use a small limit to test that membership lookup is explicitly unlimited
		return oidc.NewRepository(ctx, rw, rw, kmsCache, oidc.WithLimit(1))
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		// Use a small limit to test that membership lookup is explicitly unlimited
		return ldap.NewRepository(ctx, rw, rw, kmsCache, ldap.WithLimit(ctx, 1))
	}
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	s, err := managed_groups.NewService(ctx, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err)

	org, _ := iam.TestScopes(t, iamRepo)

	globalDBWrapper, err := kmsCache.GetWrapper(ctx, globals.GlobalPrefix, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	orgDBWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	globalOidcAm := oidc.TestAuthMethod(
		t, conn, globalDBWrapper, globals.GlobalPrefix, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	orgOidcAm1 := oidc.TestAuthMethod(
		t, conn, orgDBWrapper, org.PublicId, oidc.ActivePrivateState,
		"alice_rp_2", "alices-dogs-name",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice-org.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api.com")[0]),
	)
	orgOidcAm2 := oidc.TestAuthMethod(
		t, conn, orgDBWrapper, org.PublicId, oidc.ActivePrivateState,
		"alice_rp_3", "alices-dogs-name",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice-oraoeug.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://apiaoeu.com")[0]),
	)
	globalLdapAm := ldap.TestAuthMethod(t, conn, globalDBWrapper, globals.GlobalPrefix, []string{"ldaps://ldap1"}, ldap.WithName(ctx, "global"), ldap.WithDescription(ctx, "global"))
	orgLdapAm1 := ldap.TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://ldap2"}, ldap.WithName(ctx, "org"), ldap.WithDescription(ctx, "org"))
	orgLdapAm2 := ldap.TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://ldap3"}, ldap.WithName(ctx, "org2"), ldap.WithDescription(ctx, "org2"))

	t.Run("create oidc", func(t *testing.T) {
		testcases := []struct {
			name                     string
			userFunc                 func() (*iam.User, a.Account)
			authmethodIdExpectErrMap map[string]error
		}{
			// oidc
			{
				name: "oidc global role grant this and children can create managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				authmethodIdExpectErrMap: map[string]error{
					globalOidcAm.PublicId: nil,
					orgOidcAm1.PublicId:   nil,
					orgOidcAm2.PublicId:   nil,
				},
			},
			{
				name: "oidc global role grant this and descendants can create managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				authmethodIdExpectErrMap: map[string]error{
					globalOidcAm.PublicId: nil,
					orgOidcAm1.PublicId:   nil,
					orgOidcAm2.PublicId:   nil,
				},
			},
			{
				name: "oidc global role grant this only global can create managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				authmethodIdExpectErrMap: map[string]error{
					globalOidcAm.PublicId: nil,
					orgOidcAm1.PublicId:   handlers.ForbiddenError(),
					orgOidcAm2.PublicId:   handlers.ForbiddenError(),
				},
			},
			{
				name: "oidc children at global can create accounts in org",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				authmethodIdExpectErrMap: map[string]error{
					globalOidcAm.PublicId: handlers.ForbiddenError(),
					orgOidcAm1.PublicId:   nil,
					orgOidcAm2.PublicId:   nil,
				},
			},
			{
				name: "oidc descendant at global can create accounts in org",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				authmethodIdExpectErrMap: map[string]error{
					globalOidcAm.PublicId: handlers.ForbiddenError(),
					orgOidcAm1.PublicId:   nil,
					orgOidcAm2.PublicId:   nil,
				},
			},
			{
				name: "oidc pinned org1 grant can only create accounts in org1",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;type=managed-group;actions=create", orgOidcAm1.PublicId)},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				authmethodIdExpectErrMap: map[string]error{
					globalOidcAm.PublicId: handlers.ForbiddenError(),
					orgOidcAm1.PublicId:   nil,
					orgOidcAm2.PublicId:   handlers.ForbiddenError(),
				},
			},
			{
				name: "oidc target type does not allow create managed group",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=target;actions=*"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				authmethodIdExpectErrMap: map[string]error{
					globalOidcAm.PublicId: handlers.ForbiddenError(),
					orgOidcAm1.PublicId:   handlers.ForbiddenError(),
					orgOidcAm2.PublicId:   handlers.ForbiddenError(),
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, acct := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				for am, wantErr := range tc.authmethodIdExpectErrMap {
					name, err := uuid.GenerateUUID()
					require.NoError(t, err)
					item := &pbs.CreateManagedGroupRequest{
						Item: &pb.ManagedGroup{
							AuthMethodId: am,
							Name:         &wrapperspb.StringValue{Value: name},
							Description:  &wrapperspb.StringValue{Value: "desc"},
							Type:         oidc.Subtype.String(),
							Attrs: &pb.ManagedGroup_OidcManagedGroupAttributes{
								OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
									Filter: oidc.TestFakeManagedGroupFilter,
								},
							},
						},
					}
					got, err := s.CreateManagedGroup(fullGrantAuthCtx, item)
					if wantErr != nil {
						require.ErrorIs(t, err, wantErr)
						continue
					}
					require.NoError(t, err)
					require.NotNil(t, got)
				}
			})
		}
	})
	t.Run("create ldap", func(t *testing.T) {
		testcases := []struct {
			name                     string
			userFunc                 func() (*iam.User, a.Account)
			authmethodIdExpectErrMap map[string]error
		}{
			{
				name: "ldap global role grant this and children can create managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				authmethodIdExpectErrMap: map[string]error{
					globalLdapAm.PublicId: nil,
					orgLdapAm1.PublicId:   nil,
					orgLdapAm2.PublicId:   nil,
				},
			},
			{
				name: "ldap global role grant this and descendants can create managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				authmethodIdExpectErrMap: map[string]error{
					globalLdapAm.PublicId: nil,
					orgLdapAm1.PublicId:   nil,
					orgLdapAm2.PublicId:   nil,
				},
			},
			{
				name: "ldap global role grant this only global can create managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				authmethodIdExpectErrMap: map[string]error{
					globalLdapAm.PublicId: nil,
					orgLdapAm1.PublicId:   handlers.ForbiddenError(),
					orgLdapAm2.PublicId:   handlers.ForbiddenError(),
				},
			},
			{
				name: "ldap children at global can create accounts in org",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				authmethodIdExpectErrMap: map[string]error{
					globalLdapAm.PublicId: handlers.ForbiddenError(),
					orgLdapAm1.PublicId:   nil,
					orgLdapAm2.PublicId:   nil,
				},
			},
			{
				name: "ldap descendant at global can create accounts in org",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				authmethodIdExpectErrMap: map[string]error{
					globalLdapAm.PublicId: handlers.ForbiddenError(),
					orgLdapAm1.PublicId:   nil,
					orgLdapAm2.PublicId:   nil,
				},
			},
			{
				name: "ldap pinned org1 grant can only create accounts in org1",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;type=managed-group;actions=create", orgLdapAm1.PublicId)},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				authmethodIdExpectErrMap: map[string]error{
					globalLdapAm.PublicId: handlers.ForbiddenError(),
					orgLdapAm1.PublicId:   nil,
					orgLdapAm2.PublicId:   handlers.ForbiddenError(),
				},
			},
			{
				name: "ldap target type does not allow create managed group",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=target;actions=*"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				authmethodIdExpectErrMap: map[string]error{
					globalLdapAm.PublicId: handlers.ForbiddenError(),
					orgLdapAm1.PublicId:   handlers.ForbiddenError(),
					orgLdapAm2.PublicId:   handlers.ForbiddenError(),
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, acct := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				for am, wantErr := range tc.authmethodIdExpectErrMap {
					name, err := uuid.GenerateUUID()
					require.NoError(t, err)
					item := &pbs.CreateManagedGroupRequest{
						Item: &pb.ManagedGroup{
							AuthMethodId: am,
							Name:         &wrapperspb.StringValue{Value: name},
							Description:  &wrapperspb.StringValue{Value: "desc"},
							Type:         ldap.Subtype.String(),
							Attrs: &pb.ManagedGroup_LdapManagedGroupAttributes{
								LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
									GroupNames: []string{"admin", "users"},
								},
							},
						},
					}
					got, err := s.CreateManagedGroup(fullGrantAuthCtx, item)
					if wantErr != nil {
						require.ErrorIs(t, err, wantErr)
						continue
					}
					require.NoError(t, err)
					require.NotNil(t, got)
				}
			})
		}
	})
	t.Run("update oidc", func(t *testing.T) {
		testcases := []struct {
			name     string
			userFunc func() (*iam.User, a.Account)
			wantErr  error
		}{
			{
				name: "oidc global role grant this can update managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
			},
			{
				name: "oidc global role grant this and children can update managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=managed-group;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
			},
			{
				name: "oidc global role grant this and descendants can update managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=update"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantErr: nil,
			},
			{
				name: "oidc global role pinned id grant this can update managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;type=managed-group;actions=*", globalOidcAm.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
			},
			{
				name: "oidc global role grant this cannot update managed groups in org scope",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{org.PublicId},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				mg := oidc.TestManagedGroup(t, conn, globalOidcAm, oidc.TestFakeManagedGroupFilter, oidc.WithName("default"), oidc.WithDescription("default"))
				user, acct := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				name, err := uuid.GenerateUUID()
				require.NoError(t, err)
				item := &pbs.UpdateManagedGroupRequest{
					UpdateMask: &field_mask.FieldMask{
						Paths: []string{globals.NameField, globals.DescriptionField},
					},
					Id: mg.GetPublicId(),
					Item: &pb.ManagedGroup{
						Version:     1,
						Name:        &wrapperspb.StringValue{Value: name},
						Description: &wrapperspb.StringValue{Value: "desc"},
						Type:        oidc.Subtype.String(),
					},
				}
				got, err := s.UpdateManagedGroup(fullGrantAuthCtx, item)
				if tc.wantErr != nil {
					require.ErrorIs(t, err, tc.wantErr)
					return
				}
				require.NoError(t, err)
				require.NotNil(t, got)
			})
		}
	})
	t.Run("update ldap", func(t *testing.T) {
		testcases := []struct {
			name     string
			userFunc func() (*iam.User, a.Account)
			wantErr  error
		}{
			{
				name: "ldap global role grant this can update managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
			},
			{
				name: "ldap global role grant this and chlidren can update managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
			},
			{
				name: "ldap global role grant this and descendants can update managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantErr: nil,
			},
			{
				name: "ldap global role pinned id grant this specific can update managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;type=managed-group;actions=*", globalLdapAm.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
			},
			{
				name: "ldap global role grant this specific can update managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=update"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
			},
			{
				name: "ldap global role grant this cannot update managed groups in org scope",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{org.PublicId},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				mg := ldap.TestManagedGroup(t, conn, globalLdapAm, []string{"admin", "users"}, ldap.WithName(ctx, "default"), ldap.WithDescription(ctx, "default"))
				user, acct := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				name, err := uuid.GenerateUUID()
				require.NoError(t, err)
				item := &pbs.UpdateManagedGroupRequest{
					UpdateMask: &field_mask.FieldMask{
						Paths: []string{globals.NameField, globals.DescriptionField},
					},
					Id: mg.GetPublicId(),
					Item: &pb.ManagedGroup{
						Version:     1,
						Name:        &wrapperspb.StringValue{Value: name},
						Description: &wrapperspb.StringValue{Value: "desc"},
						Type:        ldap.Subtype.String(),
					},
				}
				got, err := s.UpdateManagedGroup(fullGrantAuthCtx, item)
				if tc.wantErr != nil {
					require.ErrorIs(t, err, tc.wantErr)
					return
				}
				require.NoError(t, err)
				require.NotNil(t, got)
			})
		}
	})
	t.Run("delete", func(t *testing.T) {
		testcases := []struct {
			name     string
			userFunc func() (*iam.User, a.Account)
			wantErr  error
			mg       a.ManagedGroup
		}{
			{
				name: "oidc global role grant this can delete managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				mg:      oidc.TestManagedGroup(t, conn, globalOidcAm, oidc.TestFakeManagedGroupFilter),
			},
			{
				name: "oidc global role grant this and children can delete managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=managed-group;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				mg:      oidc.TestManagedGroup(t, conn, globalOidcAm, oidc.TestFakeManagedGroupFilter),
			},
			{
				name: "oidc global role grant this and descendants can delete managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=managed-group;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantErr: nil,
				mg:      oidc.TestManagedGroup(t, conn, globalOidcAm, oidc.TestFakeManagedGroupFilter),
			},
			{
				name: "oidc org role grant this can delete managed groups in org scope",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{org.PublicId},
					},
				}),
				wantErr: nil,
				mg:      oidc.TestManagedGroup(t, conn, orgOidcAm1, oidc.TestFakeManagedGroupFilter),
			},
			{
				name: "oidc global role grant this cannot delete managed groups in org scope",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{org.PublicId},
					},
				}),
				wantErr: handlers.ForbiddenError(),
				mg:      oidc.TestManagedGroup(t, conn, globalOidcAm, oidc.TestFakeManagedGroupFilter),
			},
			{
				name: "ldap global role grant this can delete managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				mg:      ldap.TestManagedGroup(t, conn, globalLdapAm, []string{"admin", "users"}),
			},
			{
				name: "ldap global role grant this and children can delete managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=managed-group;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				mg:      ldap.TestManagedGroup(t, conn, globalLdapAm, []string{"admin", "users"}),
			},
			{
				name: "ldap global role grant this and descendants can delete managed groups everywhere",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=managed-group;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantErr: nil,
				mg:      ldap.TestManagedGroup(t, conn, globalLdapAm, []string{"admin", "users"}),
			},
			{
				name: "ldap global role grant this cannot delete wrong type",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=target;actions=delete"},
						GrantScopes: []string{org.PublicId},
					},
				}),
				wantErr: handlers.ForbiddenError(),
				mg:      ldap.TestManagedGroup(t, conn, globalLdapAm, []string{"admin", "users"}),
			},
			{
				name: "ldap global role grant this cannot delete managed groups in org scope",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{org.PublicId},
					},
				}),
				wantErr: handlers.ForbiddenError(),
				mg:      ldap.TestManagedGroup(t, conn, globalLdapAm, []string{"admin", "users"}),
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, acct := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

				req := &pbs.DeleteManagedGroupRequest{
					Id: tc.mg.GetPublicId(),
				}
				_, err = s.DeleteManagedGroup(fullGrantAuthCtx, req)
				if tc.wantErr != nil {
					require.ErrorIs(t, err, tc.wantErr)
					return
				}
				require.NoError(t, err)
			})
		}
	})
}
