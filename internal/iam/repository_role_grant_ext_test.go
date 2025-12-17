// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/resource"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGrantsForUser tests GrantsForUser function. This is an external package test to avoid
// cyclic import with github.com/hashicorp/boundary/internal/auth/ldap and github.com/hashicorp/boundary/internal/auth/oidc
func TestGrantsForUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	type arg struct {
		userId         string
		resourceType   []resource.Type
		requestScopeId string
		opt            []iam.Option
	}
	testcases := []struct {
		name             string
		setupInputExpect func(t *testing.T, repo *iam.Repository, conn *db.DB, wrapper wrapping.Wrapper) (arg, perms.GrantTuples)
		wantErr          bool
		wantErrMsg       string
	}{
		{
			name: "one role multiple grants return each individually",
			setupInputExpect: func(t *testing.T, repo *iam.Repository, conn *db.DB, wrapper wrapping.Wrapper) (arg, perms.GrantTuples) {
				user := iam.TestUser(t, repo, "global")
				role1 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix, []string{globals.GrantScopeThis},
					[]string{
						"ids=*;type=role;actions=list",
						"ids=*;type=role;actions=read",
						"ids=*;type=role;actions=delete",
						"ids=*;type=role;actions=add-principals",
						"ids=*;type=role;actions=remove-principals",
						"ids=*;type=role;actions=set-grant-scopes",
					})
				iam.TestUserRole(t, conn, role1.PublicId, user.PublicId)
				return arg{
						userId:         user.PublicId,
						resourceType:   []resource.Type{resource.Role},
						requestScopeId: globals.GlobalPrefix,
					},
					perms.GrantTuples{
						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GlobalPrefix,
							Grant:             "ids=*;type=role;actions=list",
						},
						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GlobalPrefix,
							Grant:             "ids=*;type=role;actions=read",
						},

						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GlobalPrefix,
							Grant:             "ids=*;type=role;actions=delete",
						},

						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GlobalPrefix,
							Grant:             "ids=*;type=role;actions=add-principals",
						},
						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GlobalPrefix,
							Grant:             "ids=*;type=role;actions=remove-principals",
						},
						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GlobalPrefix,
							Grant:             "ids=*;type=role;actions=set-grant-scopes",
						},
					}
			},
		},
		{
			name: "multiple roles return individual role grant",
			setupInputExpect: func(t *testing.T, repo *iam.Repository, conn *db.DB, wrapper wrapping.Wrapper) (arg, perms.GrantTuples) {
				user := iam.TestUser(t, repo, "global")
				role1 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=auth-method;actions=read"})
				role2 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=auth-method;actions=read"})
				role3 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=auth-method;actions=read"})
				role4 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=auth-method;actions=read"})
				role5 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=auth-method;actions=read"})
				role6 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=auth-method;actions=read"})
				iam.TestUserRole(t, conn, role1.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, role2.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, role3.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, role4.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, role5.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, role6.PublicId, user.PublicId)
				return arg{
						userId:         user.PublicId,
						resourceType:   []resource.Type{resource.AuthMethod},
						requestScopeId: globals.GlobalPrefix,
					}, perms.GrantTuples{
						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      role1.ScopeId,
							Grant:             "ids=*;type=auth-method;actions=read",
						},
						{
							RoleId:            role2.PublicId,
							RoleScopeId:       role2.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      role2.ScopeId,
							Grant:             "ids=*;type=auth-method;actions=read",
						},
						{
							RoleId:            role3.PublicId,
							RoleScopeId:       role3.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      role3.ScopeId,
							Grant:             "ids=*;type=auth-method;actions=read",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      role4.ScopeId,
							Grant:             "ids=*;type=auth-method;actions=read",
						},
						{
							RoleId:            role5.PublicId,
							RoleScopeId:       role5.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      role5.ScopeId,
							Grant:             "ids=*;type=auth-method;actions=read",
						},
						{
							RoleId:            role6.PublicId,
							RoleScopeId:       role6.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      role6.ScopeId,
							Grant:             "ids=*;type=auth-method;actions=read",
						},
					}
			},
		},
		{
			name: "global only resource (worker) global scope request",
			setupInputExpect: func(t *testing.T, repo *iam.Repository, conn *db.DB, wrapper wrapping.Wrapper) (arg, perms.GrantTuples) {
				kmsCache := kms.TestKms(t, conn, wrapper)
				databaseWrapper, err := kmsCache.GetWrapper(ctx, globals.GlobalPrefix, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				oidcAuthMethod := oidc.TestAuthMethod(
					t, conn, databaseWrapper, globals.GlobalPrefix, oidc.ActivePrivateState,
					"alice-rp", "fido",
					oidc.WithSigningAlgs(oidc.RS256),
					oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
					oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
				id, err := uuid.GenerateUUID()
				require.NoError(t, err)
				oidcAcct := oidc.TestAccount(t, conn, oidcAuthMethod, id)
				oidcMgmtGroup := oidc.TestManagedGroup(t, conn, oidcAuthMethod, oidc.TestFakeManagedGroupFilter, oidc.WithName(id))

				ldapAuthMethod := ldap.TestAuthMethod(t, conn, databaseWrapper, globals.GlobalPrefix, []string{"ldap://test-" + id})
				ldapMgmtGroup := ldap.TestManagedGroup(t, conn, ldapAuthMethod, []string{id}, ldap.WithName(ctx, id))
				ldapAccount := ldap.TestAccount(t, conn, ldapAuthMethod, id, ldap.WithMemberOfGroups(ctx, id))
				user := iam.TestUser(t, repo, "global", iam.WithAccountIds(oidcAcct.PublicId, ldapAccount.PublicId))
				oidc.TestManagedGroupMember(t, conn, oidcMgmtGroup.PublicId, oidcAcct.PublicId)

				org, proj := iam.TestScopes(t, repo)
				org2, proj2 := iam.TestScopes(t, repo)
				proj3 := iam.TestProject(t, repo, org.PublicId)
				proj4 := iam.TestProject(t, repo, org.PublicId)

				// ======= these roles are expected in the result ========
				role1 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					[]string{"ids=*;type=*;actions=*"})
				role2 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeChildren, proj.PublicId, proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=*;type=worker;actions=read"})
				role3 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, org.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=hcplg_Ia7R4E39oF;actions=read"})
				role4 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, org.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=*;type=worker;actions=list"})
				iam.TestManagedGroupRole(t, conn, role1.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role2.PublicId, oidcMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role3.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role4.PublicId, oidcMgmtGroup.PublicId)

				// ========================================================
				// add random grants and scopes to ensure that unnecessary grants aren't returned
				// ======= these roles are not expected ========
				// superset of scope but incorrect type
				unnecessaryRole1 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					[]string{"ids=*;type=account;actions=*"})
				// superset of scope but incorrect type
				unnecessaryRole2 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeDescendants},
					[]string{"ids=*;type=auth-method;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole3 := iam.TestRoleWithGrants(t, conn, org2.PublicId,
					[]string{globals.GrantScopeChildren},
					[]string{"ids=*;type=host;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole4 := iam.TestRoleWithGrants(t, conn, proj2.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=host-set;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole5 := iam.TestRoleWithGrants(t, conn, proj3.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=credential;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole6 := iam.TestRoleWithGrants(t, conn, proj4.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=credential-store;actions=*"})
				// correct scope wrong type
				unnecessaryRole7 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{proj.PublicId},
					[]string{"ids=*;type=target;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole8 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=*;type=group;actions=*"})
				iam.TestManagedGroupRole(t, conn, unnecessaryRole1.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, unnecessaryRole2.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, unnecessaryRole3.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, unnecessaryRole4.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, unnecessaryRole5.PublicId, oidcMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, unnecessaryRole6.PublicId, oidcMgmtGroup.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole7.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole8.PublicId, user.PublicId)

				// valid role but not associated to the user
				iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					[]string{"ids=*;type=*;actions=*"})
				return arg{
						userId:         user.PublicId,
						resourceType:   []resource.Type{resource.Worker},
						requestScopeId: globals.GlobalPrefix,
					}, perms.GrantTuples{
						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      role1.ScopeId,
							Grant:             "ids=*;type=*;actions=*",
						},
						{
							RoleId:            role2.PublicId,
							RoleScopeId:       role2.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      role2.ScopeId,
							Grant:             "ids=*;type=worker;actions=read",
						},
						{
							RoleId:            role3.PublicId,
							RoleScopeId:       role3.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      role3.ScopeId,
							Grant:             "ids=hcplg_Ia7R4E39oF;actions=read",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      role4.ScopeId,
							Grant:             "ids=*;type=worker;actions=list",
						},
					}
			},
		},
		{
			name: "global only resource (worker) org scope request",
			setupInputExpect: func(t *testing.T, repo *iam.Repository, conn *db.DB, wrapper wrapping.Wrapper) (arg, perms.GrantTuples) {
				user := iam.TestUser(t, repo, globals.GlobalPrefix)
				org := iam.TestOrg(t, repo)
				return arg{
					userId:         user.PublicId,
					resourceType:   []resource.Type{resource.Worker},
					requestScopeId: org.PublicId,
				}, perms.GrantTuples{}
			},
			wantErr:    true,
			wantErrMsg: "iam.(Repository).GrantsForUser: unable to resolve query: iam.(Repository).resolveQuery: request scope id must be global for [worker] resources: parameter violation: error #100",
		},
		{
			name: "global only resource (billing) project scope request",
			setupInputExpect: func(t *testing.T, repo *iam.Repository, conn *db.DB, wrapper wrapping.Wrapper) (arg, perms.GrantTuples) {
				user := iam.TestUser(t, repo, globals.GlobalPrefix)
				_, proj := iam.TestScopes(t, repo)
				return arg{
					userId:         user.PublicId,
					resourceType:   []resource.Type{resource.Billing},
					requestScopeId: proj.PublicId,
				}, perms.GrantTuples{}
			},
			wantErr:    true,
			wantErrMsg: "iam.(Repository).GrantsForUser: unable to resolve query: iam.(Repository).resolveQuery: request scope id must be global for [billing] resources: parameter violation: error #100",
		},
		{
			name: "global org and project resource (role) global scope request recursive",
			setupInputExpect: func(t *testing.T, repo *iam.Repository, conn *db.DB, wrapper wrapping.Wrapper) (arg, perms.GrantTuples) {
				kmsCache := kms.TestKms(t, conn, wrapper)
				databaseWrapper, err := kmsCache.GetWrapper(ctx, globals.GlobalPrefix, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				oidcAuthMethod := oidc.TestAuthMethod(
					t, conn, databaseWrapper, globals.GlobalPrefix, oidc.ActivePrivateState,
					"alice-rp", "fido",
					oidc.WithSigningAlgs(oidc.RS256),
					oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice1.com")[0]),
					oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice1.com/callback")[0]),
				)
				id, err := uuid.GenerateUUID()
				group := iam.TestGroup(t, conn, globals.GlobalPrefix)
				require.NoError(t, err)
				oidcAcct := oidc.TestAccount(t, conn, oidcAuthMethod, id)
				oidcMgmtGroup := oidc.TestManagedGroup(t, conn, oidcAuthMethod, oidc.TestFakeManagedGroupFilter, oidc.WithName(id))
				ldapAuthMethod := ldap.TestAuthMethod(t, conn, databaseWrapper, globals.GlobalPrefix, []string{"ldap://test-" + id})
				ldapMgmtGroup := ldap.TestManagedGroup(t, conn, ldapAuthMethod, []string{id}, ldap.WithName(ctx, id))
				ldapAccount := ldap.TestAccount(t, conn, ldapAuthMethod, id, ldap.WithMemberOfGroups(ctx, id))
				user := iam.TestUser(t, repo, "global", iam.WithAccountIds(oidcAcct.PublicId, ldapAccount.PublicId))
				iam.TestGroupMember(t, conn, group.PublicId, user.PublicId)
				oidc.TestManagedGroupMember(t, conn, oidcMgmtGroup.PublicId, oidcAcct.PublicId)
				org, proj := iam.TestScopes(t, repo)
				org2, proj2 := iam.TestScopes(t, repo)
				proj3 := iam.TestProject(t, repo, org.PublicId)
				proj4 := iam.TestProject(t, repo, org.PublicId)

				// ======= these roles are expected in the result ========
				//  descendants grant
				role1 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					[]string{"ids=*;type=*;actions=*"})
				// children grant
				role2 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeChildren},
					[]string{"ids=*;type=role;actions=read"})
				// this grant
				role3 := iam.TestRoleWithGrants(t, conn, org.PublicId,
					[]string{globals.GrantScopeThis, globals.GrantScopeChildren},
					[]string{"ids=*;type=role;actions=list"})
				// direct grant
				role4 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{org.PublicId, org2.PublicId, proj.PublicId, proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=*;type=role;actions=update"})
				// pinned id grant (descendants) - resource type = unknown
				role5 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeDescendants},
					[]string{"ids=tssh_123456;actions=authorize-session"})
				// pinned id grant (children) - different resource type also included because resource type = unknown
				role6 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeChildren, proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=hst_123456;actions=read"})
				// pinned id grant (this) - different resource type also included because resource type = unknown
				role7 := iam.TestRoleWithGrants(t, conn, org.PublicId,
					[]string{globals.GrantScopeThis, proj.PublicId, proj3.PublicId},
					[]string{"ids=ttcp_123456;actions=delete"})
				// pinned id grant (this) - different resource type also included because resource type = unknown
				role8 := iam.TestRoleWithGrants(t, conn, proj4.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=ttcp_123456;actions=delete"})
				//  this grant - only 1 relevant grant
				role9 := iam.TestRoleWithGrants(t, conn, proj2.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{
						"ids=*;type=role;actions=set-principals",
						"ids=*;type=auth-token;actions=update",
						"ids=*;type=user;actions=update",
						"ids=*;type=billing;actions=update",
					})

				iam.TestManagedGroupRole(t, conn, role1.PublicId, oidcMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role2.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role3.PublicId, oidcMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role4.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role5.PublicId, oidcMgmtGroup.PublicId)
				iam.TestGroupRole(t, conn, role6.PublicId, group.PublicId)
				iam.TestGroupRole(t, conn, role7.PublicId, group.PublicId)
				iam.TestUserRole(t, conn, role8.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, role9.PublicId, user.PublicId)
				// ========================================================

				// add random grants and scopes to ensure that unnecessary grants aren't returned
				// ======= these roles are not expected ========
				// correct scope incorrect type
				unnecessaryRole1 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					[]string{"ids=*;type=target;actions=*"})
				unnecessaryRole2 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeChildren},
					[]string{"ids=*;type=auth-method;actions=*"})
				unnecessaryRole3 := iam.TestRoleWithGrants(t, conn, org2.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=account;actions=*"})
				unnecessaryRole4 := iam.TestRoleWithGrants(t, conn, proj2.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=host-set;actions=*"})
				unnecessaryRole5 := iam.TestRoleWithGrants(t, conn, proj3.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=host;actions=*"})
				unnecessaryRole6 := iam.TestRoleWithGrants(t, conn, proj4.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=auth-token;actions=*"})
				unnecessaryRole7 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{proj.PublicId},
					[]string{"ids=*;type=credential;actions=*"})
				unnecessaryRole8 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=*;type=target;actions=*"})

				iam.TestManagedGroupRole(t, conn, unnecessaryRole1.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, unnecessaryRole2.PublicId, oidcMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, unnecessaryRole3.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, unnecessaryRole4.PublicId, oidcMgmtGroup.PublicId)
				iam.TestGroupRole(t, conn, unnecessaryRole5.PublicId, group.PublicId)
				iam.TestGroupRole(t, conn, unnecessaryRole6.PublicId, group.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole7.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole8.PublicId, user.PublicId)

				return arg{
						userId:         user.PublicId,
						resourceType:   []resource.Type{resource.Role},
						requestScopeId: globals.GlobalPrefix,
						opt:            []iam.Option{iam.WithRecursive(true)},
					}, perms.GrantTuples{
						// role 1
						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      role1.ScopeId,
							Grant:             "ids=*;type=*;actions=*",
						},
						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeDescendants,
							Grant:             "ids=*;type=*;actions=*",
						},
						// role 2
						{
							RoleId:            role2.PublicId,
							RoleScopeId:       role2.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeChildren,
							Grant:             "ids=*;type=role;actions=read",
						},
						// role 3
						{
							RoleId:            role3.PublicId,
							RoleScopeId:       role3.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      role3.ScopeId,
							Grant:             "ids=*;type=role;actions=list",
						},
						{
							RoleId:            role3.PublicId,
							RoleScopeId:       role3.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      globals.GrantScopeChildren,
							Grant:             "ids=*;type=role;actions=list",
						},
						// role 4
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      org.PublicId,
							Grant:             "ids=*;type=role;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      org2.PublicId,
							Grant:             "ids=*;type=role;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj.PublicId,
							Grant:             "ids=*;type=role;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj2.PublicId,
							Grant:             "ids=*;type=role;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj3.PublicId,
							Grant:             "ids=*;type=role;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj4.PublicId,
							Grant:             "ids=*;type=role;actions=update",
						},
						// role 5
						{
							RoleId:            role5.PublicId,
							RoleScopeId:       role5.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeDescendants,
							Grant:             "ids=tssh_123456;actions=authorize-session",
						},
						// role 6
						{
							RoleId:            role6.PublicId,
							RoleScopeId:       role6.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeChildren,
							Grant:             "ids=hst_123456;actions=read",
						},
						{
							RoleId:            role6.PublicId,
							RoleScopeId:       role6.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj2.PublicId,
							Grant:             "ids=hst_123456;actions=read",
						},
						{
							RoleId:            role6.PublicId,
							RoleScopeId:       role6.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj3.PublicId,
							Grant:             "ids=hst_123456;actions=read",
						},
						{
							RoleId:            role6.PublicId,
							RoleScopeId:       role6.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj4.PublicId,
							Grant:             "ids=hst_123456;actions=read",
						},
						// role 7
						{
							RoleId:            role7.PublicId,
							RoleScopeId:       role7.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      role7.ScopeId,
							Grant:             "ids=ttcp_123456;actions=delete",
						},
						{
							RoleId:            role7.PublicId,
							RoleScopeId:       role7.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      proj.PublicId,
							Grant:             "ids=ttcp_123456;actions=delete",
						},
						{
							RoleId:            role7.PublicId,
							RoleScopeId:       role7.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      proj3.PublicId,
							Grant:             "ids=ttcp_123456;actions=delete",
						},
						// role 8
						{
							RoleId:            role8.PublicId,
							RoleScopeId:       role8.ScopeId,
							RoleParentScopeId: org.PublicId,
							GrantScopeId:      role8.ScopeId,
							Grant:             "ids=ttcp_123456;actions=delete",
						},
						// role 9
						{
							RoleId:            role9.PublicId,
							RoleScopeId:       role9.ScopeId,
							RoleParentScopeId: org2.PublicId,
							GrantScopeId:      role9.ScopeId,
							Grant:             "ids=*;type=role;actions=set-principals",
						},
					}
			},
		},
		{
			name: "global org and project resource (role) org scope request recursive",
			setupInputExpect: func(t *testing.T, repo *iam.Repository, conn *db.DB, wrapper wrapping.Wrapper) (arg, perms.GrantTuples) {
				kmsCache := kms.TestKms(t, conn, wrapper)
				databaseWrapper, err := kmsCache.GetWrapper(ctx, globals.GlobalPrefix, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				oidcAuthMethod := oidc.TestAuthMethod(
					t, conn, databaseWrapper, globals.GlobalPrefix, oidc.ActivePrivateState,
					"alice-rp", "fido",
					oidc.WithSigningAlgs(oidc.RS256),
					oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
					oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
				id, err := uuid.GenerateUUID()
				group := iam.TestGroup(t, conn, globals.GlobalPrefix)
				require.NoError(t, err)
				oidcAcct := oidc.TestAccount(t, conn, oidcAuthMethod, id)
				oidcMgmtGroup := oidc.TestManagedGroup(t, conn, oidcAuthMethod, oidc.TestFakeManagedGroupFilter, oidc.WithName(id))
				ldapAuthMethod := ldap.TestAuthMethod(t, conn, databaseWrapper, globals.GlobalPrefix, []string{"ldap://test-" + id})
				ldapMgmtGroup := ldap.TestManagedGroup(t, conn, ldapAuthMethod, []string{id}, ldap.WithName(ctx, id))
				ldapAccount := ldap.TestAccount(t, conn, ldapAuthMethod, id, ldap.WithMemberOfGroups(ctx, id))
				user := iam.TestUser(t, repo, "global", iam.WithAccountIds(oidcAcct.PublicId, ldapAccount.PublicId))
				iam.TestGroupMember(t, conn, group.PublicId, user.PublicId)
				oidc.TestManagedGroupMember(t, conn, oidcMgmtGroup.PublicId, oidcAcct.PublicId)
				org, proj := iam.TestScopes(t, repo)
				org2, proj2 := iam.TestScopes(t, repo)
				proj3 := iam.TestProject(t, repo, org.PublicId)
				proj4 := iam.TestProject(t, repo, org.PublicId)

				// ======= these roles are expected in the result ========
				//  descendants grant
				role1 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					[]string{"ids=*;type=*;actions=*"})
				// children grant
				role2 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeChildren},
					[]string{"ids=*;type=role;actions=read"})
				// this grant
				role3 := iam.TestRoleWithGrants(t, conn, org.PublicId,
					[]string{globals.GrantScopeThis, globals.GrantScopeChildren},
					[]string{"ids=*;type=role;actions=list"})
				// direct grant
				role4 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{org.PublicId, org2.PublicId, proj.PublicId, proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=*;type=role;actions=update"})
				// pinned id grant (descendants) - resource type = unknown
				role5 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeDescendants},
					[]string{"ids=tssh_123456;actions=authorize-session"})
				// pinned id grant (children) - different resource type also included because resource type = unknown
				role6 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeChildren, proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=hst_123456;actions=read"})
				// pinned id grant (this) - different resource type also included because resource type = unknown
				role7 := iam.TestRoleWithGrants(t, conn, org.PublicId,
					[]string{globals.GrantScopeThis, proj.PublicId, proj3.PublicId},
					[]string{"ids=ttcp_123456;actions=delete"})
				// pinned id grant (this) - different resource type also included because resource type = unknown
				role8 := iam.TestRoleWithGrants(t, conn, proj4.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=ttcp_123456;actions=delete"})
				//  this grant - only 1 relevant grant
				role9 := iam.TestRoleWithGrants(t, conn, proj3.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{
						"ids=*;type=role;actions=set-principals",
						"ids=*;type=auth-token;actions=update",
						"ids=*;type=user;actions=update",
						"ids=*;type=billing;actions=update",
					})

				iam.TestManagedGroupRole(t, conn, role1.PublicId, oidcMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role2.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role3.PublicId, oidcMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role4.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role5.PublicId, oidcMgmtGroup.PublicId)
				iam.TestGroupRole(t, conn, role6.PublicId, group.PublicId)
				iam.TestGroupRole(t, conn, role7.PublicId, group.PublicId)
				iam.TestUserRole(t, conn, role8.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, role9.PublicId, user.PublicId)
				// ========================================================

				// add random grants and scopes to ensure that unnecessary grants aren't returned
				// ======= these roles are not expected ========
				// correct scope incorrect type
				unnecessaryRole1 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					[]string{"ids=*;type=target;actions=*"})
				unnecessaryRole2 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeChildren},
					[]string{"ids=*;type=auth-method;actions=*"})
				unnecessaryRole3 := iam.TestRoleWithGrants(t, conn, org2.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=account;actions=*"})
				unnecessaryRole4 := iam.TestRoleWithGrants(t, conn, proj2.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=host-set;actions=*"})
				unnecessaryRole5 := iam.TestRoleWithGrants(t, conn, proj3.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=host;actions=*"})
				unnecessaryRole6 := iam.TestRoleWithGrants(t, conn, proj4.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=auth-token;actions=*"})
				unnecessaryRole7 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{proj.PublicId},
					[]string{"ids=*;type=credential;actions=*"})
				unnecessaryRole8 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=*;type=target;actions=*"})

				iam.TestManagedGroupRole(t, conn, unnecessaryRole1.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, unnecessaryRole2.PublicId, oidcMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, unnecessaryRole3.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, unnecessaryRole4.PublicId, oidcMgmtGroup.PublicId)
				iam.TestGroupRole(t, conn, unnecessaryRole5.PublicId, group.PublicId)
				iam.TestGroupRole(t, conn, unnecessaryRole6.PublicId, group.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole7.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole8.PublicId, user.PublicId)

				return arg{
						userId:         user.PublicId,
						resourceType:   []resource.Type{resource.Role},
						requestScopeId: org.PublicId,
						opt:            []iam.Option{iam.WithRecursive(true)},
					}, perms.GrantTuples{
						// role 1
						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GlobalPrefix,
							Grant:             "ids=*;type=*;actions=*",
						},
						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeDescendants,
							Grant:             "ids=*;type=*;actions=*",
						},
						// role 2
						{
							RoleId:            role2.PublicId,
							RoleScopeId:       role2.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeChildren,
							Grant:             "ids=*;type=role;actions=read",
						},
						// role 3
						{
							RoleId:            role3.PublicId,
							RoleScopeId:       role3.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      role3.ScopeId,
							Grant:             "ids=*;type=role;actions=list",
						},
						{
							RoleId:            role3.PublicId,
							RoleScopeId:       role3.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      globals.GrantScopeChildren,
							Grant:             "ids=*;type=role;actions=list",
						},
						// role 4
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      org.PublicId,
							Grant:             "ids=*;type=role;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      org2.PublicId,
							Grant:             "ids=*;type=role;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj.PublicId,
							Grant:             "ids=*;type=role;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj2.PublicId,
							Grant:             "ids=*;type=role;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj3.PublicId,
							Grant:             "ids=*;type=role;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj4.PublicId,
							Grant:             "ids=*;type=role;actions=update",
						},
						// role 5
						{
							RoleId:            role5.PublicId,
							RoleScopeId:       role5.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeDescendants,
							Grant:             "ids=tssh_123456;actions=authorize-session",
						},
						// role 6
						{
							RoleId:            role6.PublicId,
							RoleScopeId:       role6.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeChildren,
							Grant:             "ids=hst_123456;actions=read",
						},
						{
							RoleId:            role6.PublicId,
							RoleScopeId:       role6.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj2.PublicId,
							Grant:             "ids=hst_123456;actions=read",
						},
						{
							RoleId:            role6.PublicId,
							RoleScopeId:       role6.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj3.PublicId,
							Grant:             "ids=hst_123456;actions=read",
						},
						{
							RoleId:            role6.PublicId,
							RoleScopeId:       role6.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj4.PublicId,
							Grant:             "ids=hst_123456;actions=read",
						},
						// role 7
						{
							RoleId:            role7.PublicId,
							RoleScopeId:       role7.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      role7.ScopeId,
							Grant:             "ids=ttcp_123456;actions=delete",
						},
						{
							RoleId:            role7.PublicId,
							RoleScopeId:       role7.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      proj.PublicId,
							Grant:             "ids=ttcp_123456;actions=delete",
						},
						{
							RoleId:            role7.PublicId,
							RoleScopeId:       role7.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      proj3.PublicId,
							Grant:             "ids=ttcp_123456;actions=delete",
						},
						// role 8
						{
							RoleId:            role8.PublicId,
							RoleScopeId:       role8.ScopeId,
							RoleParentScopeId: org.PublicId,
							GrantScopeId:      role8.ScopeId,
							Grant:             "ids=ttcp_123456;actions=delete",
						},
						// role 9
						{
							RoleId:            role9.PublicId,
							RoleScopeId:       role9.ScopeId,
							RoleParentScopeId: org.PublicId,
							GrantScopeId:      role9.ScopeId,
							Grant:             "ids=*;type=role;actions=set-principals",
						},
					}
			},
		},
		{
			name: "global and org resource (auth-token) global scope request recursive",
			setupInputExpect: func(t *testing.T, repo *iam.Repository, conn *db.DB, wrapper wrapping.Wrapper) (arg, perms.GrantTuples) {
				kmsCache := kms.TestKms(t, conn, wrapper)
				databaseWrapper, err := kmsCache.GetWrapper(ctx, globals.GlobalPrefix, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				oidcAuthMethod := oidc.TestAuthMethod(
					t, conn, databaseWrapper, globals.GlobalPrefix, oidc.ActivePrivateState,
					"alice-rp", "fido",
					oidc.WithSigningAlgs(oidc.RS256),
					oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
					oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
				id, err := uuid.GenerateUUID()
				require.NoError(t, err)
				oidcAcct := oidc.TestAccount(t, conn, oidcAuthMethod, id)
				oidcMgmtGroup := oidc.TestManagedGroup(t, conn, oidcAuthMethod, oidc.TestFakeManagedGroupFilter, oidc.WithName(id))
				ldapAuthMethod := ldap.TestAuthMethod(t, conn, databaseWrapper, globals.GlobalPrefix, []string{"ldap://test-" + id})
				ldapMgmtGroup := ldap.TestManagedGroup(t, conn, ldapAuthMethod, []string{id}, ldap.WithName(ctx, id))
				ldapAccount := ldap.TestAccount(t, conn, ldapAuthMethod, id, ldap.WithMemberOfGroups(ctx, id))
				user := iam.TestUser(t, repo, "global", iam.WithAccountIds(oidcAcct.PublicId, ldapAccount.PublicId))
				oidc.TestManagedGroupMember(t, conn, oidcMgmtGroup.PublicId, oidcAcct.PublicId)
				org, proj := iam.TestScopes(t, repo)
				org2, proj2 := iam.TestScopes(t, repo)
				proj3 := iam.TestProject(t, repo, org.PublicId)
				proj4 := iam.TestProject(t, repo, org.PublicId)

				// ======= these roles are expected in the result ========
				//  descendants grant
				role1 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					[]string{"ids=*;type=*;actions=*"})
				// children grant
				role2 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeChildren},
					[]string{"ids=*;type=auth-token;actions=read"})
				// this grant
				role3 := iam.TestRoleWithGrants(t, conn, org.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=auth-token;actions=list"})
				// direct grant
				role4 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{org.PublicId, org2.PublicId, proj.PublicId, proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=*;type=auth-token;actions=update"})
				// pinned id grant (descendants) - resource type = unknown
				role5 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeDescendants},
					[]string{"ids=tssh_123456;actions=authorize-session"})
				// pinned id grant (children) - different resource type also included because resource type = unknown
				role6 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeChildren},
					[]string{"ids=hst_123456;actions=read"})
				// pinned id grant (this) - different resource type also included because resource type = unknown
				role7 := iam.TestRoleWithGrants(t, conn, org.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=ttcp_123456;actions=delete"})
				// pinned id grant (individual org & project scopes) - resource type = unknown
				role8 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=hst_123456;actions=read"})
				// project grants are fetched for global/org resources in recursive requests
				role9 := iam.TestRoleWithGrants(t, conn, proj3.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=*;actions=*"})

				iam.TestManagedGroupRole(t, conn, role1.PublicId, oidcMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role2.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role3.PublicId, oidcMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role4.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role5.PublicId, oidcMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role6.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role7.PublicId, oidcMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role8.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role9.PublicId, oidcMgmtGroup.PublicId)
				// ========================================================

				// add random grants and scopes to ensure that unnecessary grants aren't returned
				// ======= these roles are not expected ========
				// correct scope incorrect type
				unnecessaryRole1 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					[]string{"ids=*;type=target;actions=*"})
				// correct scope incorrect type
				unnecessaryRole2 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeChildren},
					[]string{"ids=*;type=auth-method;actions=*"})
				// correct type incorrect scope
				unnecessaryRole3 := iam.TestRoleWithGrants(t, conn, org2.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=account;actions=*"})
				// correct scope wrong type
				unnecessaryRole4 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{proj.PublicId},
					[]string{"ids=*;type=credential;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole5 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=*;type=target;actions=*"})

				iam.TestManagedGroupRole(t, conn, unnecessaryRole1.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, unnecessaryRole2.PublicId, oidcMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, unnecessaryRole3.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, unnecessaryRole4.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, unnecessaryRole5.PublicId, oidcMgmtGroup.PublicId)

				return arg{
						userId:         user.PublicId,
						resourceType:   []resource.Type{resource.AuthToken},
						requestScopeId: globals.GlobalPrefix,
						opt:            []iam.Option{iam.WithRecursive(true)},
					}, perms.GrantTuples{
						// role 1
						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      role1.ScopeId,
							Grant:             "ids=*;type=*;actions=*",
						},
						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeDescendants,
							Grant:             "ids=*;type=*;actions=*",
						},
						// role 2
						{
							RoleId:            role2.PublicId,
							RoleScopeId:       role2.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeChildren,
							Grant:             "ids=*;type=auth-token;actions=read",
						},
						// role 3
						{
							RoleId:            role3.PublicId,
							RoleScopeId:       role3.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      role3.ScopeId,
							Grant:             "ids=*;type=auth-token;actions=list",
						},
						// role4
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      org.PublicId,
							Grant:             "ids=*;type=auth-token;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      org2.PublicId,
							Grant:             "ids=*;type=auth-token;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj.PublicId,
							Grant:             "ids=*;type=auth-token;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj2.PublicId,
							Grant:             "ids=*;type=auth-token;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj3.PublicId,
							Grant:             "ids=*;type=auth-token;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj4.PublicId,
							Grant:             "ids=*;type=auth-token;actions=update",
						},
						// role5
						{
							RoleId:            role5.PublicId,
							RoleScopeId:       role5.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeDescendants,
							Grant:             "ids=tssh_123456;actions=authorize-session",
						},
						// role6
						{
							RoleId:            role6.PublicId,
							RoleScopeId:       role6.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeChildren,
							Grant:             "ids=hst_123456;actions=read",
						},
						// role 7
						{
							RoleId:            role7.PublicId,
							RoleScopeId:       role7.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      role7.ScopeId,
							Grant:             "ids=ttcp_123456;actions=delete",
						},
						// role 8
						{
							RoleId:            role8.PublicId,
							RoleScopeId:       globals.GlobalPrefix,
							RoleParentScopeId: "",
							GrantScopeId:      proj2.PublicId,
							Grant:             "ids=hst_123456;actions=read",
						},
						{
							RoleId:            role8.PublicId,
							RoleScopeId:       globals.GlobalPrefix,
							RoleParentScopeId: "",
							GrantScopeId:      proj3.PublicId,
							Grant:             "ids=hst_123456;actions=read",
						},
						{
							RoleId:            role8.PublicId,
							RoleScopeId:       globals.GlobalPrefix,
							RoleParentScopeId: "",
							GrantScopeId:      proj4.PublicId,
							Grant:             "ids=hst_123456;actions=read",
						},
						// role 9
						{
							RoleId:            role9.PublicId,
							RoleScopeId:       proj3.PublicId,
							RoleParentScopeId: org.PublicId,
							GrantScopeId:      proj3.PublicId,
							Grant:             "ids=*;type=*;actions=*",
						},
					}
			},
		},
		{
			name: "global and org resource (session-recording) org scope request",
			setupInputExpect: func(t *testing.T, repo *iam.Repository, conn *db.DB, wrapper wrapping.Wrapper) (arg, perms.GrantTuples) {
				user := iam.TestUser(t, repo, "global")
				org, proj := iam.TestScopes(t, repo)
				org2, proj2 := iam.TestScopes(t, repo)
				proj3 := iam.TestProject(t, repo, org.PublicId)
				proj4 := iam.TestProject(t, repo, org.PublicId)
				group := iam.TestGroup(t, conn, globals.GlobalPrefix)
				iam.TestGroupMember(t, conn, group.PublicId, user.PublicId)
				// ======= these roles are expected in the result ========
				//  descendants grant
				role1 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					[]string{"ids=*;type=*;actions=*"})
				// children grant
				role2 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeChildren},
					[]string{"ids=*;type=session-recording;actions=read"})
				// this grant
				role3 := iam.TestRoleWithGrants(t, conn, org.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=session-recording;actions=list"})
				// direct grant
				role4 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{org.PublicId, proj.PublicId, proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=*;type=session-recording;actions=update"})
				// pinned id grant (descendants) - resource type = unknown
				role5 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeDescendants},
					[]string{"ids=tssh_123456;actions=authorize-session"})
				// pinned id grant (children) - different resource type also included because resource type = unknown
				role6 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeChildren},
					[]string{"ids=hst_123456;actions=read"})
				// pinned id grant (this) - different resource type also included because resource type = unknown
				role7 := iam.TestRoleWithGrants(t, conn, org.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=ttcp_123456;actions=delete"})

				iam.TestGroupRole(t, conn, role1.PublicId, group.PublicId)
				iam.TestGroupRole(t, conn, role2.PublicId, group.PublicId)
				iam.TestUserRole(t, conn, role3.PublicId, user.PublicId)
				iam.TestGroupRole(t, conn, role4.PublicId, group.PublicId)
				iam.TestGroupRole(t, conn, role5.PublicId, group.PublicId)
				iam.TestUserRole(t, conn, role6.PublicId, user.PublicId)
				iam.TestGroupRole(t, conn, role7.PublicId, group.PublicId)
				// ========================================================

				// add random grants and scopes to ensure that unnecessary grants aren't returned
				// ======= these roles are not expected ========
				// correct scope incorrect type
				unnecessaryRole1 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					[]string{"ids=*;type=target;actions=*"})
				// correct scope incorrect type
				unnecessaryRole2 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeChildren},
					[]string{"ids=*;type=auth-method;actions=*"})
				// correct type incorrect scope
				unnecessaryRole3 := iam.TestRoleWithGrants(t, conn, org2.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=account;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole4 := iam.TestRoleWithGrants(t, conn, proj2.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=*;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole5 := iam.TestRoleWithGrants(t, conn, proj3.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=*;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole6 := iam.TestRoleWithGrants(t, conn, proj4.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=*;actions=*"})
				// correct scope wrong type
				unnecessaryRole7 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{proj.PublicId},
					[]string{"ids=*;type=credential;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole8 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=*;type=target;actions=*"})
				// pinned id wrong scope
				unnecessaryRole9 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=hst_123456;actions=read"})
				// correct grant incorrect scope
				unnecessaryRole10 := iam.TestRoleWithGrants(t, conn, org.PublicId,
					[]string{proj.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=*;type=*;actions=*"})
				unnecessaryRole11 := iam.TestRoleWithGrants(t, conn, org.PublicId,
					[]string{globals.GrantScopeChildren},
					[]string{"ids=*;type=*;actions=*"})

				iam.TestUserRole(t, conn, unnecessaryRole1.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole2.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole3.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole4.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole5.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole6.PublicId, user.PublicId)
				iam.TestGroupRole(t, conn, unnecessaryRole7.PublicId, group.PublicId)
				iam.TestGroupRole(t, conn, unnecessaryRole8.PublicId, group.PublicId)
				iam.TestGroupRole(t, conn, unnecessaryRole9.PublicId, group.PublicId)
				iam.TestGroupRole(t, conn, unnecessaryRole10.PublicId, group.PublicId)
				iam.TestGroupRole(t, conn, unnecessaryRole11.PublicId, group.PublicId)

				return arg{
						userId:         user.PublicId,
						resourceType:   []resource.Type{resource.SessionRecording},
						requestScopeId: org.PublicId,
					}, perms.GrantTuples{
						// role1
						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeDescendants,
							Grant:             "ids=*;type=*;actions=*",
						},
						// role2
						{
							RoleId:            role2.PublicId,
							RoleScopeId:       role2.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeChildren,
							Grant:             "ids=*;type=session-recording;actions=read",
						},
						// role3
						{
							RoleId:            role3.PublicId,
							RoleScopeId:       role3.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      role3.ScopeId,
							Grant:             "ids=*;type=session-recording;actions=list",
						},
						// role4
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      org.PublicId,
							Grant:             "ids=*;type=session-recording;actions=update",
						},
						// role5
						{
							RoleId:            role5.PublicId,
							RoleScopeId:       role5.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeDescendants,
							Grant:             "ids=tssh_123456;actions=authorize-session",
						},
						// role6
						{
							RoleId:            role6.PublicId,
							RoleScopeId:       role6.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeChildren,
							Grant:             "ids=hst_123456;actions=read",
						},
						// role7
						{
							RoleId:            role7.PublicId,
							RoleScopeId:       role7.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      role7.ScopeId,
							Grant:             "ids=ttcp_123456;actions=delete",
						},
					}
			},
		},
		{
			name: "global and org resource (users) proj scope request",
			setupInputExpect: func(t *testing.T, repo *iam.Repository, conn *db.DB, wrapper wrapping.Wrapper) (arg, perms.GrantTuples) {
				user := iam.TestUser(t, repo, "global")
				_, proj := iam.TestScopes(t, repo, iam.WithSkipDefaultRoleCreation(true))
				return arg{
					userId:         user.PublicId,
					resourceType:   []resource.Type{resource.User},
					requestScopeId: proj.PublicId,
					opt:            []iam.Option{iam.WithRecursive(true)},
				}, perms.GrantTuples{}
			},
		},
		{
			name: "project only resource (target) global scope request recursive",
			setupInputExpect: func(t *testing.T, repo *iam.Repository, conn *db.DB, wrapper wrapping.Wrapper) (arg, perms.GrantTuples) {
				org, proj := iam.TestScopes(t, repo)
				org2, proj2 := iam.TestScopes(t, repo)
				proj3 := iam.TestProject(t, repo, org.PublicId)
				proj4 := iam.TestProject(t, repo, org.PublicId)
				group := iam.TestGroup(t, conn, globals.GlobalPrefix)
				user := iam.TestUser(t, repo, "global")
				iam.TestGroupMember(t, conn, group.PublicId, user.PublicId)
				// ======= these roles are expected in the result ========
				//  descendants grant
				//	returns 1 tuple - descendants
				role1 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					[]string{"ids=*;type=*;actions=*"})
				// children grant
				//	returns 1 tuples - children
				role2 := iam.TestRoleWithGrants(t, conn, org.PublicId,
					[]string{globals.GrantScopeThis, globals.GrantScopeChildren},
					[]string{"ids=*;type=target;actions=authorize-session"})
				// this grant
				//	returns 1 tuples
				role3 := iam.TestRoleWithGrants(t, conn, proj.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=target;actions=read"})
				// direct grant multiple scopes
				//	returns 5 tuples
				role4 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{org2.PublicId, proj.PublicId, proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=*;type=target;actions=update"})
				// pinned grants is included even when the id belongs to another resource type
				//	returns 2 tuples - proj3, proj4
				role5 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeChildren, proj3.PublicId, proj4.PublicId},
					[]string{"ids=hst_12345;actions=update"})
				iam.TestUserRole(t, conn, role1.PublicId, user.PublicId)
				iam.TestGroupRole(t, conn, role2.PublicId, group.PublicId)
				iam.TestUserRole(t, conn, role3.PublicId, user.PublicId)
				iam.TestGroupRole(t, conn, role4.PublicId, group.PublicId)
				iam.TestUserRole(t, conn, role5.PublicId, user.PublicId)

				// ========================================================
				// add random grants and scopes to ensure that unnecessary grants aren't returned
				// ======= these roles are not expected ========
				// superset of scope but incorrect type
				unnecessaryRole1 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					[]string{"ids=*;type=account;actions=*"})
				// superset of scope but incorrect type
				unnecessaryRole2 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeDescendants},
					[]string{"ids=*;type=auth-method;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole3 := iam.TestRoleWithGrants(t, conn, org2.PublicId,
					[]string{globals.GrantScopeChildren},
					[]string{"ids=*;type=host;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole4 := iam.TestRoleWithGrants(t, conn, proj2.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=host-set;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole5 := iam.TestRoleWithGrants(t, conn, proj3.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=credential;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole6 := iam.TestRoleWithGrants(t, conn, proj4.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=credential-store;actions=*"})
				// correct scope wrong type
				unnecessaryRole7 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{proj.PublicId},
					[]string{"ids=*;type=credential;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole8 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=*;type=group;actions=*"})
				iam.TestUserRole(t, conn, unnecessaryRole1.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole2.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole3.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole4.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole5.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole6.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole7.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole8.PublicId, user.PublicId)

				// valid role but not associated to the user
				iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					[]string{"ids=*;type=*;actions=*"})

				return arg{
						userId:         user.PublicId,
						resourceType:   []resource.Type{resource.Target},
						requestScopeId: globals.GlobalPrefix,
						opt:            []iam.Option{iam.WithRecursive(true)},
					}, perms.GrantTuples{
						// role 1
						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeDescendants,
							Grant:             "ids=*;type=*;actions=*",
						},
						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GlobalPrefix,
							Grant:             "ids=*;type=*;actions=*",
						},
						// role 2
						{
							RoleId:            role2.PublicId,
							RoleScopeId:       role2.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      globals.GrantScopeChildren,
							Grant:             "ids=*;type=target;actions=authorize-session",
						},
						{
							RoleId:            role2.PublicId,
							RoleScopeId:       role2.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      org.PublicId,
							Grant:             "ids=*;type=target;actions=authorize-session",
						},
						// role 3
						{
							RoleId:            role3.PublicId,
							RoleScopeId:       role3.ScopeId,
							RoleParentScopeId: org.PublicId,
							GrantScopeId:      role3.ScopeId,
							Grant:             "ids=*;type=target;actions=read",
						},
						// role 4
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      org2.PublicId,
							Grant:             "ids=*;type=target;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj.PublicId,
							Grant:             "ids=*;type=target;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj2.PublicId,
							Grant:             "ids=*;type=target;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj3.PublicId,
							Grant:             "ids=*;type=target;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj4.PublicId,
							Grant:             "ids=*;type=target;actions=update",
						},
						// role 5
						{
							RoleId:            role5.PublicId,
							RoleScopeId:       role5.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GlobalPrefix,
							Grant:             "ids=hst_12345;actions=update",
						},
						{
							RoleId:            role5.PublicId,
							RoleScopeId:       role5.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeChildren,
							Grant:             "ids=hst_12345;actions=update",
						},
						{
							RoleId:            role5.PublicId,
							RoleScopeId:       role5.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj3.PublicId,
							Grant:             "ids=hst_12345;actions=update",
						},
						{
							RoleId:            role5.PublicId,
							RoleScopeId:       role5.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj4.PublicId,
							Grant:             "ids=hst_12345;actions=update",
						},
					}
			},
		},
		{
			name: "project only resource (host-catalog) org scope request recursive",
			setupInputExpect: func(t *testing.T, repo *iam.Repository, conn *db.DB, wrapper wrapping.Wrapper) (arg, perms.GrantTuples) {
				kmsCache := kms.TestKms(t, conn, wrapper)
				databaseWrapper, err := kmsCache.GetWrapper(ctx, globals.GlobalPrefix, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				oidcAuthMethod := oidc.TestAuthMethod(
					t, conn, databaseWrapper, globals.GlobalPrefix, oidc.ActivePrivateState,
					"alice-rp", "fido",
					oidc.WithSigningAlgs(oidc.RS256),
					oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
					oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
				id, err := uuid.GenerateUUID()
				require.NoError(t, err)
				oidcAcct := oidc.TestAccount(t, conn, oidcAuthMethod, id)
				oidcMgmtGroup := oidc.TestManagedGroup(t, conn, oidcAuthMethod, oidc.TestFakeManagedGroupFilter, oidc.WithName(id))

				ldapAuthMethod := ldap.TestAuthMethod(t, conn, databaseWrapper, globals.GlobalPrefix, []string{"ldap://test-" + id})
				ldapMgmtGroup := ldap.TestManagedGroup(t, conn, ldapAuthMethod, []string{id}, ldap.WithName(ctx, id))
				ldapAccount := ldap.TestAccount(t, conn, ldapAuthMethod, id, ldap.WithMemberOfGroups(ctx, id))
				user := iam.TestUser(t, repo, "global", iam.WithAccountIds(oidcAcct.PublicId, ldapAccount.PublicId))
				oidc.TestManagedGroupMember(t, conn, oidcMgmtGroup.PublicId, oidcAcct.PublicId)

				org, proj := iam.TestScopes(t, repo)
				org2, proj2 := iam.TestScopes(t, repo)
				proj3 := iam.TestProject(t, repo, org.PublicId)
				proj4 := iam.TestProject(t, repo, org.PublicId)
				group := iam.TestGroup(t, conn, globals.GlobalPrefix)
				iam.TestGroupMember(t, conn, group.PublicId, user.PublicId)

				// ======= these roles are expected in the result ========
				//  descendants grant
				//	returns 1 tuple - descendents
				role1 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					[]string{"ids=*;type=*;actions=*"})
				// children grant
				//	returns 1 tuples - children
				role2 := iam.TestRoleWithGrants(t, conn, org.PublicId,
					[]string{globals.GrantScopeThis, globals.GrantScopeChildren},
					[]string{"ids=*;type=host-catalog;actions=authorize-session"})
				// this grant
				//	returns 1 tuples
				role3 := iam.TestRoleWithGrants(t, conn, proj.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=host-catalog;actions=read"})
				// direct grant multiple scopes
				//	returns 3 tuples - proj3, proj4
				role4 := iam.TestRoleWithGrants(t, conn, org.PublicId,
					[]string{globals.GrantScopeThis, proj3.PublicId, proj4.PublicId},
					[]string{"ids=*;type=host-catalog;actions=update"})
				// pinned grants is included even when the id belongs to another resource type
				//	returns 3 tuples - children, proj3, proj4
				role5 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeChildren, proj3.PublicId, proj4.PublicId},
					[]string{"ids=hcplg_Ia7R4E39oF;actions=update"})
				iam.TestManagedGroupRole(t, conn, role1.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, role2.PublicId, oidcMgmtGroup.PublicId)
				iam.TestUserRole(t, conn, role3.PublicId, user.PublicId)
				iam.TestGroupRole(t, conn, role4.PublicId, group.PublicId)
				iam.TestManagedGroupRole(t, conn, role5.PublicId, ldapMgmtGroup.PublicId)
				// ========================================================

				// add random grants and scopes to ensure that unnecessary grants aren't returned
				// ======= these roles are not expected ========
				// superset of scope but incorrect type
				unnecessaryRole1 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					[]string{"ids=*;type=account;actions=*"})
				// superset of scope but incorrect type
				unnecessaryRole2 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeDescendants},
					[]string{"ids=*;type=auth-method;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole3 := iam.TestRoleWithGrants(t, conn, org2.PublicId,
					[]string{globals.GrantScopeChildren},
					[]string{"ids=*;type=host;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole4 := iam.TestRoleWithGrants(t, conn, proj2.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=host-set;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole5 := iam.TestRoleWithGrants(t, conn, proj3.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=credential;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole6 := iam.TestRoleWithGrants(t, conn, proj4.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=credential-store;actions=*"})
				// correct scope wrong type
				unnecessaryRole7 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{proj.PublicId},
					[]string{"ids=*;type=target;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole8 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=*;type=group;actions=*"})
				iam.TestUserRole(t, conn, unnecessaryRole1.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole2.PublicId, user.PublicId)
				iam.TestGroupRole(t, conn, unnecessaryRole3.PublicId, group.PublicId)
				iam.TestGroupRole(t, conn, unnecessaryRole4.PublicId, group.PublicId)
				iam.TestManagedGroupRole(t, conn, unnecessaryRole5.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, unnecessaryRole6.PublicId, ldapMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, unnecessaryRole7.PublicId, oidcMgmtGroup.PublicId)
				iam.TestManagedGroupRole(t, conn, unnecessaryRole8.PublicId, oidcMgmtGroup.PublicId)

				// valid role but not associated to the user
				iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					[]string{"ids=*;type=*;actions=*"})

				return arg{
						userId:         user.PublicId,
						resourceType:   []resource.Type{resource.HostCatalog},
						requestScopeId: org.PublicId,
						opt:            []iam.Option{iam.WithRecursive(true)},
					}, perms.GrantTuples{
						// role 1
						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GlobalPrefix,
							Grant:             "ids=*;type=*;actions=*",
						},
						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeDescendants,
							Grant:             "ids=*;type=*;actions=*",
						},
						// role 2
						{
							RoleId:            role2.PublicId,
							RoleScopeId:       role2.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      globals.GrantScopeChildren,
							Grant:             "ids=*;type=host-catalog;actions=authorize-session",
						},
						{
							RoleId:            role2.PublicId,
							RoleScopeId:       role2.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      org.PublicId,
							Grant:             "ids=*;type=host-catalog;actions=authorize-session",
						},
						// role 3
						{
							RoleId:            role3.PublicId,
							RoleScopeId:       role3.ScopeId,
							RoleParentScopeId: org.PublicId,
							GrantScopeId:      role3.ScopeId,
							Grant:             "ids=*;type=host-catalog;actions=read",
						},
						// role 4
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      org.PublicId,
							Grant:             "ids=*;type=host-catalog;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      proj3.PublicId,
							Grant:             "ids=*;type=host-catalog;actions=update",
						},
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      proj4.PublicId,
							Grant:             "ids=*;type=host-catalog;actions=update",
						},
						// role 5
						{
							RoleId:            role5.PublicId,
							RoleScopeId:       role5.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GlobalPrefix,
							Grant:             "ids=hcplg_Ia7R4E39oF;actions=update",
						},
						{
							RoleId:            role5.PublicId,
							RoleScopeId:       role5.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeChildren,
							Grant:             "ids=hcplg_Ia7R4E39oF;actions=update",
						},
						{
							RoleId:            role5.PublicId,
							RoleScopeId:       role5.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj3.PublicId,
							Grant:             "ids=hcplg_Ia7R4E39oF;actions=update",
						},
						{
							RoleId:            role5.PublicId,
							RoleScopeId:       role5.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj4.PublicId,
							Grant:             "ids=hcplg_Ia7R4E39oF;actions=update",
						},
					}
			},
		},
		{
			name: "project only resource (target) project scope request",
			setupInputExpect: func(t *testing.T, repo *iam.Repository, conn *db.DB, wrapper wrapping.Wrapper) (arg, perms.GrantTuples) {
				user := iam.TestUser(t, repo, "global")
				org, proj := iam.TestScopes(t, repo)
				org2, proj2 := iam.TestScopes(t, repo)
				proj3 := iam.TestProject(t, repo, org.PublicId)
				proj4 := iam.TestProject(t, repo, org.PublicId)
				_ = iam.TestProject(t, repo, org2.PublicId)
				_ = iam.TestProject(t, repo, org2.PublicId)

				// ======= these roles are expected in the result ========
				//  descendants grant
				role1 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeDescendants},
					[]string{"ids=*;type=*;actions=*"})
				// children grant
				role2 := iam.TestRoleWithGrants(t, conn, org.PublicId,
					[]string{globals.GrantScopeChildren},
					[]string{"ids=*;type=target;actions=authorize-session"})
				// this grant
				role3 := iam.TestRoleWithGrants(t, conn, proj.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=target;actions=read"})
				// direct grant - with extras
				role4 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{org2.PublicId, proj.PublicId, proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=*;type=target;actions=update"})
				// direct grant - no extra
				role5 := iam.TestRoleWithGrants(t, conn, org.PublicId,
					[]string{proj.PublicId},
					[]string{"ids=*;type=target;actions=create"})
				// pinned id grant - resource type = unknown
				role6 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeDescendants},
					[]string{"ids=tssh_123456;actions=authorize-session"})
				// pinned id grant - different resource type also included because resource type = unknown
				role7 := iam.TestRoleWithGrants(t, conn, org.PublicId,
					[]string{globals.GrantScopeChildren},
					[]string{"ids=hst_123456;actions=read"})

				iam.TestUserRole(t, conn, role1.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, role2.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, role3.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, role4.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, role5.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, role6.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, role7.PublicId, user.PublicId)
				// ========================================================

				// add random grants and scopes to ensure that unnecessary grants aren't returned
				// ======= these roles are not expected ========
				// superset of scope but incorrect type
				unnecessaryRole1 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					[]string{"ids=*;type=account;actions=*"})
				// superset of scope but incorrect type
				unnecessaryRole2 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeDescendants},
					[]string{"ids=*;type=auth-method;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole3 := iam.TestRoleWithGrants(t, conn, org2.PublicId,
					[]string{globals.GrantScopeChildren},
					[]string{"ids=*;type=*;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole4 := iam.TestRoleWithGrants(t, conn, proj2.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=*;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole5 := iam.TestRoleWithGrants(t, conn, proj3.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=*;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole6 := iam.TestRoleWithGrants(t, conn, proj4.PublicId,
					[]string{globals.GrantScopeThis},
					[]string{"ids=*;type=*;actions=*"})
				// correct scope wrong type
				unnecessaryRole7 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{proj.PublicId},
					[]string{"ids=*;type=credential;actions=*"})
				// superset of type but incorrect scope
				unnecessaryRole8 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=*;type=target;actions=*"})
				// pinned id wrong scope
				unnecessaryRole9 := iam.TestRoleWithGrants(t, conn, globals.GlobalPrefix,
					[]string{globals.GrantScopeChildren, proj2.PublicId, proj3.PublicId, proj4.PublicId},
					[]string{"ids=hst_123456;actions=read"})

				iam.TestUserRole(t, conn, unnecessaryRole1.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole2.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole3.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole4.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole5.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole6.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole7.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole8.PublicId, user.PublicId)
				iam.TestUserRole(t, conn, unnecessaryRole9.PublicId, user.PublicId)

				return arg{
						userId:         user.PublicId,
						resourceType:   []resource.Type{resource.Target},
						requestScopeId: proj.PublicId,
					}, perms.GrantTuples{
						// role 1
						{
							RoleId:            role1.PublicId,
							RoleScopeId:       role1.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeDescendants,
							Grant:             "ids=*;type=*;actions=*",
						},
						// role 2
						{
							RoleId:            role2.PublicId,
							RoleScopeId:       role2.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      globals.GrantScopeChildren,
							Grant:             "ids=*;type=target;actions=authorize-session",
						},
						// role 3
						{
							RoleId:            role3.PublicId,
							RoleScopeId:       role3.ScopeId,
							RoleParentScopeId: org.PublicId,
							GrantScopeId:      role3.ScopeId,
							Grant:             "ids=*;type=target;actions=read",
						},
						// role 4
						{
							RoleId:            role4.PublicId,
							RoleScopeId:       role4.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      proj.PublicId,
							Grant:             "ids=*;type=target;actions=update",
						},
						// role 5
						{
							RoleId:            role5.PublicId,
							RoleScopeId:       role5.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      proj.PublicId,
							Grant:             "ids=*;type=target;actions=create",
						},
						// role 6
						{
							RoleId:            role6.PublicId,
							RoleScopeId:       role6.ScopeId,
							RoleParentScopeId: "",
							GrantScopeId:      globals.GrantScopeDescendants,
							Grant:             "ids=tssh_123456;actions=authorize-session",
						},
						// role 7
						{
							RoleId:            role7.PublicId,
							RoleScopeId:       role7.ScopeId,
							RoleParentScopeId: globals.GlobalPrefix,
							GrantScopeId:      globals.GrantScopeChildren,
							Grant:             "ids=hst_123456;actions=read",
						},
					}
			},
		},
		{
			name: "project only resource (target) global scope request recursive",
			setupInputExpect: func(t *testing.T, repo *iam.Repository, conn *db.DB, wrapper wrapping.Wrapper) (arg, perms.GrantTuples) {
				// test cases with no grants but valid request - expect no error and nothing in GrantTuples
				user := iam.TestUser(t, repo, "global")
				return arg{
					userId:         user.PublicId,
					resourceType:   []resource.Type{resource.Target},
					requestScopeId: globals.GlobalPrefix,
					opt:            []iam.Option{iam.WithRecursive(true)},
				}, perms.GrantTuples{}
			},
		},
		{
			name: "project only resource (target) global scope request non recursive",
			setupInputExpect: func(t *testing.T, repo *iam.Repository, conn *db.DB, wrapper wrapping.Wrapper) (arg, perms.GrantTuples) {
				user := iam.TestUser(t, repo, "global")
				return arg{
					userId:         user.PublicId,
					resourceType:   []resource.Type{resource.Target},
					requestScopeId: globals.GlobalPrefix,
				}, perms.GrantTuples{}
			},
			wantErr:    true,
			wantErrMsg: "iam.(Repository).GrantsForUser: unable to resolve query: iam.(Repository).resolveQuery: request scope id must be project for [target] resources: parameter violation: error #100",
		},
		{
			name: "project only resource (target) org scope request non recursive",
			setupInputExpect: func(t *testing.T, repo *iam.Repository, conn *db.DB, wrapper wrapping.Wrapper) (arg, perms.GrantTuples) {
				user := iam.TestUser(t, repo, "global")
				org, _ := iam.TestScopes(t, repo)
				return arg{
					userId:         user.PublicId,
					resourceType:   []resource.Type{resource.Target},
					requestScopeId: org.PublicId,
				}, perms.GrantTuples{}
			},
			wantErr:    true,
			wantErrMsg: "iam.(Repository).GrantsForUser: unable to resolve query: iam.(Repository).resolveQuery: request scope id must be project for [target] resources: parameter violation: error #100",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			conn, _ := db.TestSetup(t, "postgres")
			wrap := db.TestWrapper(t)
			repo := iam.TestRepo(t, conn, wrap)
			input, want := tc.setupInputExpect(t, repo, conn, wrap)
			grantTuples, err := repo.GrantsForUser(ctx, input.userId, input.resourceType, input.requestScopeId, input.opt...)
			if tc.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.wantErrMsg)
				return
			}
			// fetch default grants in case they are required - this appends `u_anon` and `u_auth` default grants to the
			// expect result set. These grants cannot be included in the hard-coded 'want' because we do not know
			// what role IDs of the default roles are ahead of time
			defaultTuples, err := repo.GrantsForUser(ctx, "u_auth", input.resourceType, input.requestScopeId, input.opt...)
			require.NoError(t, err)
			want = append(want, defaultTuples...)
			assert.NoError(t, err)
			assert.ElementsMatch(t, want, grantTuples)
		})
	}
}
