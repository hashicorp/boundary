// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package iam_test

import (
	"context"
	"encoding/json"
	"fmt"
	mathrand "math/rand"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// principal represents the different ways a user can be associated with a role.
//
//   - Direct association: principalId == userId
//   - Group association: principalId is a group ID; user Id is a member of that group
//   - Managed group association: principalId is a managed group ID; userId is a member of that managed group
type principal struct {
	principalId string
	userId      string
}

func TestGrantsForUserRandomized(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrap)
	ldapRepo, err := ldap.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	userCount := 10
	groupCount := 30
	oidcManagedGroupCount := 30
	ldapManagedGroupCount := 30
	roleCount := 1
	// probFactor acts as a mod value; increasing means less probability. 2 =
	// 50%, 5 = 20%, etc.
	probFactor := 5
	// Turning this off will let users be cross-scope instead of in the same
	// scope as the OIDC auth method
	testManagedGroups := true
	// Turning this off means users are not directly added to roles. Useful
	// since we can't set users to 0 (or we won't accounts) but if we want to
	// test only managed groups.
	addUsersDirectly := true

	o, p := iam.TestScopes(
		t,
		iamRepo,
		iam.WithSkipAdminRoleCreation(true),
		iam.WithSkipDefaultRoleCreation(true),
	)
	databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	oidcAuthMethod := oidc.TestAuthMethod(
		t, conn, databaseWrapper, o.GetPublicId(), oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	ldapAuthMethod := ldap.TestAuthMethod(t, conn, databaseWrapper, o.GetPublicId(), []string{"ldap://test"})

	// We're going to generate a bunch of users (each tied to 2 accounts; oidc
	// and ldap), groups, and managed groups (oidc and ldap). These will be
	// randomly assigned and we will record assignations.
	users, oidcAccounts, ldapAccounts := func() (usrs []*iam.User, oidcAccts []*oidc.Account, ldapAccts []*ldap.Account) {
		usrs = make([]*iam.User, 0, userCount)
		oidcAccts = make([]*oidc.Account, 0, userCount)
		scopeId := scope.Global.String()
		if mathrand.Int()%2 == 0 || testManagedGroups {
			scopeId = o.GetPublicId()
		}
		for i := 0; i < userCount; i++ {
			oidcAccts = append(oidcAccts, oidc.TestAccount(t, conn, oidcAuthMethod, fmt.Sprintf("sub-%d", i)))
			ldapAccts = append(ldapAccts, ldap.TestAccount(t, conn, ldapAuthMethod, fmt.Sprintf("login-name-%d", i)))
			usrs = append(usrs, iam.TestUser(
				t,
				iamRepo,
				scopeId,
				iam.WithAccountIds(oidcAccts[i].PublicId, ldapAccts[i].PublicId),
				iam.WithName(fmt.Sprintf("testuser%d", i)),
			))
		}
		return
	}()
	groups := func() (ret []*iam.Group) {
		ret = make([]*iam.Group, 0, groupCount)
		scopeId := o.GetPublicId()
		if mathrand.Int()%2 == 0 {
			scopeId = p.GetPublicId()
		}
		for i := 0; i < groupCount; i++ {
			ret = append(ret, iam.TestGroup(t, conn, scopeId, iam.WithName(fmt.Sprintf("testgroup%d", i))))
		}
		return
	}()
	oidcManagedGroups := func() (ret []*oidc.ManagedGroup) {
		ret = make([]*oidc.ManagedGroup, 0, oidcManagedGroupCount)
		for i := 0; i < oidcManagedGroupCount; i++ {
			ret = append(ret, oidc.TestManagedGroup(t, conn, oidcAuthMethod, oidc.TestFakeManagedGroupFilter, oidc.WithName(fmt.Sprintf("oidc-testmanagedgroup%d", i))))
		}
		return
	}()
	ldapManagedGroups := func() (ret []*ldap.ManagedGroup) {
		ret = make([]*ldap.ManagedGroup, 0, ldapManagedGroupCount)
		for i := 0; i < ldapManagedGroupCount; i++ {
			name := fmt.Sprintf("ldap-testmanagedgroup%d", i)
			ret = append(ret, ldap.TestManagedGroup(t, conn, ldapAuthMethod, []string{name}, ldap.WithName(ctx, name)))
		}
		return
	}()
	roles := func() (ret []*iam.Role) {
		ret = make([]*iam.Role, 0, roleCount)
		scopeId := o.GetPublicId()
		if mathrand.Int()%2 == 0 {
			scopeId = p.GetPublicId()
		}
		for i := 0; i < roleCount; i++ {
			role := iam.TestRole(t, conn, scopeId, iam.WithName(fmt.Sprintf("testrole%d", i)))
			iam.TestRoleGrant(t, conn, role.PublicId, "ids=*;type=*;actions=*")
			ret = append(ret, role)
		}
		return
	}()

	// This variable stores an easy way to lookup, given a group ID, whether a
	// user is in that group.
	userToGroupsMapping := map[string]map[string]bool{}
	for _, user := range users {
		for _, group := range groups {
			// Give each user a chance of being in any specific group
			if mathrand.Int()%probFactor == 0 {
				userId := user.PublicId
				groupId := group.PublicId
				iam.TestGroupMember(t, conn, groupId, userId)
				currentMapping := userToGroupsMapping[userId]
				if currentMapping == nil {
					currentMapping = make(map[string]bool)
				}
				currentMapping[groupId] = true
				userToGroupsMapping[userId] = currentMapping
			}
		}
	}
	// This variable stores an easy way to lookup, given a user id, whether or
	// not it's in an oidc managed group.
	userToOidcManagedGroupsMapping := map[string]map[string]bool{}
	for i, user := range users {
		for _, managedGroup := range oidcManagedGroups {
			// Give each user (account) a chance of being in any specific managed group
			if mathrand.Int()%probFactor == 0 {
				userId := user.PublicId
				accountId := oidcAccounts[i].PublicId
				managedGroupId := managedGroup.PublicId
				oidc.TestManagedGroupMember(t, conn, managedGroupId, accountId)
				currentMapping := userToOidcManagedGroupsMapping[userId]
				if currentMapping == nil {
					currentMapping = make(map[string]bool)
				}
				currentMapping[managedGroupId] = true
				userToOidcManagedGroupsMapping[userId] = currentMapping
			}
		}
	}

	ldapAcctCloneFunc := func(a *ldap.Account) *ldap.Account {
		cp := proto.Clone(a.Account)
		return &ldap.Account{
			Account: cp.(*store.Account),
		}
	}
	// This variable stores an easy way to lookup, given a user id, whether or
	// not it's in an ldap managed group.
	userToLdapManagedGroupsMapping := map[string]map[string]bool{}

	// This variable stores an easy way to lookup, giving an ldap managed group
	// id, whether or not it has a user id
	ldapManagedGroupToUser := map[string]map[string]bool{}

	for i, user := range users {
		userLdapAcct := ldapAccounts[i]              // the first acct goes with the first user
		acctClone := ldapAcctCloneFunc(userLdapAcct) // clone it just in case it's changed during a db update
		for _, managedGroup := range ldapManagedGroups {
			// Give each user (account) a chance of being in any specific managed group
			if mathrand.Int()%probFactor == 0 {
				var existingAcctGroups []string
				if acctClone.GetMemberOfGroups() != "" {
					require.NoError(t, json.Unmarshal([]byte(acctClone.GetMemberOfGroups()), &existingAcctGroups))
				}
				var existingManagedGroups []string
				require.NoError(t, json.Unmarshal([]byte(managedGroup.GetGroupNames()), &existingManagedGroups))
				newGrps, err := json.Marshal(append(existingAcctGroups, existingManagedGroups...))
				require.NoError(t, err)
				acctClone.MemberOfGroups = string(newGrps)
				updated, err := rw.Update(ctx, acctClone, []string{"MemberOfGroups"}, nil)
				require.NoError(t, err)
				require.Equal(t, 1, updated)
				userId := user.GetPublicId()
				currentMapping := userToLdapManagedGroupsMapping[userId]
				if currentMapping == nil {
					currentMapping = make(map[string]bool)
				}
				currentMapping[managedGroup.GetPublicId()] = true
				userToLdapManagedGroupsMapping[userId] = currentMapping

				currentMapGrpsToUser := ldapManagedGroupToUser[managedGroup.GetPublicId()]
				if currentMapGrpsToUser == nil {
					currentMapGrpsToUser = make(map[string]bool)
				}
				currentMapGrpsToUser[userId] = true
				ldapManagedGroupToUser[managedGroup.GetPublicId()] = currentMapGrpsToUser

				// check that the acct is part of the managed grp
				// 1) check acct is returned from
				// 		auth_managed_group_member_account search
				// 2) check that acct belongs to the user
				memberAccts, err := ldapRepo.ListManagedGroupMembershipsByMember(ctx, userLdapAcct.GetPublicId())
				require.NoError(t, err)
				require.GreaterOrEqual(t, len(memberAccts), 1)
				found := false
				for _, m := range memberAccts {
					if m.GetManagedGroupId() == managedGroup.GetPublicId() && m.GetMemberId() == userLdapAcct.GetPublicId() {
						found = true
					}
				}
				require.Truef(t, found, "did not find acct in managed grp search")

				accts, err := iamRepo.ListUserAccounts(ctx, userId)
				require.NoError(t, err)
				require.Contains(t, accts, userLdapAcct.GetPublicId())
			}
		}
	}

	// Now, we're going to randomly assign users and groups to roles and also
	// store mappings
	userToRolesMapping := map[string]map[string]bool{}
	groupToRolesMapping := map[string]map[string]bool{}
	oidcManagedGroupToRolesMapping := map[string]map[string]bool{}
	ldapManagedGroupToRolesMapping := map[string]map[string]bool{}
	if addUsersDirectly {
		for _, role := range roles {
			for _, user := range users {
				// Give each user a chance of being directly added to any specific
				// role
				if mathrand.Int()%probFactor == 0 {
					roleId := role.PublicId
					userId := user.PublicId
					iam.TestUserRole(t, conn, roleId, userId)
					currentMapping := userToRolesMapping[userId]
					if currentMapping == nil {
						currentMapping = make(map[string]bool)
					}
					currentMapping[roleId] = true
					userToRolesMapping[userId] = currentMapping
				}
			}
		}
	}
	for _, role := range roles {
		for _, group := range groups {
			// Give each group a chance of being directly added to any specific
			// role
			if mathrand.Int()%probFactor == 0 {
				roleId := role.PublicId
				groupId := group.PublicId
				iam.TestGroupRole(t, conn, roleId, groupId)
				currentMapping := groupToRolesMapping[groupId]
				if currentMapping == nil {
					currentMapping = make(map[string]bool)
				}
				currentMapping[roleId] = true
				groupToRolesMapping[groupId] = currentMapping
			}
		}
	}
	for _, role := range roles {
		roleId := role.PublicId
		for _, oidcManagedGroup := range oidcManagedGroups {
			// Give each oidc managed group a chance of being directly added to
			// any specific role
			if mathrand.Int()%probFactor == 0 {
				managedGroupId := oidcManagedGroup.PublicId
				iam.TestManagedGroupRole(t, conn, roleId, managedGroupId)
				currentMapping := oidcManagedGroupToRolesMapping[managedGroupId]
				if currentMapping == nil {
					currentMapping = make(map[string]bool)
				}
				currentMapping[roleId] = true
				oidcManagedGroupToRolesMapping[managedGroupId] = currentMapping
			}
		}
		for _, ldapManagedGroup := range ldapManagedGroups {
			// Give each ldap managed group a chance of being directly added to
			// any specific role
			if mathrand.Int()%probFactor == 0 {
				ldapManagedGroupId := ldapManagedGroup.GetPublicId()
				iam.TestManagedGroupRole(t, conn, roleId, ldapManagedGroupId)
				currentMapping := ldapManagedGroupToRolesMapping[ldapManagedGroupId]
				if currentMapping == nil {
					currentMapping = make(map[string]bool)
				}
				currentMapping[roleId] = true
				ldapManagedGroupToRolesMapping[ldapManagedGroupId] = currentMapping

				// just check if role shows up for the user now.
				for userId := range ldapManagedGroupToUser[ldapManagedGroupId] {
					tuples, err := iamRepo.GrantsForUser(ctx, userId)
					t.Log("userId/tuples:", userId, tuples)
					require.NoError(t, err)
					found := false
					foundRoles := []string{}
					for _, gt := range tuples {
						foundRoles = append(foundRoles, gt.RoleId)
						if gt.RoleId == roleId {
							found = true
							break
						}
					}
					if found {
						t.Log("FOUND:", userId, ldapManagedGroupId, foundRoles)
					}
					assert.Truef(t, found, "did not find role id %s in grants for user %s, grp %s, found user roles %s", roleId, userId, ldapManagedGroupId, foundRoles)
				}
			}
		}
	}

	// Now, fetch the set of grants. We're going to be testing this by looking
	// at the role IDs of the matching grant tuples.
	for _, user := range users {
		var rolesFromUsers, rolesFromGroups, rolesFromOidcManagedGroups, rolesFromLdapManagedGroups int

		tuples, err := iamRepo.GrantsForUser(ctx, user.PublicId)
		require.NoError(t, err)

		// De-dupe role IDs
		roleIds := make(map[string]bool, len(tuples))
		for _, tuple := range tuples {
			roleIds[tuple.RoleId] = true
		}

		// Now, using the previous maps, figure out which roles we _expect_ to
		// see returned. This is the set of roles with directly added users,
		// plus the set of roles where we added the user as a group member and
		// that group to a role.
		expectedRoleIds := make(map[string]bool, len(tuples))
		for roleId := range userToRolesMapping[user.PublicId] {
			expectedRoleIds[roleId] = true
			rolesFromUsers++
		}
		for groupId := range userToGroupsMapping[user.PublicId] {
			for roleId := range groupToRolesMapping[groupId] {
				expectedRoleIds[roleId] = true
				rolesFromGroups++
			}
		}
		for managedGroupId := range userToOidcManagedGroupsMapping[user.PublicId] {
			for roleId := range oidcManagedGroupToRolesMapping[managedGroupId] {
				expectedRoleIds[roleId] = true
				rolesFromOidcManagedGroups++
			}
		}
		for managedGroupId := range userToLdapManagedGroupsMapping[user.PublicId] {
			for roleId := range ldapManagedGroupToRolesMapping[managedGroupId] {
				if !expectedRoleIds[roleId] {
					t.Log("Adding ldap role: ", roleId)
				}
				expectedRoleIds[roleId] = true
				rolesFromLdapManagedGroups++
			}
		}

		// Now verify that the expected set and returned set match
		require.EqualValues(t, expectedRoleIds, roleIds)

		t.Log("finished user", user.PublicId,
			"total roles", len(expectedRoleIds),
			", roles from users", rolesFromUsers,
			", roles from groups", rolesFromGroups,
			", roles from oidc managed groups", rolesFromOidcManagedGroups,
			", roles from ldap managed groups", rolesFromLdapManagedGroups)
	}
}

func TestGrantsForUser(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	repo := iam.TestRepo(t, conn, wrap)

	// Test against each resource
	for _, r := range []resource.Type{resource.Group} {
		t.Run(fmt.Sprintf("[Resource: %s] [User Association]", r), func(t *testing.T) {
			// Create a couple users to test direct associations
			user := iam.TestUser(t, repo, "global")
			p1 := principal{principalId: user.PublicId, userId: user.PublicId}

			user2 := iam.TestUser(t, repo, "global")
			p2 := principal{principalId: user2.PublicId, userId: user2.PublicId}

			userRoleAssocFn := func(roleId, userId string) func() {
				return func() { iam.TestUserRole(t, conn, roleId, userId) }
			}
			testGrantsForUser(t, ctx, conn, repo, r, p1, p2, userRoleAssocFn)
		})
		t.Run(fmt.Sprintf("[Resource: %s] [Group Association]", r), func(t *testing.T) {
			// Create a couple groups to test indirect (group) associations
			gUser := iam.TestUser(t, repo, "global")
			group := iam.TestGroup(t, conn, "global")
			iam.TestGroupMember(t, conn, group.PublicId, gUser.PublicId)
			p1 := principal{principalId: group.PublicId, userId: gUser.PublicId}

			gUser2 := iam.TestUser(t, repo, "global")
			group2 := iam.TestGroup(t, conn, "global")
			iam.TestGroupMember(t, conn, group2.PublicId, gUser2.PublicId)
			p2 := principal{principalId: group2.PublicId, userId: gUser2.PublicId}

			groupRoleAssocFn := func(roleId, groupId string) func() {
				return func() { iam.TestGroupRole(t, conn, roleId, groupId) }
			}
			testGrantsForUser(t, ctx, conn, repo, r, p1, p2, groupRoleAssocFn)
		})
		t.Run(fmt.Sprintf("[Resource: %s] [Managed Groups Association]", r), func(t *testing.T) {
			// Create a couple of managed groups to test indirect (managed group) associations
			o, _ := iam.TestScopes(
				t,
				repo,
				iam.WithSkipAdminRoleCreation(true),
				iam.WithSkipDefaultRoleCreation(true),
			)
			databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
			require.NoError(t, err)

			oidcAuthMethod := oidc.TestAuthMethod(
				t, conn, databaseWrapper, "global", oidc.ActivePrivateState,
				"alice-rp-"+r.String(), "fido",
				oidc.WithSigningAlgs(oidc.RS256),
				oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
				oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
			)

			// oidcManagedGroup
			oidcAcct := oidc.TestAccount(t, conn, oidcAuthMethod, "sub")
			oidcManagedGroup := oidc.TestManagedGroup(t, conn, oidcAuthMethod, `"/token/sub" matches ".*"`)
			mgUser := iam.TestUser(t, repo, "global", iam.WithAccountIds(oidcAcct.PublicId))
			oidc.TestManagedGroupMember(t, conn, oidcManagedGroup.GetPublicId(), oidcAcct.GetPublicId())
			p1 := principal{principalId: oidcManagedGroup.PublicId, userId: mgUser.PublicId}

			// oidcManagedGroup2
			oidcAcct2 := oidc.TestAccount(t, conn, oidcAuthMethod, "sub no.2")
			oidcManagedGroup2 := oidc.TestManagedGroup(t, conn, oidcAuthMethod, `"/token/sub" matches ".*"`)
			mgUser2 := iam.TestUser(t, repo, "global", iam.WithAccountIds(oidcAcct2.PublicId))
			oidc.TestManagedGroupMember(t, conn, oidcManagedGroup2.GetPublicId(), oidcAcct2.GetPublicId())
			p2 := principal{principalId: oidcManagedGroup2.PublicId, userId: mgUser2.PublicId}

			mgRoleAssocFn := func(roleId, managedGrpId string) func() {
				return func() { iam.TestManagedGroupRole(t, conn, roleId, managedGrpId) }
			}
			testGrantsForUser(t, ctx, conn, repo, r, p1, p2, mgRoleAssocFn)
		})
	}
}

func testGrantsForUser(t *testing.T, ctx context.Context, conn *db.DB, repo *iam.Repository, r resource.Type, principal1, principal2 principal, roleAssociationFunc func(roleId, principalId string) func()) {
	// Create a series of scopes with roles in each. We'll create two of each
	// kind to ensure we're not just picking up the first role in each.

	// The first org/project set contains direct grants, but without
	// inheritance. We create two roles in each project.

	// Org1, Project1a, Project1b
	directGrantOrg1, directGrantProj1a, directGrantProj1b := iam.SetupDirectGrantScopes(t, conn, repo)

	// principal1
	directGrantOrg1Role := iam.TestRole(t, conn, directGrantOrg1.PublicId)
	directGrantOrg1RoleGrant1 := fmt.Sprintf("ids=*;type=%s;actions=*", r)
	directGrantOrg1RoleGrant2 := fmt.Sprintf("ids=*;type=%s;actions=create,list", r)
	grantRoleAndAssociate(t, conn, directGrantOrg1Role.PublicId, roleAssociationFunc(directGrantOrg1Role.PublicId, principal1.principalId),
		directGrantOrg1RoleGrant1, directGrantOrg1RoleGrant2,
	)

	// principal2
	directGrantOrg1Role2 := iam.TestRole(t, conn, directGrantOrg1.PublicId)
	directGrantOrg1RoleGrant3 := fmt.Sprintf("ids=*;type=%s;actions=update", r)
	grantRoleAndAssociate(t, conn, directGrantOrg1Role2.PublicId, roleAssociationFunc(directGrantOrg1Role2.PublicId, principal2.principalId), directGrantOrg1RoleGrant3)

	// principal1
	directGrantProj1aRole := iam.TestRole(t, conn, directGrantProj1a.PublicId)
	directGrantProj1aRoleGrant := fmt.Sprintf("ids=*;type=%s;actions=add-members,read", r)
	grantRoleAndAssociate(t, conn, directGrantProj1aRole.PublicId, roleAssociationFunc(directGrantProj1aRole.PublicId, principal1.principalId), directGrantProj1aRoleGrant)

	directGrantProj1bRole := iam.TestRole(t, conn, directGrantProj1b.PublicId)
	directGrantProj1bRoleGrant := fmt.Sprintf("ids=*;type=%s;actions=list,read", r)
	grantRoleAndAssociate(t, conn, directGrantProj1bRole.PublicId, roleAssociationFunc(directGrantProj1bRole.PublicId, principal1.principalId), directGrantProj1bRoleGrant)

	// principal2
	directGrantProj1aRole2 := iam.TestRole(t, conn, directGrantProj1a.PublicId)
	directGrantProj1aRoleGrant2 := fmt.Sprintf("ids=*;type=%s;actions=set-members", r)
	grantRoleAndAssociate(t, conn, directGrantProj1aRole2.PublicId, roleAssociationFunc(directGrantProj1aRole2.PublicId, principal2.principalId), directGrantProj1aRoleGrant2)

	directGrantProj1bRole2 := iam.TestRole(t, conn, directGrantProj1b.PublicId)
	directGrantProj1bRoleGrant2 := fmt.Sprintf("ids=*;type=%s;actions=delete", r)
	grantRoleAndAssociate(t, conn, directGrantProj1bRole2.PublicId, roleAssociationFunc(directGrantProj1bRole2.PublicId, principal2.principalId), directGrantProj1bRoleGrant2)

	// Org2, Project2a, Project2b
	directGrantOrg2, directGrantProj2a, directGrantProj2b := iam.SetupDirectGrantScopes(t, conn, repo)

	// principal1
	directGrantOrg2Role := iam.TestRole(t, conn, directGrantOrg2.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeThis,
			directGrantProj2a.PublicId,
		}))
	directGrantOrg2RoleGrant1 := fmt.Sprintf("ids=*;type=%s;actions=*", r)
	directGrantOrg2RoleGrant2 := fmt.Sprintf("ids=*;type=%s;actions=list,read", r)
	grantRoleAndAssociate(t, conn, directGrantOrg2Role.PublicId, roleAssociationFunc(directGrantOrg2Role.PublicId, principal1.principalId),
		directGrantOrg2RoleGrant1, directGrantOrg2RoleGrant2,
	)

	directGrantProj2aRole := iam.TestRole(t, conn, directGrantProj2a.PublicId)
	directGrantProj2aRoleGrant := "ids=hcst_abcd1234,hcst_1234abcd;actions=*"
	grantRoleAndAssociate(t, conn, directGrantProj2aRole.PublicId, roleAssociationFunc(directGrantProj2aRole.PublicId, principal1.principalId), directGrantProj2aRoleGrant)

	directGrantProj2bRole := iam.TestRole(t, conn, directGrantProj2b.PublicId)
	directGrantProj2bRoleGrant := "ids=cs_abcd1234;actions=read,update"
	grantRoleAndAssociate(t, conn, directGrantProj2bRole.PublicId, roleAssociationFunc(directGrantProj2bRole.PublicId, principal1.principalId), directGrantProj2bRoleGrant)

	// principal2
	directGrantOrg2Role2 := iam.TestRole(t, conn, directGrantOrg2.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeThis,
			directGrantProj2a.PublicId,
		}))
	directGrantOrg2RoleGrant3 := fmt.Sprintf("ids=*;type=%s;actions=add-members", r)
	grantRoleAndAssociate(t, conn, directGrantOrg2Role2.PublicId, roleAssociationFunc(directGrantOrg2Role2.PublicId, principal2.principalId), directGrantOrg2RoleGrant3)

	directGrantProj2aRole2 := iam.TestRole(t, conn, directGrantProj2a.PublicId)
	directGrantProj2aRoleGrant2 := "ids=hcst_abcd1234,hcst_1234abcd;actions=*"
	grantRoleAndAssociate(t, conn, directGrantProj2aRole2.PublicId, roleAssociationFunc(directGrantProj2aRole2.PublicId, principal2.principalId), directGrantProj2aRoleGrant2)

	directGrantProj2bRole2 := iam.TestRole(t, conn, directGrantProj2b.PublicId)
	directGrantProj2bRoleGrant2 := "ids=cs_abcd1234;actions=read,update"
	grantRoleAndAssociate(t, conn, directGrantProj2bRole2.PublicId, roleAssociationFunc(directGrantProj2bRole2.PublicId, principal2.principalId), directGrantProj2bRoleGrant2)

	// For the second set we create a couple of orgs/projects and then use globals.GrantScopeChildren
	//
	// child org 1
	childGrantOrg1, _ := iam.SetupChildGrantScopes(t, conn, repo)

	// principal1
	childGrantOrg1Role := iam.TestRole(t, conn, childGrantOrg1.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	childGrantOrg1RoleGrant := fmt.Sprintf("ids=*;type=%s;actions=add-members,remove-members", r)
	grantRoleAndAssociate(t, conn, childGrantOrg1Role.PublicId, roleAssociationFunc(childGrantOrg1Role.PublicId, principal1.principalId), childGrantOrg1RoleGrant)

	// principal2
	childGrantOrg1Role2 := iam.TestRole(t, conn, childGrantOrg1.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	childGrantOrg1RoleGrant2 := fmt.Sprintf("ids=*;type=%s;actions=read", r)
	grantRoleAndAssociate(t, conn, childGrantOrg1Role2.PublicId, roleAssociationFunc(childGrantOrg1Role2.PublicId, principal2.principalId), childGrantOrg1RoleGrant2)

	// child org 2
	childGrantOrg2, _ := iam.SetupChildGrantScopes(t, conn, repo)

	// principal1
	childGrantOrg2Role := iam.TestRole(t, conn, childGrantOrg2.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	childGrantOrg2RoleGrant1 := fmt.Sprintf("ids=*;type=%s;actions=set-members", r)
	childGrantOrg2RoleGrant2 := fmt.Sprintf("ids=*;type=%s;actions=delete", r)
	grantRoleAndAssociate(t, conn, childGrantOrg2Role.PublicId, roleAssociationFunc(childGrantOrg2Role.PublicId, principal1.principalId),
		childGrantOrg2RoleGrant1, childGrantOrg2RoleGrant2,
	)

	// principal2
	childGrantOrg2Role2 := iam.TestRole(t, conn, childGrantOrg2.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	childGrantOrg2RoleGrant3 := fmt.Sprintf("ids=*;type=%s;actions=set-members", r)
	grantRoleAndAssociate(t, conn, childGrantOrg2Role2.PublicId, roleAssociationFunc(childGrantOrg2Role2.PublicId, principal2.principalId), childGrantOrg2RoleGrant3)

	// Finally, let's create some roles at global scope with this, children, and descendants grants
	//
	// principal1
	directGrantGlobalRole := iam.TestRole(t, conn, scope.Global.String())
	directGrantGlobalRoleGrant := fmt.Sprintf("ids=*;type=%s;actions=read", r)
	grantRoleAndAssociate(t, conn, directGrantGlobalRole.PublicId, roleAssociationFunc(directGrantGlobalRole.PublicId, principal1.principalId), directGrantGlobalRoleGrant)

	// principal2
	directGrantGlobalRole2 := iam.TestRole(t, conn, scope.Global.String())
	directGrantGlobalRoleGrant2 := fmt.Sprintf("ids=*;type=%s;actions=list", r)
	grantRoleAndAssociate(t, conn, directGrantGlobalRole2.PublicId, roleAssociationFunc(directGrantGlobalRole2.PublicId, principal2.principalId), directGrantGlobalRoleGrant2)

	// principal1
	childGrantGlobalRole := iam.TestRole(t, conn, scope.Global.String(),
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	childGrantGlobalRoleGrant := fmt.Sprintf("ids=*;type=%s;actions=*", r)
	grantRoleAndAssociate(t, conn, childGrantGlobalRole.PublicId, roleAssociationFunc(childGrantGlobalRole.PublicId, principal1.principalId), childGrantGlobalRoleGrant)

	// principal2
	childGrantGlobalRole2 := iam.TestRole(t, conn, scope.Global.String(),
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	childGrantGlobalRoleGrant2 := fmt.Sprintf("ids=*;type=%s;actions=list", r)
	grantRoleAndAssociate(t, conn, childGrantGlobalRole2.PublicId, roleAssociationFunc(childGrantGlobalRole2.PublicId, principal2.principalId), childGrantGlobalRoleGrant2)

	// principal1
	descendantGrantGlobalRole := iam.TestRole(t, conn, scope.Global.String(),
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeDescendants,
		}))
	descendantGrantGlobalRoleGrant := fmt.Sprintf("ids=*;type=%s;actions=*", r)
	grantRoleAndAssociate(t, conn, descendantGrantGlobalRole.PublicId, roleAssociationFunc(descendantGrantGlobalRole.PublicId, principal1.principalId), descendantGrantGlobalRoleGrant)

	// principal2
	descendantGrantGlobalRole2 := iam.TestRole(t, conn, scope.Global.String(),
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeDescendants,
		}))
	descendantGrantGlobalRoleGrant2 := fmt.Sprintf("ids=*;type=%s;actions=add-members", r)
	grantRoleAndAssociate(t, conn, descendantGrantGlobalRole2.PublicId, roleAssociationFunc(descendantGrantGlobalRole2.PublicId, principal2.principalId), descendantGrantGlobalRoleGrant2)

	resourceAllowedIn, err := scope.AllowedIn(ctx, r)
	require.NoError(t, err)

	t.Run("db-grants", func(t *testing.T) {
		// Here we should see exactly what the DB has returned, before we do some
		// local exploding of grants and grant scopes

		expMultiGrantTuples := map[principal][]iam.MultiGrantTuple{
			principal1: {},
			principal2: {},
		}

		// Build the expected set of grants based on the resource's applicable scopes
		switch {
		case slices.Equal(resourceAllowedIn, []scope.Type{scope.Global}):
			// Global
			expMultiGrantTuples = map[principal][]iam.MultiGrantTuple{
				principal1: {
					// Direct global:
					{
						RoleId:            directGrantGlobalRole.PublicId,
						RoleScopeId:       scope.Global.String(),
						RoleParentScopeId: "",
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantGlobalRoleGrant,
					},
					// no Direct org1/2:
					// no Proj orgs 1/2:
					// no Child grants from orgs 1/2:
					// no Children of global and no Descendants of global
				},
				principal2: {
					// Direct global:
					{
						RoleId:            directGrantGlobalRole2.PublicId,
						RoleScopeId:       scope.Global.String(),
						RoleParentScopeId: "",
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantGlobalRoleGrant2,
					},
					// no Direct org1/2:
					// no Proj orgs 1/2:
					// no Child grants from orgs 1/2:
					// no Children of global and no Descendants of global
				},
			}
		case slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org}):
			// Global + Org
			expMultiGrantTuples = map[principal][]iam.MultiGrantTuple{
				principal1: {
					// Direct global:
					{
						RoleId:            directGrantGlobalRole.PublicId,
						RoleScopeId:       scope.Global.String(),
						RoleParentScopeId: "",
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantGlobalRoleGrant,
					},
					// Direct org1/2:
					{
						RoleId:            directGrantOrg1Role.PublicId,
						RoleScopeId:       directGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            strings.Join([]string{directGrantOrg1RoleGrant1, directGrantOrg1RoleGrant2}, "^"),
					},
					{
						RoleId:            directGrantOrg2Role.PublicId,
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     strings.Join([]string{globals.GrantScopeThis, directGrantProj2a.PublicId}, "^"),
						Grants:            strings.Join([]string{directGrantOrg2RoleGrant1, directGrantOrg2RoleGrant2}, "^"),
					},
					// no Proj orgs 1/2
					// Child grants from orgs 1/2:
					{
						RoleId:            childGrantOrg1Role.PublicId,
						RoleScopeId:       childGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     globals.GrantScopeChildren,
						Grants:            childGrantOrg1RoleGrant,
					},
					{
						RoleId:            childGrantOrg2Role.PublicId,
						RoleScopeId:       childGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     globals.GrantScopeChildren,
						Grants:            strings.Join([]string{childGrantOrg2RoleGrant1, childGrantOrg2RoleGrant2}, "^"),
					},
					// Children of global and descendants of global
					{
						RoleId:        descendantGrantGlobalRole.PublicId,
						RoleScopeId:   scope.Global.String(),
						GrantScopeIds: globals.GrantScopeDescendants,
						Grants:        descendantGrantGlobalRoleGrant,
					},
					{
						RoleId:        childGrantGlobalRole.PublicId,
						RoleScopeId:   scope.Global.String(),
						GrantScopeIds: globals.GrantScopeChildren,
						Grants:        childGrantGlobalRoleGrant,
					},
				},
				principal2: {
					// Direct global:
					{
						RoleId:            directGrantGlobalRole2.PublicId,
						RoleScopeId:       scope.Global.String(),
						RoleParentScopeId: "",
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantGlobalRoleGrant2,
					},
					// Direct org1/2:
					{
						RoleId:            directGrantOrg1Role2.PublicId,
						RoleScopeId:       directGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantOrg1RoleGrant3,
					},
					{
						RoleId:            directGrantOrg2Role2.PublicId,
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     strings.Join([]string{globals.GrantScopeThis, directGrantProj2a.PublicId}, "^"),
						Grants:            directGrantOrg2RoleGrant3,
					},
					// no Proj orgs 1/2
					// Child grants from orgs 1/2:
					{
						RoleId:            childGrantOrg1Role2.PublicId,
						RoleScopeId:       childGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     globals.GrantScopeChildren,
						Grants:            childGrantOrg1RoleGrant2,
					},
					{
						RoleId:            childGrantOrg2Role2.PublicId,
						RoleScopeId:       childGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     globals.GrantScopeChildren,
						Grants:            childGrantOrg2RoleGrant3,
					},
					// Children of global and descendants of global
					{
						RoleId:        descendantGrantGlobalRole2.PublicId,
						RoleScopeId:   scope.Global.String(),
						GrantScopeIds: globals.GrantScopeDescendants,
						Grants:        descendantGrantGlobalRoleGrant2,
					},
					{
						RoleId:        childGrantGlobalRole2.PublicId,
						RoleScopeId:   scope.Global.String(),
						GrantScopeIds: globals.GrantScopeChildren,
						Grants:        childGrantGlobalRoleGrant2,
					},
				},
			}
		case slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org, scope.Project}):
			// Global + Org + Project
			expMultiGrantTuples = map[principal][]iam.MultiGrantTuple{
				principal1: {
					// Direct global:
					{
						RoleId:            directGrantGlobalRole.PublicId,
						RoleScopeId:       scope.Global.String(),
						RoleParentScopeId: "",
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantGlobalRoleGrant,
					},
					// Direct org1/2:
					{
						RoleId:            directGrantOrg1Role.PublicId,
						RoleScopeId:       directGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            strings.Join([]string{directGrantOrg1RoleGrant1, directGrantOrg1RoleGrant2}, "^"),
					},
					{
						RoleId:            directGrantOrg2Role.PublicId,
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     strings.Join([]string{globals.GrantScopeThis, directGrantProj2a.PublicId}, "^"),
						Grants:            strings.Join([]string{directGrantOrg2RoleGrant1, directGrantOrg2RoleGrant2}, "^"),
					},
					// Proj orgs 1/2:
					{
						RoleId:            directGrantProj1aRole.PublicId,
						RoleScopeId:       directGrantProj1a.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantProj1aRoleGrant,
					},
					{
						RoleId:            directGrantProj1bRole.PublicId,
						RoleScopeId:       directGrantProj1b.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantProj1bRoleGrant,
					},
					{
						RoleId:            directGrantProj2aRole.PublicId,
						RoleScopeId:       directGrantProj2a.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantProj2aRoleGrant,
					},
					{
						RoleId:            directGrantProj2bRole.PublicId,
						RoleScopeId:       directGrantProj2b.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantProj2bRoleGrant,
					},
					// Child grants from orgs 1/2:
					{
						RoleId:            childGrantOrg1Role.PublicId,
						RoleScopeId:       childGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     globals.GrantScopeChildren,
						Grants:            childGrantOrg1RoleGrant,
					},
					{
						RoleId:            childGrantOrg2Role.PublicId,
						RoleScopeId:       childGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     globals.GrantScopeChildren,
						Grants:            strings.Join([]string{childGrantOrg2RoleGrant1, childGrantOrg2RoleGrant2}, "^"),
					},
					// Children of global and descendants of global
					{
						RoleId:        descendantGrantGlobalRole.PublicId,
						RoleScopeId:   scope.Global.String(),
						GrantScopeIds: globals.GrantScopeDescendants,
						Grants:        descendantGrantGlobalRoleGrant,
					},
					{
						RoleId:        childGrantGlobalRole.PublicId,
						RoleScopeId:   scope.Global.String(),
						GrantScopeIds: globals.GrantScopeChildren,
						Grants:        childGrantGlobalRoleGrant,
					},
				},
				principal2: {
					// Direct global:
					{
						RoleId:            directGrantGlobalRole2.PublicId,
						RoleScopeId:       scope.Global.String(),
						RoleParentScopeId: "",
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantGlobalRoleGrant2,
					},
					// Direct org1/2:
					{
						RoleId:            directGrantOrg1Role2.PublicId,
						RoleScopeId:       directGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantOrg1RoleGrant3,
					},
					{
						RoleId:            directGrantOrg2Role2.PublicId,
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     strings.Join([]string{globals.GrantScopeThis, directGrantProj2a.PublicId}, "^"),
						Grants:            directGrantOrg2RoleGrant3,
					},
					// Proj orgs 1/2:
					{
						RoleId:            directGrantProj1aRole2.PublicId,
						RoleScopeId:       directGrantProj1a.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantProj1aRoleGrant2,
					},
					{
						RoleId:            directGrantProj1bRole2.PublicId,
						RoleScopeId:       directGrantProj1b.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantProj1bRoleGrant2,
					},
					{
						RoleId:            directGrantProj2aRole2.PublicId,
						RoleScopeId:       directGrantProj2a.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantProj2aRoleGrant2,
					},
					{
						RoleId:            directGrantProj2bRole2.PublicId,
						RoleScopeId:       directGrantProj2b.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantProj2bRoleGrant2,
					},
					// Child grants from orgs 1/2:
					{
						RoleId:            childGrantOrg1Role2.PublicId,
						RoleScopeId:       childGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     globals.GrantScopeChildren,
						Grants:            childGrantOrg1RoleGrant2,
					},
					{
						RoleId:            childGrantOrg2Role2.PublicId,
						RoleScopeId:       childGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     globals.GrantScopeChildren,
						Grants:            childGrantOrg2RoleGrant3,
					},
					// Children of global and descendants of global
					{
						RoleId:        descendantGrantGlobalRole2.PublicId,
						RoleScopeId:   scope.Global.String(),
						GrantScopeIds: globals.GrantScopeDescendants,
						Grants:        descendantGrantGlobalRoleGrant2,
					},
					{
						RoleId:        childGrantGlobalRole2.PublicId,
						RoleScopeId:   scope.Global.String(),
						GrantScopeIds: globals.GrantScopeChildren,
						Grants:        childGrantGlobalRoleGrant2,
					},
				},
			}
		case slices.Equal(resourceAllowedIn, []scope.Type{scope.Project}):
			// Project
			expMultiGrantTuples = map[principal][]iam.MultiGrantTuple{
				principal1: {
					// no Direct global
					// no Direct org1/2:
					// Proj orgs 1/2:
					{
						RoleId:            directGrantProj1aRole.PublicId,
						RoleScopeId:       directGrantProj1a.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantProj1aRoleGrant,
					},
					{
						RoleId:            directGrantProj1bRole.PublicId,
						RoleScopeId:       directGrantProj1b.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantProj1bRoleGrant,
					},
					{
						RoleId:            directGrantProj2aRole.PublicId,
						RoleScopeId:       directGrantProj2a.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantProj2aRoleGrant,
					},
					{
						RoleId:            directGrantProj2bRole.PublicId,
						RoleScopeId:       directGrantProj2b.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantProj2bRoleGrant,
					},
					// Child grants from orgs 1/2:
					{
						RoleId:            childGrantOrg1Role.PublicId,
						RoleScopeId:       childGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     globals.GrantScopeChildren,
						Grants:            childGrantOrg1RoleGrant,
					},
					{
						RoleId:            childGrantOrg2Role.PublicId,
						RoleScopeId:       childGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     globals.GrantScopeChildren,
						Grants:            strings.Join([]string{childGrantOrg2RoleGrant1, childGrantOrg2RoleGrant2}, "^"),
					},
					// no Children of global
					// Descendants of global
					{
						RoleId:        descendantGrantGlobalRole.PublicId,
						RoleScopeId:   scope.Global.String(),
						GrantScopeIds: globals.GrantScopeDescendants,
						Grants:        descendantGrantGlobalRoleGrant,
					},
				},
				principal2: {
					// no Direct global
					// no Direct org1/2:
					// Proj orgs 1/2:
					{
						RoleId:            directGrantProj1aRole.PublicId,
						RoleScopeId:       directGrantProj1a.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantProj1aRoleGrant,
					},
					{
						RoleId:            directGrantProj1bRole.PublicId,
						RoleScopeId:       directGrantProj1b.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantProj1bRoleGrant,
					},
					{
						RoleId:            directGrantProj2aRole.PublicId,
						RoleScopeId:       directGrantProj2a.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantProj2aRoleGrant,
					},
					{
						RoleId:            directGrantProj2bRole.PublicId,
						RoleScopeId:       directGrantProj2b.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeIds:     globals.GrantScopeThis,
						Grants:            directGrantProj2bRoleGrant,
					},
					// Child grants from orgs 1/2:
					{
						RoleId:            childGrantOrg1Role.PublicId,
						RoleScopeId:       childGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     globals.GrantScopeChildren,
						Grants:            childGrantOrg1RoleGrant,
					},
					{
						RoleId:            childGrantOrg2Role.PublicId,
						RoleScopeId:       childGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeIds:     globals.GrantScopeChildren,
						Grants:            strings.Join([]string{childGrantOrg2RoleGrant1, childGrantOrg2RoleGrant2}, "^"),
					},
					// no Children of global
					// Descendants of global
					{
						RoleId:        descendantGrantGlobalRole.PublicId,
						RoleScopeId:   scope.Global.String(),
						GrantScopeIds: globals.GrantScopeDescendants,
						Grants:        descendantGrantGlobalRoleGrant,
					},
				},
			}
		}

		for principal, tuples := range expMultiGrantTuples {
			for i, tuple := range tuples {
				tuple.TestStableSort()
				expMultiGrantTuples[principal][i] = tuple
			}
			multiGrantTuplesCache := new([]iam.MultiGrantTuple)
			_, err := repo.GrantsForUser(ctx, principal.userId, iam.WithTestCacheMultiGrantTuples(multiGrantTuplesCache))
			require.NoError(t, err)

			assert.ElementsMatch(t, *multiGrantTuplesCache, expMultiGrantTuples[principal])
		}
	})

	t.Run("exploded-grants", func(t *testing.T) {
		// We expect to see:
		//
		// * A global grant
		// * Grants from direct orgs/projs:
		//   * directGrantOrg1/directGrantOrg2 on org and respective projects (6 grants total per org)
		//   * directGrantProj on respective projects (4 grants total)
		expGrantTuples := []perms.GrantTuple{}

		switch {
		case slices.Equal(resourceAllowedIn, []scope.Type{scope.Global}):
			// Global
			expGrantTuples = []perms.GrantTuple{
				// Grants from global:
				{
					RoleId:            directGrantGlobalRole.PublicId,
					RoleScopeId:       scope.Global.String(),
					RoleParentScopeId: "",
					GrantScopeId:      scope.Global.String(),
					Grant:             directGrantGlobalRoleGrant,
				},
			}
		case slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org}):
			// Global + Org
			expGrantTuples = []perms.GrantTuple{
				// Grants from global:
				{
					RoleId:            directGrantGlobalRole.PublicId,
					RoleScopeId:       scope.Global.String(),
					RoleParentScopeId: "",
					GrantScopeId:      scope.Global.String(),
					Grant:             directGrantGlobalRoleGrant,
				},
				// Grants from direct org1 to org1:
				{
					RoleId:            directGrantOrg1Role.PublicId,
					RoleScopeId:       directGrantOrg1.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      directGrantOrg1.PublicId,
					Grant:             directGrantOrg1RoleGrant1,
				},
				{
					RoleId:            directGrantOrg1Role.PublicId,
					RoleScopeId:       directGrantOrg1.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      directGrantOrg1.PublicId,
					Grant:             directGrantOrg1RoleGrant2,
				},
				// Grants from direct org2 to org2:
				{
					RoleId:            directGrantOrg2Role.PublicId,
					RoleScopeId:       directGrantOrg2.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      directGrantOrg2.PublicId,
					Grant:             directGrantOrg2RoleGrant1,
				},
				{
					RoleId:            directGrantOrg2Role.PublicId,
					RoleScopeId:       directGrantOrg2.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      directGrantOrg2.PublicId,
					Grant:             directGrantOrg2RoleGrant2,
				},
				// Child grants from global to child org1/org2:
				{
					RoleId:            childGrantOrg1Role.PublicId,
					RoleScopeId:       childGrantOrg1.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      globals.GrantScopeChildren,
					Grant:             childGrantOrg1RoleGrant,
				},
				{
					RoleId:            childGrantOrg2Role.PublicId,
					RoleScopeId:       childGrantOrg2.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      globals.GrantScopeChildren,
					Grant:             childGrantOrg2RoleGrant1,
				},
				{
					RoleId:            childGrantOrg2Role.PublicId,
					RoleScopeId:       childGrantOrg2.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      globals.GrantScopeChildren,
					Grant:             childGrantOrg2RoleGrant2,
				},
				{
					RoleId:       childGrantGlobalRole.PublicId,
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: globals.GrantScopeChildren,
					Grant:        childGrantGlobalRoleGrant,
				},
			}
		case slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org, scope.Project}):
			// Global + Org + Project
			expGrantTuples = []perms.GrantTuple{
				// Grants from global:
				{
					RoleId:            directGrantGlobalRole.PublicId,
					RoleScopeId:       scope.Global.String(),
					RoleParentScopeId: "",
					GrantScopeId:      scope.Global.String(),
					Grant:             directGrantGlobalRoleGrant,
				},
				// Grants from direct org1 to org1/proj1a/proj1b:
				{
					RoleId:            directGrantOrg1Role.PublicId,
					RoleScopeId:       directGrantOrg1.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      directGrantOrg1.PublicId,
					Grant:             directGrantOrg1RoleGrant1,
				},
				{
					RoleId:            directGrantOrg1Role.PublicId,
					RoleScopeId:       directGrantOrg1.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      directGrantOrg1.PublicId,
					Grant:             directGrantOrg1RoleGrant2,
				},
				// Grants from direct org 1 proj 1a:
				{
					RoleId:            directGrantProj1aRole.PublicId,
					RoleScopeId:       directGrantProj1a.PublicId,
					RoleParentScopeId: directGrantOrg1.PublicId,
					GrantScopeId:      directGrantProj1a.PublicId,
					Grant:             directGrantProj1aRoleGrant,
				},
				// Grant from direct org 1 proj 1 b:
				{
					RoleId:            directGrantProj1bRole.PublicId,
					RoleScopeId:       directGrantProj1b.PublicId,
					RoleParentScopeId: directGrantOrg1.PublicId,
					GrantScopeId:      directGrantProj1b.PublicId,
					Grant:             directGrantProj1bRoleGrant,
				},
				// Grants from direct org2 to org2/proj2a/proj2b:
				{
					RoleId:            directGrantOrg2Role.PublicId,
					RoleScopeId:       directGrantOrg2.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      directGrantOrg2.PublicId,
					Grant:             directGrantOrg2RoleGrant1,
				},
				{
					RoleId:            directGrantOrg2Role.PublicId,
					RoleScopeId:       directGrantOrg2.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      directGrantProj2a.PublicId,
					Grant:             directGrantOrg2RoleGrant1,
				},
				{
					RoleId:            directGrantOrg2Role.PublicId,
					RoleScopeId:       directGrantOrg2.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      directGrantOrg2.PublicId,
					Grant:             directGrantOrg2RoleGrant2,
				},
				{
					RoleId:            directGrantOrg2Role.PublicId,
					RoleScopeId:       directGrantOrg2.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      directGrantProj2a.PublicId,
					Grant:             directGrantOrg2RoleGrant2,
				},
				// Grants from direct org 2 proj 2a:
				{
					RoleId:            directGrantProj2aRole.PublicId,
					RoleScopeId:       directGrantProj2a.PublicId,
					RoleParentScopeId: directGrantOrg2.PublicId,
					GrantScopeId:      directGrantProj2a.PublicId,
					Grant:             directGrantProj2aRoleGrant,
				},
				// Grant from direct org 2 proj 2 b:
				{
					RoleId:            directGrantProj2bRole.PublicId,
					RoleScopeId:       directGrantProj2b.PublicId,
					RoleParentScopeId: directGrantOrg2.PublicId,
					GrantScopeId:      directGrantProj2b.PublicId,
					Grant:             directGrantProj2bRoleGrant,
				},
				// Child grants from child org1 to proj1a/proj1b:
				{
					RoleId:            childGrantOrg1Role.PublicId,
					RoleScopeId:       childGrantOrg1.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      globals.GrantScopeChildren,
					Grant:             childGrantOrg1RoleGrant,
				},
				// Child grants from child org2 to proj2a/proj2b:
				{
					RoleId:            childGrantOrg2Role.PublicId,
					RoleScopeId:       childGrantOrg2.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      globals.GrantScopeChildren,
					Grant:             childGrantOrg2RoleGrant1,
				},
				{
					RoleId:            childGrantOrg2Role.PublicId,
					RoleScopeId:       childGrantOrg2.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      globals.GrantScopeChildren,
					Grant:             childGrantOrg2RoleGrant2,
				},
				// Grants from global to every org:
				{
					RoleId:       childGrantGlobalRole.PublicId,
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: globals.GrantScopeChildren,
					Grant:        childGrantGlobalRoleGrant,
				},
				// Grants from global to every org and project:
				{
					RoleId:       descendantGrantGlobalRole.PublicId,
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: globals.GrantScopeDescendants,
					Grant:        descendantGrantGlobalRoleGrant,
				},
			}
		case slices.Equal(resourceAllowedIn, []scope.Type{scope.Project}):
			// Project
			expGrantTuples = []perms.GrantTuple{
				// Grants from direct org1 to org1/proj1a/proj1b:
				{
					RoleId:            directGrantOrg1Role.PublicId,
					RoleScopeId:       directGrantOrg1.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      directGrantOrg1.PublicId,
					Grant:             directGrantOrg1RoleGrant1,
				},
				{
					RoleId:            directGrantOrg1Role.PublicId,
					RoleScopeId:       directGrantOrg1.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      directGrantOrg1.PublicId,
					Grant:             directGrantOrg1RoleGrant2,
				},
				// Grants from direct org 1 proj 1a:
				{
					RoleId:            directGrantProj1aRole.PublicId,
					RoleScopeId:       directGrantProj1a.PublicId,
					RoleParentScopeId: directGrantOrg1.PublicId,
					GrantScopeId:      directGrantProj1a.PublicId,
					Grant:             directGrantProj1aRoleGrant,
				},
				// Grant from direct org 1 proj 1 b:
				{
					RoleId:            directGrantProj1bRole.PublicId,
					RoleScopeId:       directGrantProj1b.PublicId,
					RoleParentScopeId: directGrantOrg1.PublicId,
					GrantScopeId:      directGrantProj1b.PublicId,
					Grant:             directGrantProj1bRoleGrant,
				},

				// Grants from direct org2 to org2/proj2a/proj2b:
				{
					RoleId:            directGrantOrg2Role.PublicId,
					RoleScopeId:       directGrantOrg2.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      directGrantOrg2.PublicId,
					Grant:             directGrantOrg2RoleGrant1,
				},
				{
					RoleId:            directGrantOrg2Role.PublicId,
					RoleScopeId:       directGrantOrg2.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      directGrantProj2a.PublicId,
					Grant:             directGrantOrg2RoleGrant1,
				},
				{
					RoleId:            directGrantOrg2Role.PublicId,
					RoleScopeId:       directGrantOrg2.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      directGrantOrg2.PublicId,
					Grant:             directGrantOrg2RoleGrant2,
				},
				{
					RoleId:            directGrantOrg2Role.PublicId,
					RoleScopeId:       directGrantOrg2.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      directGrantProj2a.PublicId,
					Grant:             directGrantOrg2RoleGrant2,
				},
				// Grants from direct org 2 proj 2a:
				{
					RoleId:            directGrantProj2aRole.PublicId,
					RoleScopeId:       directGrantProj2a.PublicId,
					RoleParentScopeId: directGrantOrg2.PublicId,
					GrantScopeId:      directGrantProj2a.PublicId,
					Grant:             directGrantProj2aRoleGrant,
				},
				// Grant from direct org 2 proj 2 b:
				{
					RoleId:            directGrantProj2bRole.PublicId,
					RoleScopeId:       directGrantProj2b.PublicId,
					RoleParentScopeId: directGrantOrg2.PublicId,
					GrantScopeId:      directGrantProj2b.PublicId,
					Grant:             directGrantProj2bRoleGrant,
				},
				// Child grants from child org1 to proj1a/proj1b:
				{
					RoleId:            childGrantOrg1Role.PublicId,
					RoleScopeId:       childGrantOrg1.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      globals.GrantScopeChildren,
					Grant:             childGrantOrg1RoleGrant,
				},
				// Child grants from child org2 to proj2a/proj2b:
				{
					RoleId:            childGrantOrg2Role.PublicId,
					RoleScopeId:       childGrantOrg2.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      globals.GrantScopeChildren,
					Grant:             childGrantOrg2RoleGrant1,
				},
				{
					RoleId:            childGrantOrg2Role.PublicId,
					RoleScopeId:       childGrantOrg2.PublicId,
					RoleParentScopeId: scope.Global.String(),
					GrantScopeId:      globals.GrantScopeChildren,
					Grant:             childGrantOrg2RoleGrant2,
				},
				// Grants from global to every org:
				{
					RoleId:       childGrantGlobalRole.PublicId,
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: globals.GrantScopeChildren,
					Grant:        childGrantGlobalRoleGrant,
				},
				// Grants from global to every org and project:
				{
					RoleId:       descendantGrantGlobalRole.PublicId,
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: globals.GrantScopeDescendants,
					Grant:        descendantGrantGlobalRoleGrant,
				},
			}
		}

		multiGrantTuplesCache := new([]iam.MultiGrantTuple)
		grantTuples, err := repo.GrantsForUser(ctx, principal1.userId, iam.WithTestCacheMultiGrantTuples(multiGrantTuplesCache))
		require.NoError(t, err)
		assert.ElementsMatch(t, grantTuples, expGrantTuples)
	})

	t.Run("acl-grants", func(t *testing.T) {
		grantTuples, err := repo.GrantsForUser(ctx, principal1.userId)
		require.NoError(t, err)
		grants := make([]perms.Grant, 0, len(grantTuples))
		for _, gt := range grantTuples {
			grant, err := perms.Parse(ctx, gt)
			require.NoError(t, err)
			grants = append(grants, grant)
		}
		acl := perms.NewACL(grants...)

		// Descendant & Children grants
		if slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org}) ||
			slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org, scope.Project}) ||
			slices.Equal(resourceAllowedIn, []scope.Type{scope.Project}) {
			t.Run("descendant-grants", func(t *testing.T) {
				descendantGrants := acl.DescendantsGrants()
				expDescendantGrants := []perms.AclGrant{
					{
						RoleScopeId:  scope.Global.String(),
						GrantScopeId: globals.GrantScopeDescendants,
						Id:           "*",
						Type:         r,
						ActionSet:    perms.ActionSet{action.All: true},
					},
				}
				assert.ElementsMatch(t, descendantGrants, expDescendantGrants)
			})

			t.Run("child-grants", func(t *testing.T) {
				childrenGrants := acl.ChildrenScopeGrantMap()
				expChildrenGrants := map[string][]perms.AclGrant{
					childGrantOrg1.PublicId: {
						{
							RoleScopeId:       childGrantOrg1.PublicId,
							RoleParentScopeId: scope.Global.String(),
							GrantScopeId:      globals.GrantScopeChildren,
							Id:                "*",
							Type:              r,
							ActionSet:         perms.ActionSet{action.AddMembers: true, action.RemoveMembers: true},
						},
					},
					childGrantOrg2.PublicId: {
						{
							RoleScopeId:       childGrantOrg2.PublicId,
							RoleParentScopeId: scope.Global.String(),
							GrantScopeId:      globals.GrantScopeChildren,
							Id:                "*",
							Type:              r,
							ActionSet:         perms.ActionSet{action.SetMembers: true},
						},
						{
							RoleScopeId:       childGrantOrg2.PublicId,
							RoleParentScopeId: scope.Global.String(),
							GrantScopeId:      globals.GrantScopeChildren,
							Id:                "*",
							Type:              r,
							ActionSet:         perms.ActionSet{action.Delete: true},
						},
					},
					scope.Global.String(): {
						{
							RoleScopeId:  scope.Global.String(),
							GrantScopeId: globals.GrantScopeChildren,
							Id:           "*",
							Type:         r,
							ActionSet:    perms.ActionSet{action.All: true},
						},
					},
				}
				assert.Len(t, childrenGrants, len(expChildrenGrants))
				for k, v := range childrenGrants {
					assert.ElementsMatch(t, v, expChildrenGrants[k])
				}
			})
		}

		// Direct grants
		t.Run("direct-grants", func(t *testing.T) {
			directGrants := acl.DirectScopeGrantMap()
			expDirectGrants := map[string][]perms.AclGrant{}

			switch {
			// Global
			case slices.Equal(resourceAllowedIn, []scope.Type{scope.Global}):
				expDirectGrants[scope.Global.String()] = append(expDirectGrants[scope.Global.String()], []perms.AclGrant{
					{
						RoleScopeId:  scope.Global.String(),
						GrantScopeId: scope.Global.String(),
						Id:           "*",
						Type:         r,
						ActionSet:    perms.ActionSet{action.Read: true},
					},
				}...)

			// Global + Org
			case slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org}):
				expDirectGrants[scope.Global.String()] = append(expDirectGrants[scope.Global.String()], []perms.AclGrant{
					{
						RoleScopeId:  scope.Global.String(),
						GrantScopeId: scope.Global.String(),
						Id:           "*",
						Type:         r,
						ActionSet:    perms.ActionSet{action.Read: true},
					},
				}...)
				expDirectGrants[directGrantOrg1.PublicId] = append(expDirectGrants[directGrantOrg1.PublicId], []perms.AclGrant{
					{
						RoleScopeId:       directGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg1.PublicId,
						Id:                "*",
						Type:              r,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg1.PublicId,
						Id:                "*",
						Type:              r,
						ActionSet:         perms.ActionSet{action.Create: true, action.List: true},
					},
				}...)
				expDirectGrants[directGrantOrg2.PublicId] = append(expDirectGrants[directGrantOrg2.PublicId], []perms.AclGrant{
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg2.PublicId,
						Id:                "*",
						Type:              r,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg2.PublicId,
						Id:                "*",
						Type:              r,
						ActionSet:         perms.ActionSet{action.List: true, action.Read: true},
					},
				}...)

			// Global + Org + Project
			case slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org, scope.Project}):
				expDirectGrants[scope.Global.String()] = append(expDirectGrants[scope.Global.String()], []perms.AclGrant{
					{
						RoleScopeId:  scope.Global.String(),
						GrantScopeId: scope.Global.String(),
						Id:           "*",
						Type:         r,
						ActionSet:    perms.ActionSet{action.Read: true},
					},
				}...)
				expDirectGrants[directGrantOrg1.PublicId] = append(expDirectGrants[directGrantOrg1.PublicId], []perms.AclGrant{
					{
						RoleScopeId:       directGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg1.PublicId,
						Id:                "*",
						Type:              r,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg1.PublicId,
						Id:                "*",
						Type:              r,
						ActionSet:         perms.ActionSet{action.Create: true, action.List: true},
					},
				}...)
				expDirectGrants[directGrantOrg2.PublicId] = append(expDirectGrants[directGrantOrg2.PublicId], []perms.AclGrant{
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg2.PublicId,
						Id:                "*",
						Type:              r,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg2.PublicId,
						Id:                "*",
						Type:              r,
						ActionSet:         perms.ActionSet{action.List: true, action.Read: true},
					},
				}...)
				expDirectGrants[directGrantProj1a.PublicId] = append(expDirectGrants[directGrantProj1a.PublicId], []perms.AclGrant{
					{
						RoleScopeId:       directGrantProj1a.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeId:      directGrantProj1a.PublicId,
						Id:                "*",
						Type:              r,
						ActionSet:         perms.ActionSet{action.AddMembers: true, action.Read: true},
					},
				}...)
				expDirectGrants[directGrantProj1b.PublicId] = append(expDirectGrants[directGrantProj1b.PublicId], []perms.AclGrant{
					{
						RoleScopeId:       directGrantProj1b.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeId:      directGrantProj1b.PublicId,
						Id:                "*",
						Type:              r,
						ActionSet:         perms.ActionSet{action.List: true, action.Read: true},
					},
				}...)
				expDirectGrants[directGrantProj2a.PublicId] = append(expDirectGrants[directGrantProj2a.PublicId], []perms.AclGrant{
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantProj2a.PublicId,
						Id:                "*",
						Type:              r,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantProj2a.PublicId,
						Id:                "*",
						Type:              r,
						ActionSet:         perms.ActionSet{action.List: true, action.Read: true},
					},
					{
						RoleScopeId:       directGrantProj2a.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeId:      directGrantProj2a.PublicId,
						Id:                "hcst_abcd1234",
						Type:              resource.Unknown,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantProj2a.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeId:      directGrantProj2a.PublicId,
						Id:                "hcst_1234abcd",
						Type:              resource.Unknown,
						ActionSet:         perms.ActionSet{action.All: true},
					},
				}...)
				expDirectGrants[directGrantProj2b.PublicId] = append(expDirectGrants[directGrantProj2b.PublicId], []perms.AclGrant{
					{
						RoleScopeId:       directGrantProj2b.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeId:      directGrantProj2b.PublicId,
						Id:                "cs_abcd1234",
						Type:              resource.Unknown,
						ActionSet:         perms.ActionSet{action.Update: true, action.Read: true},
					},
				}...)

			// Project
			case slices.Equal(resourceAllowedIn, []scope.Type{scope.Project}):
				expDirectGrants[directGrantProj1a.PublicId] = append(expDirectGrants[directGrantProj1a.PublicId], []perms.AclGrant{
					{
						RoleScopeId:       directGrantProj1a.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeId:      directGrantProj1a.PublicId,
						Id:                "*",
						Type:              r,
						ActionSet:         perms.ActionSet{action.AddMembers: true, action.Read: true},
					},
				}...)
				expDirectGrants[directGrantProj1b.PublicId] = append(expDirectGrants[directGrantProj1b.PublicId], []perms.AclGrant{
					{
						RoleScopeId:       directGrantProj1b.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeId:      directGrantProj1b.PublicId,
						Id:                "*",
						Type:              r,
						ActionSet:         perms.ActionSet{action.List: true, action.Read: true},
					},
				}...)
				expDirectGrants[directGrantProj2a.PublicId] = append(expDirectGrants[directGrantProj2a.PublicId], []perms.AclGrant{
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantProj2a.PublicId,
						Id:                "*",
						Type:              r,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantProj2a.PublicId,
						Id:                "*",
						Type:              r,
						ActionSet:         perms.ActionSet{action.List: true, action.Read: true},
					},
					{
						RoleScopeId:       directGrantProj2a.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeId:      directGrantProj2a.PublicId,
						Id:                "hcst_abcd1234",
						Type:              resource.Unknown,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantProj2a.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeId:      directGrantProj2a.PublicId,
						Id:                "hcst_1234abcd",
						Type:              resource.Unknown,
						ActionSet:         perms.ActionSet{action.All: true},
					},
				}...)
				expDirectGrants[directGrantProj2b.PublicId] = append(expDirectGrants[directGrantProj2b.PublicId], []perms.AclGrant{
					{
						RoleScopeId:       directGrantProj2b.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeId:      directGrantProj2b.PublicId,
						Id:                "cs_abcd1234",
						Type:              resource.Unknown,
						ActionSet:         perms.ActionSet{action.Update: true, action.Read: true},
					},
				}...)
			}

			assert.Len(t, directGrants, len(expDirectGrants))
			for k, v := range directGrants {
				assert.ElementsMatch(t, v, expDirectGrants[k])
			}
		})
	})
}

// grantRoleAndAssociate link one or more grants to a role and associate the role with a principal (i.e. user, group, or managed group)
func grantRoleAndAssociate(t *testing.T, conn *db.DB, roleId string, roleAssociationFunc func(), grants ...string) {
	t.Helper()
	for _, grant := range grants {
		iam.TestRoleGrant(t, conn, roleId, grant)
	}
	roleAssociationFunc()
}
