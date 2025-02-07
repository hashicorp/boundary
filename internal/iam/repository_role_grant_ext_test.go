// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package iam_test

import (
	"context"
	"encoding/json"
	"fmt"
	mathrand "math/rand"
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

func TestGrantsForUser_DirectAssociation(t *testing.T) {
	ctx := context.Background()

	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)

	repo := iam.TestRepo(t, conn, wrap)
	user := iam.TestUser(t, repo, "global")
	user2 := iam.TestUser(t, repo, "global")

	// Create a series of scopes with roles in each. We'll create two of each
	// kind to ensure we're not just picking up the first role in each.

	// The first org/project set contains direct grants, but without
	// inheritance. We create two roles in each project.
	directGrantOrg1, directGrantProj1a, directGrantProj1b := iam.SetupDirectGrantScopes(t, conn, repo)

	// user
	directGrantOrg1Role := iam.TestRole(t, conn, directGrantOrg1.PublicId)
	iam.TestUserRole(t, conn, directGrantOrg1Role.PublicId, user.PublicId)
	directGrantOrg1RoleGrant1 := "ids=*;type=group;actions=*"
	iam.TestRoleGrant(t, conn, directGrantOrg1Role.PublicId, directGrantOrg1RoleGrant1)
	directGrantOrg1RoleGrant2 := "ids=*;type=group;actions=create,list"
	iam.TestRoleGrant(t, conn, directGrantOrg1Role.PublicId, directGrantOrg1RoleGrant2)
	// user2
	directGrantOrg1Role2 := iam.TestRole(t, conn, directGrantOrg1.PublicId)
	iam.TestUserRole(t, conn, directGrantOrg1Role2.PublicId, user2.PublicId)
	directGrantOrg1RoleGrant3 := "ids=*;type=group;actions=update"
	iam.TestRoleGrant(t, conn, directGrantOrg1Role2.PublicId, directGrantOrg1RoleGrant3)

	// user
	directGrantProj1aRole := iam.TestRole(t, conn, directGrantProj1a.PublicId)
	iam.TestUserRole(t, conn, directGrantProj1aRole.PublicId, user.PublicId)
	directGrantProj1aRoleGrant := "ids=*;type=group;actions=add-members,read"
	iam.TestRoleGrant(t, conn, directGrantProj1aRole.PublicId, directGrantProj1aRoleGrant)
	directGrantProj1bRole := iam.TestRole(t, conn, directGrantProj1b.PublicId)
	iam.TestUserRole(t, conn, directGrantProj1bRole.PublicId, user.PublicId)
	directGrantProj1bRoleGrant := "ids=*;type=group;actions=list,read"
	iam.TestRoleGrant(t, conn, directGrantProj1bRole.PublicId, directGrantProj1bRoleGrant)
	// user2
	directGrantProj1aRole2 := iam.TestRole(t, conn, directGrantProj1a.PublicId)
	iam.TestUserRole(t, conn, directGrantProj1aRole2.PublicId, user2.PublicId)
	directGrantProj1aRoleGrant2 := "ids=*;type=group;actions=set-members"
	iam.TestRoleGrant(t, conn, directGrantProj1aRole2.PublicId, directGrantProj1aRoleGrant2)
	directGrantProj1bRole2 := iam.TestRole(t, conn, directGrantProj1b.PublicId)
	iam.TestUserRole(t, conn, directGrantProj1bRole2.PublicId, user2.PublicId)
	directGrantProj1bRoleGrant2 := "ids=*;type=group;actions=delete"
	iam.TestRoleGrant(t, conn, directGrantProj1bRole2.PublicId, directGrantProj1bRoleGrant2)

	directGrantOrg2, directGrantProj2a, directGrantProj2b := iam.SetupDirectGrantScopes(t, conn, repo)
	// user
	directGrantOrg2Role := iam.TestRole(t, conn, directGrantOrg2.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeThis,
			directGrantProj2a.PublicId,
		}))
	iam.TestUserRole(t, conn, directGrantOrg2Role.PublicId, user.PublicId)
	directGrantOrg2RoleGrant1 := "ids=*;type=group;actions=*"
	iam.TestRoleGrant(t, conn, directGrantOrg2Role.PublicId, directGrantOrg2RoleGrant1)
	directGrantOrg2RoleGrant2 := "ids=*;type=group;actions=list,read"
	iam.TestRoleGrant(t, conn, directGrantOrg2Role.PublicId, directGrantOrg2RoleGrant2)

	directGrantProj2aRole := iam.TestRole(t, conn, directGrantProj2a.PublicId)
	iam.TestUserRole(t, conn, directGrantProj2aRole.PublicId, user.PublicId)
	directGrantProj2aRoleGrant := "ids=hcst_abcd1234,hcst_1234abcd;actions=*"
	iam.TestRoleGrant(t, conn, directGrantProj2aRole.PublicId, directGrantProj2aRoleGrant)
	directGrantProj2bRole := iam.TestRole(t, conn, directGrantProj2b.PublicId)
	iam.TestUserRole(t, conn, directGrantProj2bRole.PublicId, user.PublicId)
	directGrantProj2bRoleGrant := "ids=cs_abcd1234;actions=read,update"
	iam.TestRoleGrant(t, conn, directGrantProj2bRole.PublicId, directGrantProj2bRoleGrant)

	// user2
	directGrantOrg2Role2 := iam.TestRole(t, conn, directGrantOrg2.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeThis,
			directGrantProj2a.PublicId,
		}))
	iam.TestUserRole(t, conn, directGrantOrg2Role2.PublicId, user2.PublicId)
	directGrantOrg2RoleGrant3 := "ids=*;type=group;actions=add-members"
	iam.TestRoleGrant(t, conn, directGrantOrg2Role2.PublicId, directGrantOrg2RoleGrant3)

	directGrantProj2aRole2 := iam.TestRole(t, conn, directGrantProj2a.PublicId)
	iam.TestUserRole(t, conn, directGrantProj2aRole2.PublicId, user2.PublicId)
	directGrantProj2aRoleGrant2 := "ids=hcst_abcd1234,hcst_1234abcd;actions=*"
	iam.TestRoleGrant(t, conn, directGrantProj2aRole2.PublicId, directGrantProj2aRoleGrant2)
	directGrantProj2bRole2 := iam.TestRole(t, conn, directGrantProj2b.PublicId)
	iam.TestUserRole(t, conn, directGrantProj2bRole2.PublicId, user2.PublicId)
	directGrantProj2bRoleGrant2 := "ids=cs_abcd1234;actions=read,update"
	iam.TestRoleGrant(t, conn, directGrantProj2bRole2.PublicId, directGrantProj2bRoleGrant2)

	// For the second set we create a couple of orgs/projects and then use globals.GrantScopeChildren
	childGrantOrg1, _ := iam.SetupChildGrantScopes(t, conn, repo)

	// user
	childGrantOrg1Role := iam.TestRole(t, conn, childGrantOrg1.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	iam.TestUserRole(t, conn, childGrantOrg1Role.PublicId, user.PublicId)
	childGrantOrg1RoleGrant := "ids=*;type=group;actions=add-members,remove-members"
	iam.TestRoleGrant(t, conn, childGrantOrg1Role.PublicId, childGrantOrg1RoleGrant)
	// user2
	childGrantOrg1Role2 := iam.TestRole(t, conn, childGrantOrg1.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	iam.TestUserRole(t, conn, childGrantOrg1Role2.PublicId, user2.PublicId)
	childGrantOrg1RoleGrant2 := "ids=*;type=group;actions=read"
	iam.TestRoleGrant(t, conn, childGrantOrg1Role2.PublicId, childGrantOrg1RoleGrant2)

	childGrantOrg2, _ := iam.SetupChildGrantScopes(t, conn, repo)
	// user
	childGrantOrg2Role := iam.TestRole(t, conn, childGrantOrg2.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	iam.TestUserRole(t, conn, childGrantOrg2Role.PublicId, user.PublicId)
	childGrantOrg2RoleGrant1 := "ids=*;type=group;actions=set-members"
	iam.TestRoleGrant(t, conn, childGrantOrg2Role.PublicId, childGrantOrg2RoleGrant1)
	childGrantOrg2RoleGrant2 := "ids=*;type=group;actions=delete"
	iam.TestRoleGrant(t, conn, childGrantOrg2Role.PublicId, childGrantOrg2RoleGrant2)
	// user2
	childGrantOrg2Role2 := iam.TestRole(t, conn, childGrantOrg2.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	iam.TestUserRole(t, conn, childGrantOrg2Role2.PublicId, user2.PublicId)
	childGrantOrg2RoleGrant3 := "ids=*;type=group;actions=set-members"
	iam.TestRoleGrant(t, conn, childGrantOrg2Role2.PublicId, childGrantOrg2RoleGrant3)

	// Finally, let's create some roles at global scope with children and descendants grants

	// user
	childGrantGlobalRole := iam.TestRole(t, conn, scope.Global.String(),
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	iam.TestUserRole(t, conn, childGrantGlobalRole.PublicId, user.PublicId)
	childGrantGlobalRoleGrant := "ids=*;type=group;actions=*"
	iam.TestRoleGrant(t, conn, childGrantGlobalRole.PublicId, childGrantGlobalRoleGrant)
	// user2
	childGrantGlobalRole2 := iam.TestRole(t, conn, scope.Global.String(),
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	iam.TestUserRole(t, conn, childGrantGlobalRole2.PublicId, user2.PublicId)
	childGrantGlobalRoleGrant2 := "ids=*;type=group;actions=list"
	iam.TestRoleGrant(t, conn, childGrantGlobalRole2.PublicId, childGrantGlobalRoleGrant2)
	// user
	descendantGrantGlobalRole := iam.TestRole(t, conn, scope.Global.String(),
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeDescendants,
		}))
	iam.TestUserRole(t, conn, descendantGrantGlobalRole.PublicId, user.PublicId)
	descendantGrantGlobalRoleGrant := "ids=*;type=group;actions=*"
	iam.TestRoleGrant(t, conn, descendantGrantGlobalRole.PublicId, descendantGrantGlobalRoleGrant)
	// user2
	descendantGrantGlobalRole2 := iam.TestRole(t, conn, scope.Global.String(),
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeDescendants,
		}))
	iam.TestUserRole(t, conn, descendantGrantGlobalRole2.PublicId, user2.PublicId)
	descendantGrantGlobalRoleGrant2 := "ids=*;type=group;actions=add-members"
	iam.TestRoleGrant(t, conn, descendantGrantGlobalRole2.PublicId, descendantGrantGlobalRoleGrant2)

	t.Run("db-grants", func(t *testing.T) {
		// Here we should see exactly what the DB has returned, before we do some
		// local exploding of grants and grant scopes
		expMultiGrantTuples := map[string][]iam.MultiGrantTuple{
			user.PublicId: {
				// No grants from noOrg/noProj
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
			user2.PublicId: {
				// No grants from noOrg/noProj
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
		for userId, tuples := range expMultiGrantTuples {
			for i, tuple := range tuples {
				tuple.TestStableSort()
				expMultiGrantTuples[userId][i] = tuple
			}
			multiGrantTuplesCache := new([]iam.MultiGrantTuple)
			_, err := repo.GrantsForUser(ctx, userId, iam.WithTestCacheMultiGrantTuples(multiGrantTuplesCache))
			require.NoError(t, err)

			// log.Println("multiGrantTuplesCache", pretty.Sprint(*multiGrantTuplesCache))
			assert.ElementsMatch(t, *multiGrantTuplesCache, expMultiGrantTuples[userId])
		}
	})

	t.Run("exploded-grants", func(t *testing.T) {
		// We expect to see:
		//
		// * No grants from noOrg/noProj
		// * Grants from direct orgs/projs:
		//   * directGrantOrg1/directGrantOrg2 on org and respective projects (6 grants total per org)
		//   * directGrantProj on respective projects (4 grants total)
		expGrantTuples := []perms.GrantTuple{
			// No grants from noOrg/noProj
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

		multiGrantTuplesCache := new([]iam.MultiGrantTuple)
		grantTuples, err := repo.GrantsForUser(ctx, user.PublicId, iam.WithTestCacheMultiGrantTuples(multiGrantTuplesCache))
		require.NoError(t, err)
		assert.ElementsMatch(t, grantTuples, expGrantTuples)
	})

	t.Run("acl-grants", func(t *testing.T) {
		grantTuples, err := repo.GrantsForUser(ctx, user.PublicId)
		require.NoError(t, err)
		grants := make([]perms.Grant, 0, len(grantTuples))
		for _, gt := range grantTuples {
			grant, err := perms.Parse(ctx, gt)
			require.NoError(t, err)
			grants = append(grants, grant)
		}
		acl := perms.NewACL(grants...)

		t.Run("descendant-grants", func(t *testing.T) {
			descendantGrants := acl.DescendantsGrants()
			expDescendantGrants := []perms.AclGrant{
				{
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: globals.GrantScopeDescendants,
					Id:           "*",
					Type:         resource.Group,
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
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.AddMembers: true, action.RemoveMembers: true},
					},
				},
				childGrantOrg2.PublicId: {
					{
						RoleScopeId:       childGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      globals.GrantScopeChildren,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.SetMembers: true},
					},
					{
						RoleScopeId:       childGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      globals.GrantScopeChildren,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.Delete: true},
					},
				},
				scope.Global.String(): {
					{
						RoleScopeId:  scope.Global.String(),
						GrantScopeId: globals.GrantScopeChildren,
						Id:           "*",
						Type:         resource.Group,
						ActionSet:    perms.ActionSet{action.All: true},
					},
				},
			}
			assert.Len(t, childrenGrants, len(expChildrenGrants))
			for k, v := range childrenGrants {
				assert.ElementsMatch(t, v, expChildrenGrants[k])
			}
		})

		t.Run("direct-grants", func(t *testing.T) {
			directGrants := acl.DirectScopeGrantMap()
			expDirectGrants := map[string][]perms.AclGrant{
				directGrantOrg1.PublicId: {
					{
						RoleScopeId:       directGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg1.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg1.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.Create: true, action.List: true},
					},
				},
				directGrantProj1a.PublicId: {
					{
						RoleScopeId:       directGrantProj1a.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeId:      directGrantProj1a.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.AddMembers: true, action.Read: true},
					},
				},
				directGrantProj1b.PublicId: {
					{
						RoleScopeId:       directGrantProj1b.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeId:      directGrantProj1b.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.List: true, action.Read: true},
					},
				},
				directGrantOrg2.PublicId: {
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg2.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg2.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.List: true, action.Read: true},
					},
				},
				directGrantProj2a.PublicId: {
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantProj2a.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantProj2a.PublicId,
						Id:                "*",
						Type:              resource.Group,
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
				},
				directGrantProj2b.PublicId: {
					{
						RoleScopeId:       directGrantProj2b.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeId:      directGrantProj2b.PublicId,
						Id:                "cs_abcd1234",
						Type:              resource.Unknown,
						ActionSet:         perms.ActionSet{action.Update: true, action.Read: true},
					},
				},
			}
			/*
				log.Println("org1", directGrantOrg1.PublicId)
				log.Println("proj1a", directGrantProj1a.PublicId)
				log.Println("proj1b", directGrantProj1b.PublicId)
				log.Println("org2", directGrantOrg2.PublicId)
				log.Println("proj2a", directGrantProj2a.PublicId)
				log.Println("proj2b", directGrantProj2b.PublicId)
			*/
			assert.Len(t, directGrants, len(expDirectGrants))
			for k, v := range directGrants {
				assert.ElementsMatch(t, v, expDirectGrants[k])
			}
		})
	})
}

func TestGrantsForUser_Group(t *testing.T) {
	ctx := context.Background()

	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)

	repo := iam.TestRepo(t, conn, wrap)
	user := iam.TestUser(t, repo, "global")
	user2 := iam.TestUser(t, repo, "global")
	group := iam.TestGroup(t, conn, "global")
	group2 := iam.TestGroup(t, conn, "global")
	iam.TestGroupMember(t, conn, group.PublicId, user.PublicId)
	iam.TestGroupMember(t, conn, group2.PublicId, user2.PublicId)

	// Create a series of scopes with roles in each. We'll create two of each
	// kind to ensure we're not just picking up the first role in each.

	// The first org/project set contains direct grants, but without
	// inheritance. We create two roles in each project.
	directGrantOrg1, directGrantProj1a, directGrantProj1b := iam.SetupDirectGrantScopes(t, conn, repo)

	// group
	directGrantOrg1Role := iam.TestRole(t, conn, directGrantOrg1.PublicId)
	iam.TestGroupRole(t, conn, directGrantOrg1Role.PublicId, group.PublicId)
	directGrantOrg1RoleGrant1 := "ids=*;type=group;actions=*"
	iam.TestRoleGrant(t, conn, directGrantOrg1Role.PublicId, directGrantOrg1RoleGrant1)
	directGrantOrg1RoleGrant2 := "ids=*;type=group;actions=create,list"
	iam.TestRoleGrant(t, conn, directGrantOrg1Role.PublicId, directGrantOrg1RoleGrant2)

	// group2
	directGrantOrg1Role2 := iam.TestRole(t, conn, directGrantOrg1.PublicId)
	iam.TestGroupRole(t, conn, directGrantOrg1Role2.PublicId, group2.PublicId)
	directGrantOrg1RoleGrant3 := "ids=*;type=group;actions=update"
	iam.TestRoleGrant(t, conn, directGrantOrg1Role2.PublicId, directGrantOrg1RoleGrant3)

	// group
	directGrantProj1aRole := iam.TestRole(t, conn, directGrantProj1a.PublicId)
	iam.TestGroupRole(t, conn, directGrantProj1aRole.PublicId, group.PublicId)
	directGrantProj1aRoleGrant := "ids=*;type=group;actions=add-members,read"
	iam.TestRoleGrant(t, conn, directGrantProj1aRole.PublicId, directGrantProj1aRoleGrant)
	directGrantProj1bRole := iam.TestRole(t, conn, directGrantProj1b.PublicId)
	iam.TestGroupRole(t, conn, directGrantProj1bRole.PublicId, group.PublicId)
	directGrantProj1bRoleGrant := "ids=*;type=group;actions=list,read"
	iam.TestRoleGrant(t, conn, directGrantProj1bRole.PublicId, directGrantProj1bRoleGrant)

	// group2
	directGrantProj1aRole2 := iam.TestRole(t, conn, directGrantProj1a.PublicId)
	iam.TestGroupRole(t, conn, directGrantProj1aRole2.PublicId, group2.PublicId)
	directGrantProj1aRoleGrant2 := "ids=*;type=group;actions=set-members"
	iam.TestRoleGrant(t, conn, directGrantProj1aRole2.PublicId, directGrantProj1aRoleGrant2)
	directGrantProj1bRole2 := iam.TestRole(t, conn, directGrantProj1b.PublicId)
	iam.TestGroupRole(t, conn, directGrantProj1bRole2.PublicId, group2.PublicId)
	directGrantProj1bRoleGrant2 := "ids=*;type=group;actions=delete"
	iam.TestRoleGrant(t, conn, directGrantProj1bRole2.PublicId, directGrantProj1bRoleGrant2)

	directGrantOrg2, directGrantProj2a, directGrantProj2b := iam.SetupDirectGrantScopes(t, conn, repo)

	// group
	directGrantOrg2Role := iam.TestRole(t, conn, directGrantOrg2.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeThis,
			directGrantProj2a.PublicId,
		}))
	iam.TestGroupRole(t, conn, directGrantOrg2Role.PublicId, group.PublicId)
	directGrantOrg2RoleGrant1 := "ids=*;type=group;actions=*"
	iam.TestRoleGrant(t, conn, directGrantOrg2Role.PublicId, directGrantOrg2RoleGrant1)
	directGrantOrg2RoleGrant2 := "ids=*;type=group;actions=list,read"
	iam.TestRoleGrant(t, conn, directGrantOrg2Role.PublicId, directGrantOrg2RoleGrant2)

	directGrantProj2aRole := iam.TestRole(t, conn, directGrantProj2a.PublicId)
	iam.TestGroupRole(t, conn, directGrantProj2aRole.PublicId, group.PublicId)
	directGrantProj2aRoleGrant := "ids=hcst_abcd1234,hcst_1234abcd;actions=*"
	iam.TestRoleGrant(t, conn, directGrantProj2aRole.PublicId, directGrantProj2aRoleGrant)
	directGrantProj2bRole := iam.TestRole(t, conn, directGrantProj2b.PublicId)
	iam.TestGroupRole(t, conn, directGrantProj2bRole.PublicId, group.PublicId)
	directGrantProj2bRoleGrant := "ids=cs_abcd1234;actions=read,update"
	iam.TestRoleGrant(t, conn, directGrantProj2bRole.PublicId, directGrantProj2bRoleGrant)

	// group2
	directGrantOrg2Role2 := iam.TestRole(t, conn, directGrantOrg2.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeThis,
			directGrantProj2a.PublicId,
		}))
	iam.TestGroupRole(t, conn, directGrantOrg2Role2.PublicId, group2.PublicId)
	directGrantOrg2RoleGrant3 := "ids=*;type=group;actions=add-members"
	iam.TestRoleGrant(t, conn, directGrantOrg2Role2.PublicId, directGrantOrg2RoleGrant3)

	directGrantProj2aRole2 := iam.TestRole(t, conn, directGrantProj2a.PublicId)
	iam.TestGroupRole(t, conn, directGrantProj2aRole2.PublicId, group2.PublicId)
	directGrantProj2aRoleGrant2 := "ids=hcst_abcd1234,hcst_1234abcd;actions=*"
	iam.TestRoleGrant(t, conn, directGrantProj2aRole2.PublicId, directGrantProj2aRoleGrant2)
	directGrantProj2bRole2 := iam.TestRole(t, conn, directGrantProj2b.PublicId)
	iam.TestGroupRole(t, conn, directGrantProj2bRole2.PublicId, group2.PublicId)
	directGrantProj2bRoleGrant2 := "ids=cs_abcd1234;actions=read,update"
	iam.TestRoleGrant(t, conn, directGrantProj2bRole2.PublicId, directGrantProj2bRoleGrant2)

	// For the second set we create a couple of orgs/projects and then use
	// globals.GrantScopeChildren.
	childGrantOrg1, _ := iam.SetupChildGrantScopes(t, conn, repo)

	// group
	childGrantOrg1Role := iam.TestRole(t, conn, childGrantOrg1.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	iam.TestGroupRole(t, conn, childGrantOrg1Role.PublicId, group.PublicId)
	childGrantOrg1RoleGrant := "ids=*;type=group;actions=add-members,remove-members"
	iam.TestRoleGrant(t, conn, childGrantOrg1Role.PublicId, childGrantOrg1RoleGrant)
	// group2
	childGrantOrg1Role2 := iam.TestRole(t, conn, childGrantOrg1.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	iam.TestGroupRole(t, conn, childGrantOrg1Role2.PublicId, group2.PublicId)
	childGrantOrg1RoleGrant2 := "ids=*;type=group;actions=read"
	iam.TestRoleGrant(t, conn, childGrantOrg1Role2.PublicId, childGrantOrg1RoleGrant2)

	childGrantOrg2, _ := iam.SetupChildGrantScopes(t, conn, repo)

	// group
	childGrantOrg2Role := iam.TestRole(t, conn, childGrantOrg2.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	iam.TestGroupRole(t, conn, childGrantOrg2Role.PublicId, group.PublicId)
	childGrantOrg2RoleGrant1 := "ids=*;type=group;actions=set-members"
	iam.TestRoleGrant(t, conn, childGrantOrg2Role.PublicId, childGrantOrg2RoleGrant1)
	childGrantOrg2RoleGrant2 := "ids=*;type=group;actions=delete"
	iam.TestRoleGrant(t, conn, childGrantOrg2Role.PublicId, childGrantOrg2RoleGrant2)

	// group2
	childGrantOrg2Role2 := iam.TestRole(t, conn, childGrantOrg2.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	iam.TestGroupRole(t, conn, childGrantOrg2Role2.PublicId, group2.PublicId)
	childGrantOrg2RoleGrant3 := "ids=*;type=group;actions=set-members"
	iam.TestRoleGrant(t, conn, childGrantOrg2Role2.PublicId, childGrantOrg2RoleGrant3)

	// Finally, let's create some roles at global scope with children and descendants grants

	// group
	childGrantGlobalRole := iam.TestRole(t, conn, scope.Global.String(),
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	iam.TestGroupRole(t, conn, childGrantGlobalRole.PublicId, group.PublicId)
	childGrantGlobalRoleGrant := "ids=*;type=group;actions=*"
	iam.TestRoleGrant(t, conn, childGrantGlobalRole.PublicId, childGrantGlobalRoleGrant)
	// group2
	childGrantGlobalRole2 := iam.TestRole(t, conn, scope.Global.String(),
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	iam.TestGroupRole(t, conn, childGrantGlobalRole2.PublicId, group2.PublicId)
	childGrantGlobalRoleGrant2 := "ids=*;type=group;actions=list"
	iam.TestRoleGrant(t, conn, childGrantGlobalRole2.PublicId, childGrantGlobalRoleGrant2)

	// group
	descendantGrantGlobalRole := iam.TestRole(t, conn, scope.Global.String(),
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeDescendants,
		}))
	iam.TestGroupRole(t, conn, descendantGrantGlobalRole.PublicId, group.PublicId)
	descendantGrantGlobalRoleGrant := "ids=*;type=group;actions=*"
	iam.TestRoleGrant(t, conn, descendantGrantGlobalRole.PublicId, descendantGrantGlobalRoleGrant)

	// group2
	descendantGrantGlobalRole2 := iam.TestRole(t, conn, scope.Global.String(),
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeDescendants,
		}))
	iam.TestGroupRole(t, conn, descendantGrantGlobalRole2.PublicId, group2.PublicId)
	descendantGrantGlobalRoleGrant2 := "ids=*;type=group;actions=add-members"
	iam.TestRoleGrant(t, conn, descendantGrantGlobalRole2.PublicId, descendantGrantGlobalRoleGrant2)

	t.Run("db-grants", func(t *testing.T) {
		// Here we should see exactly what the DB has returned, before we do some
		// local exploding of grants and grant scopes
		expMultiGrantTuples := map[string][]iam.MultiGrantTuple{
			user.PublicId: {
				// No grants from noOrg/noProj
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
			user2.PublicId: {
				// No grants from noOrg/noProj
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
		for userId, tuples := range expMultiGrantTuples {
			for i, tuple := range tuples {
				tuple.TestStableSort()
				expMultiGrantTuples[userId][i] = tuple
			}
			multiGrantTuplesCache := new([]iam.MultiGrantTuple)
			_, err := repo.GrantsForUser(ctx, userId, iam.WithTestCacheMultiGrantTuples(multiGrantTuplesCache))
			require.NoError(t, err)

			// log.Println("multiGrantTuplesCache", pretty.Sprint(*multiGrantTuplesCache))
			assert.ElementsMatch(t, *multiGrantTuplesCache, expMultiGrantTuples[userId])
		}
	})

	t.Run("exploded-grants", func(t *testing.T) {
		// We expect to see:
		//
		// * No grants from noOrg/noProj
		// * Grants from direct orgs/projs:
		//   * directGrantOrg1/directGrantOrg2 on org and respective projects (6 grants total per org)
		//   * directGrantProj on respective projects (4 grants total)
		expGrantTuples := []perms.GrantTuple{
			// No grants from noOrg/noProj
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

		multiGrantTuplesCache := new([]iam.MultiGrantTuple)
		grantTuples, err := repo.GrantsForUser(ctx, user.PublicId, iam.WithTestCacheMultiGrantTuples(multiGrantTuplesCache))
		require.NoError(t, err)
		assert.ElementsMatch(t, grantTuples, expGrantTuples)
	})

	t.Run("acl-grants", func(t *testing.T) {
		grantTuples, err := repo.GrantsForUser(ctx, user.PublicId)
		require.NoError(t, err)
		grants := make([]perms.Grant, 0, len(grantTuples))
		for _, gt := range grantTuples {
			grant, err := perms.Parse(ctx, gt)
			require.NoError(t, err)
			grants = append(grants, grant)
		}
		acl := perms.NewACL(grants...)

		t.Run("descendant-grants", func(t *testing.T) {
			descendantGrants := acl.DescendantsGrants()
			expDescendantGrants := []perms.AclGrant{
				{
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: globals.GrantScopeDescendants,
					Id:           "*",
					Type:         resource.Group,
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
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.AddMembers: true, action.RemoveMembers: true},
					},
				},
				childGrantOrg2.PublicId: {
					{
						RoleScopeId:       childGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      globals.GrantScopeChildren,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.SetMembers: true},
					},
					{
						RoleScopeId:       childGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      globals.GrantScopeChildren,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.Delete: true},
					},
				},
				scope.Global.String(): {
					{
						RoleScopeId:  scope.Global.String(),
						GrantScopeId: globals.GrantScopeChildren,
						Id:           "*",
						Type:         resource.Group,
						ActionSet:    perms.ActionSet{action.All: true},
					},
				},
			}
			assert.Len(t, childrenGrants, len(expChildrenGrants))
			for k, v := range childrenGrants {
				assert.ElementsMatch(t, v, expChildrenGrants[k])
			}
		})

		t.Run("direct-grants", func(t *testing.T) {
			directGrants := acl.DirectScopeGrantMap()
			expDirectGrants := map[string][]perms.AclGrant{
				directGrantOrg1.PublicId: {
					{
						RoleScopeId:       directGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg1.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg1.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.Create: true, action.List: true},
					},
				},
				directGrantProj1a.PublicId: {
					{
						RoleScopeId:       directGrantProj1a.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeId:      directGrantProj1a.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.AddMembers: true, action.Read: true},
					},
				},
				directGrantProj1b.PublicId: {
					{
						RoleScopeId:       directGrantProj1b.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeId:      directGrantProj1b.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.List: true, action.Read: true},
					},
				},
				directGrantOrg2.PublicId: {
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg2.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg2.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.List: true, action.Read: true},
					},
				},
				directGrantProj2a.PublicId: {
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantProj2a.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantProj2a.PublicId,
						Id:                "*",
						Type:              resource.Group,
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
				},
				directGrantProj2b.PublicId: {
					{
						RoleScopeId:       directGrantProj2b.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeId:      directGrantProj2b.PublicId,
						Id:                "cs_abcd1234",
						Type:              resource.Unknown,
						ActionSet:         perms.ActionSet{action.Update: true, action.Read: true},
					},
				},
			}
			/*
				log.Println("org1", directGrantOrg1.PublicId)
				log.Println("proj1a", directGrantProj1a.PublicId)
				log.Println("proj1b", directGrantProj1b.PublicId)
				log.Println("org2", directGrantOrg2.PublicId)
				log.Println("proj2a", directGrantProj2a.PublicId)
				log.Println("proj2b", directGrantProj2b.PublicId)
			*/
			assert.Len(t, directGrants, len(expDirectGrants))
			for k, v := range directGrants {
				assert.ElementsMatch(t, v, expDirectGrants[k])
			}
		})
	})
}

func TestGrantsForUser_ManagedGroup(t *testing.T) {
	ctx := context.Background()

	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)

	repo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)

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
		"alice-rp", "fido",
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	// oidcManagedGroup
	oidcAcct := oidc.TestAccount(t, conn, oidcAuthMethod, "sub")
	oidcManagedGroup := oidc.TestManagedGroup(t, conn, oidcAuthMethod, `"/token/sub" matches ".*"`)
	user := iam.TestUser(t, repo, "global", iam.WithAccountIds(oidcAcct.PublicId))
	oidc.TestManagedGroupMember(t, conn, oidcManagedGroup.GetPublicId(), oidcAcct.GetPublicId())

	// oidcManagedGroup2
	oidcAcct2 := oidc.TestAccount(t, conn, oidcAuthMethod, "sub no.2")
	oidcManagedGroup2 := oidc.TestManagedGroup(t, conn, oidcAuthMethod, `"/token/sub" matches ".*"`)
	user2 := iam.TestUser(t, repo, "global", iam.WithAccountIds(oidcAcct2.PublicId))
	oidc.TestManagedGroupMember(t, conn, oidcManagedGroup2.GetPublicId(), oidcAcct2.GetPublicId())

	// Create a series of scopes with roles in each. We'll create two of each
	// kind to ensure we're not just picking up the first role in each.

	// The first org/project set contains direct grants, but without
	// inheritance. We create two roles in each project.
	directGrantOrg1, directGrantProj1a, directGrantProj1b := iam.SetupDirectGrantScopes(t, conn, repo)

	// oidcManagedGroup
	directGrantOrg1Role := iam.TestRole(t, conn, directGrantOrg1.PublicId)
	iam.TestManagedGroupRole(t, conn, directGrantOrg1Role.PublicId, oidcManagedGroup.PublicId)
	directGrantOrg1RoleGrant1 := "ids=*;type=group;actions=*"
	iam.TestRoleGrant(t, conn, directGrantOrg1Role.PublicId, directGrantOrg1RoleGrant1)
	directGrantOrg1RoleGrant2 := "ids=*;type=group;actions=create,list"
	iam.TestRoleGrant(t, conn, directGrantOrg1Role.PublicId, directGrantOrg1RoleGrant2)

	// oidcManagedGroup2
	directGrantOrg1Role2 := iam.TestRole(t, conn, directGrantOrg1.PublicId)
	iam.TestManagedGroupRole(t, conn, directGrantOrg1Role2.PublicId, oidcManagedGroup2.PublicId)
	directGrantOrg1RoleGrant3 := "ids=*;type=group;actions=update"
	iam.TestRoleGrant(t, conn, directGrantOrg1Role2.PublicId, directGrantOrg1RoleGrant3)

	// oidcManagedGroup
	directGrantProj1aRole := iam.TestRole(t, conn, directGrantProj1a.PublicId)
	iam.TestManagedGroupRole(t, conn, directGrantProj1aRole.PublicId, oidcManagedGroup.PublicId)
	directGrantProj1aRoleGrant := "ids=*;type=group;actions=add-members,read"
	iam.TestRoleGrant(t, conn, directGrantProj1aRole.PublicId, directGrantProj1aRoleGrant)
	directGrantProj1bRole := iam.TestRole(t, conn, directGrantProj1b.PublicId)
	iam.TestManagedGroupRole(t, conn, directGrantProj1bRole.PublicId, oidcManagedGroup.PublicId)
	directGrantProj1bRoleGrant := "ids=*;type=group;actions=list,read"
	iam.TestRoleGrant(t, conn, directGrantProj1bRole.PublicId, directGrantProj1bRoleGrant)

	// oidcManagedGroup2
	directGrantProj1aRole2 := iam.TestRole(t, conn, directGrantProj1a.PublicId)
	iam.TestManagedGroupRole(t, conn, directGrantProj1aRole2.PublicId, oidcManagedGroup2.PublicId)
	directGrantProj1aRoleGrant2 := "ids=*;type=group;actions=set-members"
	iam.TestRoleGrant(t, conn, directGrantProj1aRole2.PublicId, directGrantProj1aRoleGrant2)
	directGrantProj1bRole2 := iam.TestRole(t, conn, directGrantProj1b.PublicId)
	iam.TestManagedGroupRole(t, conn, directGrantProj1bRole2.PublicId, oidcManagedGroup2.PublicId)
	directGrantProj1bRoleGrant2 := "ids=*;type=group;actions=delete"
	iam.TestRoleGrant(t, conn, directGrantProj1bRole2.PublicId, directGrantProj1bRoleGrant2)

	directGrantOrg2, directGrantProj2a, directGrantProj2b := iam.SetupDirectGrantScopes(t, conn, repo)

	// oidcManagedGroup
	directGrantOrg2Role := iam.TestRole(t, conn, directGrantOrg2.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeThis,
			directGrantProj2a.PublicId,
		}))
	iam.TestManagedGroupRole(t, conn, directGrantOrg2Role.PublicId, oidcManagedGroup.PublicId)
	directGrantOrg2RoleGrant1 := "ids=*;type=group;actions=*"
	iam.TestRoleGrant(t, conn, directGrantOrg2Role.PublicId, directGrantOrg2RoleGrant1)
	directGrantOrg2RoleGrant2 := "ids=*;type=group;actions=list,read"
	iam.TestRoleGrant(t, conn, directGrantOrg2Role.PublicId, directGrantOrg2RoleGrant2)

	directGrantProj2aRole := iam.TestRole(t, conn, directGrantProj2a.PublicId)
	iam.TestManagedGroupRole(t, conn, directGrantProj2aRole.PublicId, oidcManagedGroup.PublicId)
	directGrantProj2aRoleGrant := "ids=hcst_abcd1234,hcst_1234abcd;actions=*"
	iam.TestRoleGrant(t, conn, directGrantProj2aRole.PublicId, directGrantProj2aRoleGrant)
	directGrantProj2bRole := iam.TestRole(t, conn, directGrantProj2b.PublicId)
	iam.TestManagedGroupRole(t, conn, directGrantProj2bRole.PublicId, oidcManagedGroup.PublicId)
	directGrantProj2bRoleGrant := "ids=cs_abcd1234;actions=read,update"
	iam.TestRoleGrant(t, conn, directGrantProj2bRole.PublicId, directGrantProj2bRoleGrant)

	// oidcManagedGroup2
	directGrantOrg2Role2 := iam.TestRole(t, conn, directGrantOrg2.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeThis,
			directGrantProj2a.PublicId,
		}))
	iam.TestManagedGroupRole(t, conn, directGrantOrg2Role2.PublicId, oidcManagedGroup2.PublicId)
	directGrantOrg2RoleGrant3 := "ids=*;type=group;actions=add-members"
	iam.TestRoleGrant(t, conn, directGrantOrg2Role2.PublicId, directGrantOrg2RoleGrant3)

	directGrantProj2aRole2 := iam.TestRole(t, conn, directGrantProj2a.PublicId)
	iam.TestManagedGroupRole(t, conn, directGrantProj2aRole2.PublicId, oidcManagedGroup2.PublicId)
	directGrantProj2aRoleGrant2 := "ids=hcst_abcd1234,hcst_1234abcd;actions=*"
	iam.TestRoleGrant(t, conn, directGrantProj2aRole2.PublicId, directGrantProj2aRoleGrant2)
	directGrantProj2bRole2 := iam.TestRole(t, conn, directGrantProj2b.PublicId)
	iam.TestManagedGroupRole(t, conn, directGrantProj2bRole2.PublicId, oidcManagedGroup2.PublicId)
	directGrantProj2bRoleGrant2 := "ids=cs_abcd1234;actions=read,update"
	iam.TestRoleGrant(t, conn, directGrantProj2bRole2.PublicId, directGrantProj2bRoleGrant2)

	// For the second set we create a couple of orgs/projects and then use
	// globals.GrantScopeChildren.
	childGrantOrg1, _ := iam.SetupChildGrantScopes(t, conn, repo)

	// oidcManagedGroup
	childGrantOrg1Role := iam.TestRole(t, conn, childGrantOrg1.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	iam.TestManagedGroupRole(t, conn, childGrantOrg1Role.PublicId, oidcManagedGroup.PublicId)
	childGrantOrg1RoleGrant := "ids=*;type=group;actions=add-members,remove-members"
	iam.TestRoleGrant(t, conn, childGrantOrg1Role.PublicId, childGrantOrg1RoleGrant)
	// oidcManagedGroup2
	childGrantOrg1Role2 := iam.TestRole(t, conn, childGrantOrg1.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	iam.TestManagedGroupRole(t, conn, childGrantOrg1Role2.PublicId, oidcManagedGroup2.PublicId)
	childGrantOrg1RoleGrant2 := "ids=*;type=group;actions=read"
	iam.TestRoleGrant(t, conn, childGrantOrg1Role2.PublicId, childGrantOrg1RoleGrant2)

	childGrantOrg2, _ := iam.SetupChildGrantScopes(t, conn, repo)

	// oidcManagedGroup
	childGrantOrg2Role := iam.TestRole(t, conn, childGrantOrg2.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	iam.TestManagedGroupRole(t, conn, childGrantOrg2Role.PublicId, oidcManagedGroup.PublicId)
	childGrantOrg2RoleGrant1 := "ids=*;type=group;actions=set-members"
	iam.TestRoleGrant(t, conn, childGrantOrg2Role.PublicId, childGrantOrg2RoleGrant1)
	childGrantOrg2RoleGrant2 := "ids=*;type=group;actions=delete"
	iam.TestRoleGrant(t, conn, childGrantOrg2Role.PublicId, childGrantOrg2RoleGrant2)

	// oidcManagedGroup2
	childGrantOrg2Role2 := iam.TestRole(t, conn, childGrantOrg2.PublicId,
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	iam.TestManagedGroupRole(t, conn, childGrantOrg2Role2.PublicId, oidcManagedGroup2.PublicId)
	childGrantOrg2RoleGrant3 := "ids=*;type=group;actions=set-members"
	iam.TestRoleGrant(t, conn, childGrantOrg2Role2.PublicId, childGrantOrg2RoleGrant3)

	// Finally, let's create some roles at global scope with children and descendants grants

	// oidcManagedGroup
	childGrantGlobalRole := iam.TestRole(t, conn, scope.Global.String(),
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	iam.TestManagedGroupRole(t, conn, childGrantGlobalRole.PublicId, oidcManagedGroup.PublicId)
	childGrantGlobalRoleGrant := "ids=*;type=group;actions=*"
	iam.TestRoleGrant(t, conn, childGrantGlobalRole.PublicId, childGrantGlobalRoleGrant)
	// oidcManagedGroup2
	childGrantGlobalRole2 := iam.TestRole(t, conn, scope.Global.String(),
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	iam.TestManagedGroupRole(t, conn, childGrantGlobalRole2.PublicId, oidcManagedGroup2.PublicId)
	childGrantGlobalRoleGrant2 := "ids=*;type=group;actions=list"
	iam.TestRoleGrant(t, conn, childGrantGlobalRole2.PublicId, childGrantGlobalRoleGrant2)

	// oidcManagedGroup
	descendantGrantGlobalRole := iam.TestRole(t, conn, scope.Global.String(),
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeDescendants,
		}))
	iam.TestManagedGroupRole(t, conn, descendantGrantGlobalRole.PublicId, oidcManagedGroup.PublicId)
	descendantGrantGlobalRoleGrant := "ids=*;type=group;actions=*"
	iam.TestRoleGrant(t, conn, descendantGrantGlobalRole.PublicId, descendantGrantGlobalRoleGrant)

	// oidcManagedGroup2
	descendantGrantGlobalRole2 := iam.TestRole(t, conn, scope.Global.String(),
		iam.WithGrantScopeIds([]string{
			globals.GrantScopeDescendants,
		}))
	iam.TestManagedGroupRole(t, conn, descendantGrantGlobalRole2.PublicId, oidcManagedGroup2.PublicId)
	descendantGrantGlobalRoleGrant2 := "ids=*;type=group;actions=add-members"
	iam.TestRoleGrant(t, conn, descendantGrantGlobalRole2.PublicId, descendantGrantGlobalRoleGrant2)
	t.Run("db-grants", func(t *testing.T) {
		// Here we should see exactly what the DB has returned, before we do some
		// local exploding of grants and grant scopes
		expMultiGrantTuples := map[string][]iam.MultiGrantTuple{
			user.PublicId: {
				// No grants from noOrg/noProj
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
			user2.PublicId: {
				// No grants from noOrg/noProj
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
		for userId, tuples := range expMultiGrantTuples {
			for i, tuple := range tuples {
				tuple.TestStableSort()
				expMultiGrantTuples[userId][i] = tuple
			}
			multiGrantTuplesCache := new([]iam.MultiGrantTuple)
			_, err := repo.GrantsForUser(ctx, userId, iam.WithTestCacheMultiGrantTuples(multiGrantTuplesCache))
			require.NoError(t, err)

			// log.Println("multiGrantTuplesCache", pretty.Sprint(*multiGrantTuplesCache))
			assert.ElementsMatch(t, *multiGrantTuplesCache, expMultiGrantTuples[userId])
		}
	})

	t.Run("exploded-grants", func(t *testing.T) {
		// We expect to see:
		//
		// * No grants from noOrg/noProj
		// * Grants from direct orgs/projs:
		//   * directGrantOrg1/directGrantOrg2 on org and respective projects (6 grants total per org)
		//   * directGrantProj on respective projects (4 grants total)
		expGrantTuples := []perms.GrantTuple{
			// No grants from noOrg/noProj
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

		multiGrantTuplesCache := new([]iam.MultiGrantTuple)
		grantTuples, err := repo.GrantsForUser(ctx, user.PublicId, iam.WithTestCacheMultiGrantTuples(multiGrantTuplesCache))
		require.NoError(t, err)
		assert.ElementsMatch(t, grantTuples, expGrantTuples)
	})

	t.Run("acl-grants", func(t *testing.T) {
		grantTuples, err := repo.GrantsForUser(ctx, user.PublicId)
		require.NoError(t, err)
		grants := make([]perms.Grant, 0, len(grantTuples))
		for _, gt := range grantTuples {
			grant, err := perms.Parse(ctx, gt)
			require.NoError(t, err)
			grants = append(grants, grant)
		}
		acl := perms.NewACL(grants...)

		t.Run("descendant-grants", func(t *testing.T) {
			descendantGrants := acl.DescendantsGrants()
			expDescendantGrants := []perms.AclGrant{
				{
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: globals.GrantScopeDescendants,
					Id:           "*",
					Type:         resource.Group,
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
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.AddMembers: true, action.RemoveMembers: true},
					},
				},
				childGrantOrg2.PublicId: {
					{
						RoleScopeId:       childGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      globals.GrantScopeChildren,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.SetMembers: true},
					},
					{
						RoleScopeId:       childGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      globals.GrantScopeChildren,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.Delete: true},
					},
				},
				scope.Global.String(): {
					{
						RoleScopeId:  scope.Global.String(),
						GrantScopeId: globals.GrantScopeChildren,
						Id:           "*",
						Type:         resource.Group,
						ActionSet:    perms.ActionSet{action.All: true},
					},
				},
			}
			assert.Len(t, childrenGrants, len(expChildrenGrants))
			for k, v := range childrenGrants {
				assert.ElementsMatch(t, v, expChildrenGrants[k])
			}
		})

		t.Run("direct-grants", func(t *testing.T) {
			directGrants := acl.DirectScopeGrantMap()
			expDirectGrants := map[string][]perms.AclGrant{
				directGrantOrg1.PublicId: {
					{
						RoleScopeId:       directGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg1.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg1.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.Create: true, action.List: true},
					},
				},
				directGrantProj1a.PublicId: {
					{
						RoleScopeId:       directGrantProj1a.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeId:      directGrantProj1a.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.AddMembers: true, action.Read: true},
					},
				},
				directGrantProj1b.PublicId: {
					{
						RoleScopeId:       directGrantProj1b.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeId:      directGrantProj1b.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.List: true, action.Read: true},
					},
				},
				directGrantOrg2.PublicId: {
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg2.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg2.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.List: true, action.Read: true},
					},
				},
				directGrantProj2a.PublicId: {
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantProj2a.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantProj2a.PublicId,
						Id:                "*",
						Type:              resource.Group,
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
				},
				directGrantProj2b.PublicId: {
					{
						RoleScopeId:       directGrantProj2b.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeId:      directGrantProj2b.PublicId,
						Id:                "cs_abcd1234",
						Type:              resource.Unknown,
						ActionSet:         perms.ActionSet{action.Update: true, action.Read: true},
					},
				},
			}
			/*
				log.Println("org1", directGrantOrg1.PublicId)
				log.Println("proj1a", directGrantProj1a.PublicId)
				log.Println("proj1b", directGrantProj1b.PublicId)
				log.Println("org2", directGrantOrg2.PublicId)
				log.Println("proj2a", directGrantProj2a.PublicId)
				log.Println("proj2b", directGrantProj2b.PublicId)
			*/
			assert.Len(t, directGrants, len(expDirectGrants))
			for k, v := range directGrants {
				assert.ElementsMatch(t, v, expDirectGrants[k])
			}
		})
	})
}
