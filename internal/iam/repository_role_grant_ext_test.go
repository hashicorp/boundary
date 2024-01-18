// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package iam_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	mathrand "math/rand"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/kr/pretty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestGrantsForUser(t *testing.T) {
	ctx := context.Background()
	conn, dbUrl := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	log.Println(dbUrl)

	iamRepo := iam.TestRepo(t, conn, wrap)
	user := iam.TestUser(t, iamRepo, "global")
	org1, proj1 := iam.TestScopes(
		t,
		iamRepo,
		iam.WithSkipAdminRoleCreation(true),
		iam.WithSkipDefaultRoleCreation(true),
	)
	org2, proj2 := iam.TestScopes(
		t,
		iamRepo,
		iam.WithSkipAdminRoleCreation(true),
		iam.WithSkipDefaultRoleCreation(true),
	)
	t.Log("org1", org1.GetPublicId(), "proj1", proj1.GetPublicId(), "org2", org2.GetPublicId(), "proj2", proj2.GetPublicId())
	org1Proj1Role := iam.TestRole(t, conn, org1.GetPublicId(), iam.WithGrantScopeId(proj1.PublicId))
	org2Proj2Role := iam.TestRole(t, conn, org2.GetPublicId(), iam.WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeChildren}))
	globalRole := iam.TestRole(t, conn, scope.Global.String(), iam.WithGrantScopeIds([]string{globals.GrantScopeDescendants}))
	iam.TestUserRole(t, conn, org1Proj1Role.PublicId, user.PublicId)
	iam.TestUserRole(t, conn, org2Proj2Role.PublicId, user.PublicId)
	iam.TestUserRole(t, conn, globalRole.PublicId, user.PublicId)
	iam.TestRoleGrant(t, conn, org1Proj1Role.PublicId, "id=*;type=*;actions=read")
	iam.TestRoleGrant(t, conn, org2Proj2Role.PublicId, "id=*;type=*;actions=create")
	iam.TestRoleGrant(t, conn, org2Proj2Role.PublicId, "id=*;type=*;actions=list,no-op")
	iam.TestRoleGrant(t, conn, globalRole.PublicId, "id=*;type=auth-method;actions=update")
	iam.TestRoleGrant(t, conn, globalRole.PublicId, "id=*;type=credential-store;actions=list,no-op")
	// time.Sleep(10000 * time.Second)
	grantTuples, err := iamRepo.GrantsForUser(ctx, user.PublicId)
	require.NoError(t, err)
	t.Log(pretty.Sprint(grantTuples))
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
