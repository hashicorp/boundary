// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package iam_test

import (
	"context"
	"fmt"
	mathrand "math/rand"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGrantsForUser(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)

	userCount := 10
	groupCount := 30
	managedGroupCount := 30
	roleCount := 30
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

	kmsCache := kms.TestKms(t, conn, wrap)
	databaseWrapper, err := kmsCache.GetWrapper(ctx, o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	authMethod := oidc.TestAuthMethod(
		t, conn, databaseWrapper, o.GetPublicId(), oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	// We're going to generate a bunch of users (each tied to an account),
	// groups, and managed groups. These will be randomly assigned and we will
	// record assignations.
	users, accounts := func() (usrs []*iam.User, accts []*oidc.Account) {
		usrs = make([]*iam.User, 0, userCount)
		accts = make([]*oidc.Account, 0, userCount)
		scopeId := scope.Global.String()
		if mathrand.Int()%2 == 0 || testManagedGroups {
			scopeId = o.GetPublicId()
		}
		for i := 0; i < userCount; i++ {
			accts = append(accts, oidc.TestAccount(t, conn, authMethod, fmt.Sprintf("sub-%d", i)))
			usrs = append(usrs, iam.TestUser(
				t,
				iamRepo,
				scopeId,
				iam.WithAccountIds(accts[i].PublicId),
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
	managedGroups := func() (ret []*oidc.ManagedGroup) {
		ret = make([]*oidc.ManagedGroup, 0, managedGroupCount)
		for i := 0; i < managedGroupCount; i++ {
			ret = append(ret, oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter, oidc.WithName(fmt.Sprintf("testmanagedgroup%d", i))))
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
			iam.TestRoleGrant(t, conn, role.PublicId, "id=*;type=*;actions=*")
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
	// This variable stores an easy way to lookup, given a managed group ID, whether a
	// user is in that group.
	userToManagedGroupsMapping := map[string]map[string]bool{}
	for i, user := range users {
		for _, managedGroup := range managedGroups {
			// Give each user (account) a chance of being in any specific managed group
			if mathrand.Int()%probFactor == 0 {
				userId := user.PublicId
				accountId := accounts[i].PublicId
				managedGroupId := managedGroup.PublicId
				oidc.TestManagedGroupMember(t, conn, managedGroupId, accountId)
				currentMapping := userToManagedGroupsMapping[userId]
				if currentMapping == nil {
					currentMapping = make(map[string]bool)
				}
				currentMapping[managedGroupId] = true
				userToManagedGroupsMapping[userId] = currentMapping
			}
		}
	}

	// Now, we're going to randomly assign users and groups to roles and also
	// store mappings
	userToRolesMapping := map[string]map[string]bool{}
	groupToRolesMapping := map[string]map[string]bool{}
	managedGroupToRolesMapping := map[string]map[string]bool{}
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
		for _, managedGroup := range managedGroups {
			// Give each managed group a chance of being directly added to any
			// specific role
			if mathrand.Int()%probFactor == 0 {
				roleId := role.PublicId
				managedGroupId := managedGroup.PublicId
				iam.TestManagedGroupRole(t, conn, roleId, managedGroupId)
				currentMapping := managedGroupToRolesMapping[managedGroupId]
				if currentMapping == nil {
					currentMapping = make(map[string]bool)
				}
				currentMapping[roleId] = true
				managedGroupToRolesMapping[managedGroupId] = currentMapping
			}
		}
	}

	// Now, fetch the set of grants. We're going to be testing this by looking
	// at the role IDs of the matching grant tuples.
	for _, user := range users {
		var rolesFromUsers, rolesFromGroups, rolesFromManagedGroups int

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
		for managedGroupId := range userToManagedGroupsMapping[user.PublicId] {
			for roleId := range managedGroupToRolesMapping[managedGroupId] {
				expectedRoleIds[roleId] = true
				rolesFromManagedGroups++
			}
		}

		// Now verify that the expected set and returned set match
		assert.EqualValues(t, expectedRoleIds, roleIds)

		t.Log("finished user", user.PublicId, "total roles", len(expectedRoleIds), "roles from users", rolesFromUsers, "roles from groups", rolesFromGroups, "roles from managed groups", rolesFromManagedGroups)
	}
}
