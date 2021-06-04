package iam_test

import (
	"context"
	mathrand "math/rand"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGrantsForUser(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	// conn.LogMode(true)
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)

	userCount := 1
	groupCount := 1
	roleCount := 1
	// probFactor acts as a mod value; increasing means less probability. 2 =
	// 50%, 5 = 20%, etc.
	probFactor := 1

	/*
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
	*/

	// We're going to generate a bunch of users, groups, and managed groups.
	// These will be randomly assigned and we will record assignations.
	scopeId := "global"
	// scopeId := o.GetPublicId()
	users := func() (ret []*iam.User) {
		ret = make([]*iam.User, 0, userCount)
		for i := 0; i < userCount; i++ {
			ret = append(ret, iam.TestUser(t, iamRepo, scopeId))
		}
		return
	}()
	groups := func() (ret []*iam.Group) {
		ret = make([]*iam.Group, 0, groupCount)
		// scopeId := o.GetPublicId()
		if mathrand.Int()%2 == 0 {
			// scopeId = p.GetPublicId()
		}
		for i := 0; i < groupCount; i++ {
			ret = append(ret, iam.TestGroup(t, conn, scopeId))
		}
		return
	}()
	roles := func() (ret []*iam.Role) {
		ret = make([]*iam.Role, 0, roleCount)
		// scopeId := o.GetPublicId()
		if mathrand.Int()%2 == 0 {
			// scopeId = p.GetPublicId()
		}
		for i := 0; i < roleCount; i++ {
			role := iam.TestRole(t, conn, scopeId)
			t.Log("created role", role.PublicId)
			ret = append(ret, role)
		}
		return
	}()
	/*
		managedGroups := func() (ret []*oidc.ManagedGroup) {
			ret = make([]*oidc.ManagedGroup, 0, 30)
			for i := 0; i < 30; i++ {
				ret = append(ret, oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter))
			}
			return
		}()
	*/

	// This variable stores an easy way to lookup, given a group ID, whether a
	// user is in that group.
	userToGroupsMapping := map[string]map[string]bool{}
	for _, user := range users {
		for _, group := range groups {
			// Give each user about a chance of being in any specific
			// group
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
				t.Log("added user to group", userId, groupId)
			}
		}
	}

	// Now, we're going to randomly assign users and groups to roles and also
	// store mappings
	userToRolesMapping := map[string]map[string]bool{}
	groupToRolesMapping := map[string]map[string]bool{}
	for _, role := range roles {
		for _, user := range users {
			// Give each user about a chance of being directly added to
			// any specific role
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
				t.Log("added user to role", userId, roleId)
			}
		}
		rs, err := iamRepo.ListPrincipalRoles(ctx, role.PublicId)
		require.NoError(t, err)
		t.Log("roles for user", rs)
	}
	for _, role := range roles {
		for _, group := range groups {
			// Give each group about a chance of being directly added to
			// any specific role
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
				t.Log("added group to role", groupId, roleId)
			}
		}
		rs, err := iamRepo.ListPrincipalRoles(ctx, role.PublicId)
		require.NoError(t, err)
		t.Log("roles for group", rs)
	}

	// Now, fetch the set of grants. We're going to be testing this by looking
	// at the role IDs of the matching grant tuples.
	for _, user := range users {
		tuples, err := iamRepo.GrantsForUser(ctx, user.PublicId)
		require.NoError(t, err)

		// De-dupe role IDs
		roleIds := make(map[string]bool, len(tuples))
		for _, tuple := range tuples {
			// roleIds[tuple.RoleId] = true
			roleIds[tuple.ScopeId] = true
		}

		// Now, using the previous maps, figure out which roles we _expect_ to
		// see returned. This is the set of roles with directly added users,
		// plus the set of roles where we added the user as a group member and
		// that group to a role.
		expectedRoleIds := make(map[string]bool, len(tuples))
		for roleId := range userToRolesMapping[user.PublicId] {
			expectedRoleIds[roleId] = true
		}
		for groupId := range userToGroupsMapping[user.PublicId] {
			for roleId := range groupToRolesMapping[groupId] {
				expectedRoleIds[roleId] = true
			}
		}

		// Now verify that the expected set and returned set match
		assert.EqualValues(t, expectedRoleIds, roleIds)
	}
}
