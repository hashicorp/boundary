package iam_test

import (
	"context"
	"fmt"
	mathrand "math/rand"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
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
	roleCount := 30
	// probFactor acts as a mod value; increasing means less probability. 2 =
	// 50%, 5 = 20%, etc.
	probFactor := 4

	o, p := iam.TestScopes(
		t,
		iamRepo,
		iam.WithSkipAdminRoleCreation(true),
		iam.WithSkipDefaultRoleCreation(true),
	)

	// We're going to generate a bunch of users, groups, and managed groups.
	// These will be randomly assigned and we will record assignations.
	users := func() (ret []*iam.User) {
		ret = make([]*iam.User, 0, userCount)
		scopeId := scope.Global.String()
		if mathrand.Int()%2 == 0 {
			scopeId = o.GetPublicId()
		}
		for i := 0; i < userCount; i++ {
			ret = append(ret, iam.TestUser(t, iamRepo, scopeId, iam.WithName(fmt.Sprintf("testuser%d", i))))
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
			}
		}
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
			}
		}
	}

	// Now, fetch the set of grants. We're going to be testing this by looking
	// at the role IDs of the matching grant tuples.
	for _, user := range users {
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
