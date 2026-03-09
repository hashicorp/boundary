// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_testOrg(t *testing.T) {
	assert := assert.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	id := testId(t)

	org := testOrg(t, repo, id, id)
	assert.Equal(id, org.Name)
	assert.Equal(id, org.Description)
	assert.NotEmpty(org.PublicId)
}

func Test_testProj(t *testing.T) {
	assert := assert.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	id := testId(t)

	org := testOrg(t, repo, id, id)
	proj := testProject(t, repo, org.PublicId, WithName(id), WithDescription(id))
	assert.Equal(id, proj.Name)
	assert.Equal(id, proj.Description)
	assert.NotEmpty(proj.PublicId)
}

func Test_testId(t *testing.T) {
	assert := assert.New(t)
	id := testId(t)
	assert.NotEmpty(id)
}

func Test_testPublicId(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	id := testPublicId(t, "test")
	require.NotEmpty(id)
	assert.True(strings.HasPrefix(id, "test_"))
}

func Test_TestScopes(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, prj := TestScopes(t, repo)

	require.NotNil(org)
	assert.NotEmpty(org.GetPublicId())

	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())
}

func Test_TestRepo(t *testing.T) {
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)

	repo := TestRepo(t, conn, wrapper)
	require.NotNil(repo)

	repo = TestRepo(t, conn, wrapper)
	require.NotNil(repo)
}

func Test_TestUser(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)

	require.NotNil(org)
	assert.NotEmpty(org.GetPublicId())

	user := TestUser(t, repo, org.PublicId)
	require.NotNil(user)
	assert.NotEmpty(user.PublicId)
}

func Test_TestRole(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	id := testId(t)
	org, proj := TestScopes(t, repo)
	role := TestRole(t, conn, org.PublicId, WithDescription(id), WithName(id))
	require.NotNil(role)
	assert.Equal(id, role.Description)
	assert.Equal(id, role.Name)
	assert.NotEmpty(role.PublicId)

	projRole := TestRole(t, conn, proj.PublicId)
	require.NotNil(projRole)
	assert.NotEmpty(projRole.PublicId)
}

func Test_TestRoleGrant(t *testing.T) {
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	_, proj := TestScopes(t, repo)
	projRole := TestRole(t, conn, proj.PublicId)

	grant := TestRoleGrant(t, conn, projRole.PublicId, "type=*;actions=*;ids=*")
	require.NotNil(grant)
	require.Equal(projRole.PublicId, grant.RoleId)
	require.Equal("type=*;actions=*;ids=*", grant.RawGrant)
	require.Equal("ids=*;type=*;actions=*", grant.CanonicalGrant)
}

func Test_TestUserRole(t *testing.T) {
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	org2, proj2 := TestScopes(t, repo)

	orgRole := TestRole(t, conn, org.PublicId)
	projRole := TestRole(t, conn, proj.PublicId)
	org2Role := TestRole(t, conn, org2.PublicId)
	proj2Role := TestRole(t, conn, proj2.PublicId)
	user := TestUser(t, repo, org.PublicId)

	userRole := TestUserRole(t, conn, orgRole.PublicId, user.PublicId)
	require.NotNil(userRole)
	require.Equal(orgRole.PublicId, userRole.RoleId)
	require.Equal(user.PublicId, userRole.PrincipalId)

	userRole = TestUserRole(t, conn, projRole.PublicId, user.PublicId)
	require.NotNil(userRole)
	require.Equal(projRole.PublicId, userRole.RoleId)
	require.Equal(user.PublicId, userRole.PrincipalId)

	userRole = TestUserRole(t, conn, org2Role.PublicId, user.PublicId)
	require.NotNil(userRole)
	require.Equal(org2Role.PublicId, userRole.RoleId)
	require.Equal(user.PublicId, userRole.PrincipalId)

	userRole = TestUserRole(t, conn, proj2Role.PublicId, user.PublicId)
	require.NotNil(userRole)
	require.Equal(proj2Role.PublicId, userRole.RoleId)
	require.Equal(user.PublicId, userRole.PrincipalId)
}

func Test_TestGroupRole(t *testing.T) {
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	org2, proj2 := TestScopes(t, repo)

	orgRole := TestRole(t, conn, org.PublicId)
	orgGroup := TestGroup(t, conn, org.PublicId)
	org2Group := TestGroup(t, conn, org2.PublicId)

	projRole := TestRole(t, conn, proj.PublicId)
	projGroup := TestGroup(t, conn, proj.PublicId)
	proj2Group := TestGroup(t, conn, proj2.PublicId)

	groupRole := TestGroupRole(t, conn, orgRole.PublicId, orgGroup.PublicId)
	require.NotNil(groupRole)
	require.Equal(orgRole.PublicId, groupRole.RoleId)
	require.Equal(orgGroup.PublicId, groupRole.PrincipalId)

	groupRole = TestGroupRole(t, conn, projRole.PublicId, projGroup.PublicId)
	require.NotNil(groupRole)
	require.Equal(projRole.PublicId, groupRole.RoleId)
	require.Equal(projGroup.PublicId, groupRole.PrincipalId)

	groupRole = TestGroupRole(t, conn, orgRole.PublicId, org2Group.PublicId)
	require.NotNil(groupRole)
	require.Equal(orgRole.PublicId, groupRole.RoleId)
	require.Equal(org2Group.PublicId, groupRole.PrincipalId)

	groupRole = TestGroupRole(t, conn, projRole.PublicId, proj2Group.PublicId)
	require.NotNil(groupRole)
	require.Equal(projRole.PublicId, groupRole.RoleId)
	require.Equal(proj2Group.PublicId, groupRole.PrincipalId)
}

func Test_TestGroupMember(t *testing.T) {
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	og := TestGroup(t, conn, org.PublicId)
	pg := TestGroup(t, conn, proj.PublicId)
	u := TestUser(t, repo, org.PublicId)

	gm := TestGroupMember(t, conn, og.PublicId, u.PublicId)
	require.NotNil(gm)
	require.Equal(og.PublicId, gm.GroupId)
	require.Equal(u.PublicId, gm.MemberId)

	gm = TestGroupMember(t, conn, pg.PublicId, u.PublicId)
	require.NotNil(gm)
	require.Equal(pg.PublicId, gm.GroupId)
	require.Equal(u.PublicId, gm.MemberId)
}

func Test_testAccount(t *testing.T) {
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)
	authMethodId := testAuthMethod(t, conn, org.PublicId)
	acct := testAccount(t, conn, org.PublicId, authMethodId, "")
	require.Equal(acct.ScopeId, org.PublicId)
}
