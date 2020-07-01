package iam

import (
	"strings"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_testOrg(t *testing.T) {
	assert := assert.New(t)

	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(err)
		err = conn.Close()
		assert.NoError(err)
	}()
	id := testId(t)

	org := testOrg(t, conn, id, id)
	assert.Equal(id, org.Name)
	assert.Equal(id, org.Description)
	assert.NotEmpty(org.PublicId)
}

func Test_testProj(t *testing.T) {
	assert := assert.New(t)

	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(err)
		err = conn.Close()
		assert.NoError(err)
	}()
	id := testId(t)

	org := testOrg(t, conn, id, id)
	proj := testProject(t, conn, org.PublicId, WithName(id), WithDescription(id))
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
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(err)
		err = conn.Close()
		assert.NoError(err)
	}()

	org, prj := TestScopes(t, conn)

	require.NotNil(org)
	assert.NotEmpty(org.GetPublicId())

	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())
}
func Test_TestUser(t *testing.T) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(err)
		err = conn.Close()
		assert.NoError(err)
	}()
	org, _ := TestScopes(t, conn)

	require.NotNil(org)
	assert.NotEmpty(org.GetPublicId())

	user := TestUser(t, conn, org.PublicId)
	require.NotNil(user)
	assert.NotEmpty(user.PublicId)
}

func Test_TestRole(t *testing.T) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(err)
		err = conn.Close()
		assert.NoError(err)
	}()
	id := testId(t)
	org, proj := TestScopes(t, conn)
	role := TestRole(t, conn, org.PublicId, WithDescription(id), WithName(id))
	require.NotNil(role)
	assert.Equal(id, role.Description)
	assert.Equal(id, role.Name)
	assert.NotEmpty(role.PublicId)

	projRole := TestRole(t, conn, proj.PublicId)
	require.NotNil(projRole)
	assert.NotEmpty(projRole.PublicId)
}

func Test_TestUserRole(t *testing.T) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(err)
		err = conn.Close()
		assert.NoError(err)
	}()
	org, proj := TestScopes(t, conn)
	orgRole := TestRole(t, conn, org.PublicId)
	projRole := TestRole(t, conn, proj.PublicId)
	user := TestUser(t, conn, org.PublicId)

	userRole := TestUserRole(t, conn, org.PublicId, orgRole.PublicId, user.PublicId)
	require.NotNil(userRole)
	require.Equal(orgRole.PublicId, userRole.RoleId)
	require.Equal(user.PublicId, userRole.PrincipalId)

	userRole = TestUserRole(t, conn, proj.PublicId, projRole.PublicId, user.PublicId)
	require.NotNil(userRole)
	require.Equal(projRole.PublicId, userRole.RoleId)
	require.Equal(user.PublicId, userRole.PrincipalId)
}

func Test_TestGroupRole(t *testing.T) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(err)
		err = conn.Close()
		assert.NoError(err)
	}()
	org, proj := TestScopes(t, conn)
	orgRole := TestRole(t, conn, org.PublicId)
	orgGroup := TestGroup(t, conn, org.PublicId)

	projRole := TestRole(t, conn, proj.PublicId)
	projGroup := TestGroup(t, conn, proj.PublicId)

	groupRole := TestGroupRole(t, conn, org.PublicId, orgRole.PublicId, orgGroup.PublicId)
	require.NotNil(groupRole)
	require.Equal(orgRole.PublicId, groupRole.RoleId)
	require.Equal(orgGroup.PublicId, groupRole.PrincipalId)

	groupRole = TestGroupRole(t, conn, proj.PublicId, projRole.PublicId, projGroup.PublicId)
	require.NotNil(groupRole)
	require.Equal(projRole.PublicId, groupRole.RoleId)
	require.Equal(projGroup.PublicId, groupRole.PrincipalId)
}
