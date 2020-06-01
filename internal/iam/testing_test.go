package iam

import (
	"strings"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
)

func Test_testOrg(t *testing.T) {
	assert := assert.New(t)

	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(err)
	}()
	defer func() {
		err := conn.Close()
		assert.NoError(err)
	}()
	id := testId(t)

	org := testOrg(t, conn, id, id)
	assert.Equal(id, org.Name)
	assert.Equal(id, org.Description)
	assert.NotEmpty(org.PublicId)
}

func Test_testId(t *testing.T) {
	assert := assert.New(t)
	id := testId(t)
	assert.NotEmpty(id)
}

func Test_testPublicId(t *testing.T) {
	assert := assert.New(t)
	id := testPublicId(t, "test")
	assert.NotEmpty(id)
	assert.True(strings.HasPrefix(id, "test_"))
}
func Test_TestScopes(t *testing.T) {
	assert := assert.New(t)

	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()

	org, prj := TestScopes(t, conn)

	assert.NotNil(org)
	assert.NotEmpty(org.GetPublicId())

	assert.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())
}
func Test_TestUser(t *testing.T) {
	t.Helper()
	assert := assert.New(t)
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	defer conn.Close()

	org, _ := TestScopes(t, conn)

	assert.NotNil(org)
	assert.NotEmpty(org.GetPublicId())

	user := TestUser(t, conn, org.PublicId)
	assert.NotNil(user)
	assert.NotEmpty(user.PublicId)
}
