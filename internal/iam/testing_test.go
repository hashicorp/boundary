package iam

import (
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
)

func Test_TestScopes(t *testing.T) {
	t.Helper()
	assert := assert.New(t)

	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	defer conn.Close()

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
	defer cleanup()
	defer conn.Close()

	org, _ := TestScopes(t, conn)

	assert.NotNil(org)
	assert.NotEmpty(org.GetPublicId())

	user := TestUser(t, conn, org.PublicId)
	assert.NotNil(user)
	assert.NotEmpty(user.PublicId)
}
