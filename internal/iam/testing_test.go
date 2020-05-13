package iam

import (
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
)

func Test_TestScopes(t *testing.T) {
	assert := assert.New(t)

	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	defer conn.Close()

	org, prj := TestScopes(t, conn)

	assert.NotNil(org)
	assert.NotEmpty(org.GetPublicId())
	assert.Equal(org.GetName(), "test-org")

	assert.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())
	assert.Equal(prj.GetName(), "test-project")
}
