package iam

import (
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
)

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
