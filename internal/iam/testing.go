package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

// TestScopes creates an organization and project suitable for testing.
func TestScopes(t *testing.T, conn *gorm.DB) (org *Scope, prj *Scope) {
	t.Helper()
	assert := assert.New(t)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	assert.NoError(err)

	org, err = NewOrganization()
	org, err = repo.CreateScope(context.Background(), org)
	assert.NoError(err)
	assert.NotNil(org)
	assert.NotEmpty(org.GetPublicId())

	prj, err = NewProject(org.GetPublicId())
	prj, err = repo.CreateScope(context.Background(), prj)
	assert.NoError(err)
	assert.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	return
}
