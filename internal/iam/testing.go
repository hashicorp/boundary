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
	assert.NoError(err)
	org, err = repo.CreateScope(context.Background(), org)
	assert.NoError(err)
	assert.NotNil(org)
	assert.NotEmpty(org.GetPublicId())

	prj, err = NewProject(org.GetPublicId())
	assert.NoError(err)
	prj, err = repo.CreateScope(context.Background(), prj)
	assert.NoError(err)
	assert.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	return
}

// TestUser creates a user suitable for testing.
func TestUser(t *testing.T, conn *gorm.DB, orgId string) *User {
	t.Helper()
	assert := assert.New(t)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	assert.NoError(err)

	user, err := NewUser(orgId)
	assert.NoError(err)
	user, err = repo.CreateUser(context.Background(), user)
	assert.NoError(err)
	assert.NotEmpty(user.PublicId)
	return user
}
