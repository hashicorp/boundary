package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/go-uuid"
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

func testOrg(t *testing.T, conn *gorm.DB, name, description string) (org *Scope) {
	t.Helper()
	assert := assert.New(t)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	assert.NoError(err)

	o, err := NewOrganization(WithDescription(description), WithName(name))
	assert.NoError(err)
	o, err = repo.CreateScope(context.Background(), o)
	assert.NoError(err)
	assert.NotNil(o)
	assert.NotEmpty(o.GetPublicId())
	return o
}

func testId(t *testing.T) string {
	t.Helper()
	assert := assert.New(t)
	id, err := uuid.GenerateUUID()
	assert.NoError(err)
	return id
}

func testPublicId(t *testing.T, prefix string) string {
	t.Helper()
	assert := assert.New(t)
	publicId, err := db.NewPublicId(prefix)
	assert.NoError(err)
	return publicId
}
