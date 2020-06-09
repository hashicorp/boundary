package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScopes creates an organization and project suitable for testing.
func TestScopes(t *testing.T, conn *gorm.DB) (org *Scope, prj *Scope) {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(err)

	org, err = NewOrganization()
	require.NoError(err)

	org, err = repo.CreateScope(context.Background(), org)
	require.NoError(err)
	require.NotNil(org)
	require.NotEmpty(org.GetPublicId())

	prj, err = NewProject(org.GetPublicId())
	require.NoError(err)

	prj, err = repo.CreateScope(context.Background(), prj)
	require.NoError(err)
	require.NotNil(prj)
	require.NotEmpty(prj.GetPublicId())

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

// TestUser creates a user suitable for testing.
func TestUser(t *testing.T, conn *gorm.DB, orgId string, opt ...Option) *User {
	t.Helper()
	assert := assert.New(t)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	assert.NoError(err)

	user, err := NewUser(orgId, opt...)
	assert.NoError(err)
	user, err = repo.CreateUser(context.Background(), user)
	assert.NoError(err)
	assert.NotEmpty(user.PublicId)
	return user
}

// TestGroup creates a group suitable for testing.
func TestGroup(t *testing.T, conn *gorm.DB, orgId string) *Group {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)

	grp, err := NewGroup(orgId)
	require.NoError(err)
	id, err := newGroupId()
	require.NoError(err)
	grp.PublicId = id
	err = rw.Create(context.Background(), grp)
	require.NoError(err)
	require.NotEmpty(grp.PublicId)
	return grp
}
