package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
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
	require := require.New(t)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(err)

	o, err := NewOrganization(WithDescription(description), WithName(name))
	require.NoError(err)
	o, err = repo.CreateScope(context.Background(), o)
	require.NoError(err)
	require.NotNil(o)
	require.NotEmpty(o.GetPublicId())
	return o
}

func testProject(t *testing.T, conn *gorm.DB, orgId string, opt ...Option) *Scope {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(err)

	p, err := NewProject(orgId, opt...)
	require.NoError(err)
	p, err = repo.CreateScope(context.Background(), p)
	require.NoError(err)
	require.NotNil(p)
	require.NotEmpty(p.GetPublicId())
	return p
}

func testId(t *testing.T) string {
	t.Helper()
	id, err := uuid.GenerateUUID()
	require.NoError(t, err)
	return id
}

func testPublicId(t *testing.T, prefix string) string {
	t.Helper()
	publicId, err := db.NewPublicId(prefix)
	require.NoError(t, err)
	return publicId
}

// TestUser creates a user suitable for testing.
func TestUser(t *testing.T, conn *gorm.DB, orgId string, opt ...Option) *User {
	t.Helper()
	require := assert.New(t)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(err)

	user, err := NewUser(orgId, opt...)
	require.NoError(err)
	user, err = repo.CreateUser(context.Background(), user)
	require.NoError(err)
	require.NotEmpty(user.PublicId)
	return user
}

// TestRole creates a role suitable for testing.
func TestRole(t *testing.T, conn *gorm.DB, scopeId string, opt ...Option) *Role {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)

	role, err := NewRole(scopeId, opt...)
	require.NoError(err)
	id, err := newRoleId()
	require.NoError(err)
	role.PublicId = id
	err = rw.Create(context.Background(), role)
	require.NoError(err)
	require.NotEmpty(role.PublicId)

	opts := getOpts(opt...)
	require.Equal(opts.withDescription, role.Description)
	require.Equal(opts.withName, role.Name)
	return role
}

// TestGroup creates a group suitable for testing.
func TestGroup(t *testing.T, conn *gorm.DB, scopeId string, opt ...Option) *Group {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)

	grp, err := NewGroup(scopeId, opt...)
	require.NoError(err)
	id, err := newGroupId()
	require.NoError(err)
	grp.PublicId = id
	err = rw.Create(context.Background(), grp)
	require.NoError(err)
	require.NotEmpty(grp.PublicId)
	return grp
}

// testAuthAccount is a temporary test function.  TODO - replace with an auth
// subsystem testAuthAccount function.
func testAuthAccount(t *testing.T, conn *gorm.DB, scopeId, authMethodId, userId string) *AuthAccount {
	t.Helper()
	const authAccountPrefix = "aa_"
	require := require.New(t)
	require.NotNil(conn)
	require.NotEmpty(scopeId)
	require.NotEmpty(userId)
	require.NotEmpty(authMethodId)

	id, err := db.NewPublicId(authAccountPrefix)
	require.NoError(err)

	acct := &AuthAccount{
		AuthAccount: &store.AuthAccount{
			PublicId:     id,
			ScopeId:      scopeId,
			AuthMethodId: authMethodId,
			IamUserId:    userId,
		},
	}
	rw := db.New(conn)
	err = rw.Create(context.Background(), acct)
	require.NoError(err)
	require.NotEmpty(acct.PublicId)
	return acct
}

// testAuthMethod is a temporary test function.  TODO - replace with an auth
// subsystem testAuthMethod function.
func testAuthMethod(t *testing.T, conn *gorm.DB, scopeId string) string {
	t.Helper()
	require := require.New(t)
	require.NotNil(conn)
	require.NotEmpty(scopeId)
	const (
		authMethodPrefix = "am_"
		insert           = `insert into auth_method (public_id, scope_id) values ($1, $2)`
	)
	id, err := db.NewPublicId(authMethodPrefix)
	require.NoError(err)

	_, err = conn.DB().Exec(insert, id, scopeId)
	require.NoError(err)
	return id
}
