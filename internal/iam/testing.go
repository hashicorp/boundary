package iam

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/store"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

// TestRepo creates a repo that can be used for various purposes. Crucially, it
// ensures that the global scope contains a valid root key.
func TestRepo(t *testing.T, conn *gorm.DB, rootWrapper wrapping.Wrapper, opt ...Option) *Repository {
	require := require.New(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	wrapper, err := kmsCache.GetWrapper(context.Background(), scope.Global.String(), kms.KeyPurposeOplog)
	if err != nil {
		_, err = kms.CreateKeysTx(context.Background(), rw, rw, rootWrapper, rand.Reader, scope.Global.String())
		require.NoError(err)
		wrapper, err = kmsCache.GetWrapper(context.Background(), scope.Global.String(), kms.KeyPurposeOplog)
		if err != nil {
			panic(err)
		}
	}
	require.NoError(err)
	require.NotNil(wrapper)

	repo, err := NewRepository(rw, rw, kmsCache, opt...)
	require.NoError(err)
	return repo
}

// TestScopes creates an org and project suitable for testing.
func TestScopes(t *testing.T, repo *Repository, opt ...Option) (org *Scope, prj *Scope) {
	t.Helper()
	require := require.New(t)

	opts := getOpts(opt...)

	org, err := NewOrg(opt...)
	require.NoError(err)
	org, err = repo.CreateScope(context.Background(), org, opts.withUserId, opt...)
	require.NoError(err)
	require.NotNil(org)
	require.NotEmpty(org.GetPublicId())

	prj, err = NewProject(org.GetPublicId(), opt...)
	require.NoError(err)
	prj, err = repo.CreateScope(context.Background(), prj, opts.withUserId, opt...)
	require.NoError(err)
	require.NotNil(prj)
	require.NotEmpty(prj.GetPublicId())

	return
}

func TestOrg(t *testing.T, repo *Repository, opt ...Option) (org *Scope) {
	t.Helper()
	require := require.New(t)

	opts := getOpts(opt...)

	org, err := NewOrg(opt...)
	require.NoError(err)
	org, err = repo.CreateScope(context.Background(), org, opts.withUserId)
	require.NoError(err)
	require.NotNil(org)
	require.NotEmpty(org.GetPublicId())

	return
}

func testOrg(t *testing.T, repo *Repository, name, description string) (org *Scope) {
	t.Helper()
	require := require.New(t)

	o, err := NewOrg(WithDescription(description), WithName(name))
	require.NoError(err)
	o, err = repo.CreateScope(context.Background(), o, "")
	require.NoError(err)
	require.NotNil(o)
	require.NotEmpty(o.GetPublicId())

	return o
}

func testProject(t *testing.T, repo *Repository, orgId string, opt ...Option) *Scope {
	t.Helper()
	require := require.New(t)

	p, err := NewProject(orgId, opt...)
	require.NoError(err)
	p, err = repo.CreateScope(context.Background(), p, "")
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
func TestUser(t *testing.T, repo *Repository, scopeId string, opt ...Option) *User {
	t.Helper()
	require := require.New(t)

	user, err := NewUser(scopeId, opt...)
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

func TestRoleGrant(t *testing.T, conn *gorm.DB, roleId, grant string, opt ...Option) *RoleGrant {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)

	g, err := NewRoleGrant(roleId, grant, opt...)
	require.NoError(err)
	err = rw.Create(context.Background(), g)
	require.NoError(err)
	return g
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

func TestGroupMember(t *testing.T, conn *gorm.DB, groupId, userId string, opt ...Option) *GroupMemberUser {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	gm, err := NewGroupMemberUser(groupId, userId)
	require.NoError(err)
	require.NotNil(gm)
	err = rw.Create(context.Background(), gm)
	require.NoError(err)
	require.NotEmpty(gm.CreateTime)
	return gm
}

func TestUserRole(t *testing.T, conn *gorm.DB, roleId, userId string, opt ...Option) *UserRole {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	r, err := NewUserRole(roleId, userId, opt...)
	require.NoError(err)

	err = rw.Create(context.Background(), r)
	require.NoError(err)
	return r
}

func TestGroupRole(t *testing.T, conn *gorm.DB, roleId, grpId string, opt ...Option) *GroupRole {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	r, err := NewGroupRole(roleId, grpId, opt...)
	require.NoError(err)

	err = rw.Create(context.Background(), r)
	require.NoError(err)
	return r
}

// testAccount is a temporary test function.  TODO - replace with an auth
// subsystem testAccount function.  If userId is zero value, then an auth
// account will be created with a null IamUserId
func testAccount(t *testing.T, conn *gorm.DB, scopeId, authMethodId, userId string) *authAccount {
	const (
		accountPrefix = "aa_"
	)
	t.Helper()
	rw := db.New(conn)
	require := require.New(t)
	require.NotNil(conn)
	require.NotEmpty(scopeId)
	require.NotEmpty(authMethodId)

	if userId != "" {
		foundUser := allocUser()
		foundUser.PublicId = userId
		err := rw.LookupByPublicId(context.Background(), &foundUser)
		require.NoError(err)
		require.Equal(scopeId, foundUser.ScopeId)
	}

	var count int
	err := conn.DB().QueryRow(whereValidAuthMethod, authMethodId, scopeId).Scan(&count)
	require.NoError(err)
	require.Equal(1, count)

	id, err := db.NewPublicId(accountPrefix)
	require.NoError(err)

	acct := &authAccount{
		Account: &store.Account{
			PublicId:     id,
			ScopeId:      scopeId,
			AuthMethodId: authMethodId,
			IamUserId:    userId,
		},
	}
	err = rw.Create(context.Background(), acct)
	require.NoError(err)
	require.NotEmpty(acct.PublicId)

	if userId == "" {
		dbassert := dbassert.New(t, rw)
		dbassert.IsNull(acct, "IamUserId")
	}
	return acct
}

// testAuthMethod is a temporary test function.  TODO - replace with an auth
// subsystem testAuthMethod function.
func testAuthMethod(t *testing.T, conn *gorm.DB, scopeId string) string {
	const (
		authMethodPrefix = "am_"
	)
	t.Helper()
	require := require.New(t)
	require.NotNil(conn)
	require.NotEmpty(scopeId)
	id, err := db.NewPublicId(authMethodPrefix)
	require.NoError(err)

	_, err = conn.DB().Exec(insertAuthMethod, id, scopeId)
	require.NoError(err)
	return id
}
