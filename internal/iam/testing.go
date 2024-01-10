// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

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
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
)

// TestRepo creates a repo that can be used for various purposes. Crucially, it
// ensures that the global scope contains a valid root key.
func TestRepo(t testing.TB, conn *db.DB, rootWrapper wrapping.Wrapper, opt ...Option) *Repository {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	wrapper, err := kmsCache.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeOplog)
	if err != nil {
		err = kmsCache.CreateKeys(ctx, scope.Global.String(), kms.WithRandomReader(rand.Reader))
		require.NoError(err)
		wrapper, err = kmsCache.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeOplog)
		if err != nil {
			panic(err)
		}
	}
	require.NoError(err)
	require.NotNil(wrapper)

	repo, err := NewRepository(ctx, rw, rw, kmsCache, opt...)
	require.NoError(err)
	return repo
}

// TestSetPrimaryAuthMethod will set the PrimaryAuthMethodId for a scope.
func TestSetPrimaryAuthMethod(t testing.TB, repo *Repository, s *Scope, authMethodId string) {
	t.Helper()
	require := require.New(t)
	require.NotEmpty(s)
	require.NotEmpty(authMethodId)
	s.PrimaryAuthMethodId = authMethodId
	_, _, err := repo.UpdateScope(context.Background(), s, s.Version, []string{"PrimaryAuthMethodId"})
	require.NoError(err)

	updated, err := repo.LookupScope(context.Background(), s.PublicId)
	require.NoError(err)
	require.Equalf(authMethodId, updated.PrimaryAuthMethodId, "expected %s to be the primary auth method for scope: %s", authMethodId, updated.PublicId)
}

// TestScopes creates an org and project suitable for testing.
func TestScopes(t testing.TB, repo *Repository, opt ...Option) (org *Scope, prj *Scope) {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)

	opts := getOpts(opt...)

	org, err := NewOrg(ctx, opt...)
	require.NoError(err)
	org, err = repo.CreateScope(ctx, org, opts.withUserId, opt...)
	require.NoError(err)
	require.NotNil(org)
	require.NotEmpty(org.GetPublicId())

	prj, err = NewProject(ctx, org.GetPublicId(), opt...)
	require.NoError(err)
	prj, err = repo.CreateScope(ctx, prj, opts.withUserId, opt...)
	require.NoError(err)
	require.NotNil(prj)
	require.NotEmpty(prj.GetPublicId())

	return
}

func TestOrg(t testing.TB, repo *Repository, opt ...Option) *Scope {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)

	opts := getOpts(opt...)

	org, err := NewOrg(ctx, opt...)
	require.NoError(err)
	org, err = repo.CreateScope(ctx, org, opts.withUserId, opt...)
	require.NoError(err)
	require.NotNil(org)
	require.NotEmpty(org.GetPublicId())

	return org
}

func TestProject(t testing.TB, repo *Repository, orgId string, opt ...Option) *Scope {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)

	opts := getOpts(opt...)

	proj, err := NewProject(ctx, orgId, opt...)
	require.NoError(err)
	proj, err = repo.CreateScope(ctx, proj, opts.withUserId, opt...)
	require.NoError(err)
	require.NotNil(proj)
	require.NotEmpty(proj.GetPublicId())

	return proj
}

func testOrg(t testing.TB, repo *Repository, name, description string) (org *Scope) {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)

	o, err := NewOrg(ctx, WithDescription(description), WithName(name))
	require.NoError(err)
	o, err = repo.CreateScope(ctx, o, "")
	require.NoError(err)
	require.NotNil(o)
	require.NotEmpty(o.GetPublicId())

	return o
}

func testProject(t testing.TB, repo *Repository, orgId string, opt ...Option) *Scope {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)

	p, err := NewProject(ctx, orgId, opt...)
	require.NoError(err)
	p, err = repo.CreateScope(ctx, p, "")
	require.NoError(err)
	require.NotNil(p)
	require.NotEmpty(p.GetPublicId())

	return p
}

func testId(t testing.TB) string {
	t.Helper()
	id, err := uuid.GenerateUUID()
	require.NoError(t, err)
	return id
}

func testPublicId(t testing.TB, prefix string) string {
	t.Helper()
	publicId, err := db.NewPublicId(context.Background(), prefix)
	require.NoError(t, err)
	return publicId
}

// TestUser creates a user suitable for testing.  Supports the options:
// WithName, WithDescription and WithAccountIds.
func TestUser(t testing.TB, repo *Repository, scopeId string, opt ...Option) *User {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)

	user, err := NewUser(ctx, scopeId, opt...)
	require.NoError(err)
	user, err = repo.CreateUser(ctx, user)
	require.NoError(err)
	require.NotEmpty(user.PublicId)
	opts := getOpts(opt...)
	if len(opts.withAccountIds) > 0 {
		_, err := repo.AddUserAccounts(ctx, user.PublicId, user.Version, opts.withAccountIds)
		require.NoError(err)
		// now that we have updated user accounts, we need to re-fetch the user
		// to get the updated version and update time
		user, err = repo.lookupUser(ctx, user.GetPublicId())
		require.NoError(err)
	}
	return user
}

// TestRole creates a role suitable for testing.
func TestRole(t testing.TB, conn *db.DB, scopeId string, opt ...Option) *Role {
	t.Helper()
	opts := getOpts(opt...)
	if opts.withGrantScopeId != "" && len(opts.withGrantScopeIds) > 0 {
		require.FailNow(t, "cannot specify both withGrantScopeId and withGrantScopeIds")
	}

	ctx := context.Background()
	require := require.New(t)
	rw := db.New(conn)

	role, err := NewRole(ctx, scopeId, opt...)
	require.NoError(err)
	id, err := newRoleId(ctx)
	require.NoError(err)
	role.PublicId = id
	role.GrantScopeId = scopeId
	require.NoError(rw.Create(ctx, role))
	require.NotEmpty(role.PublicId)

	grantScopeIds := opts.withGrantScopeIds
	if len(grantScopeIds) == 0 {
		scpId := opts.withGrantScopeId
		if scpId == "" {
			scpId = "this"
		}
		grantScopeIds = []string{scpId}
	}
	for _, gsi := range grantScopeIds {
		gs, err := NewRoleGrantScope(ctx, id, gsi)
		require.NoError(err)
		require.NoError(rw.Create(ctx, gs))
	}
	require.Equal(opts.withDescription, role.Description)
	require.Equal(opts.withName, role.Name)
	return role
}

func TestRoleGrant(t testing.TB, conn *db.DB, roleId, grant string, opt ...Option) *RoleGrant {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)

	g, err := NewRoleGrant(context.Background(), roleId, grant, opt...)
	require.NoError(err)
	err = rw.Create(context.Background(), g)
	require.NoError(err)
	return g
}

// TestGroup creates a group suitable for testing.
func TestGroup(t testing.TB, conn *db.DB, scopeId string, opt ...Option) *Group {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)
	rw := db.New(conn)

	grp, err := NewGroup(ctx, scopeId, opt...)
	require.NoError(err)
	id, err := newGroupId(ctx)
	require.NoError(err)
	grp.PublicId = id
	err = rw.Create(ctx, grp)
	require.NoError(err)
	require.NotEmpty(grp.PublicId)
	return grp
}

func TestGroupMember(t testing.TB, conn *db.DB, groupId, userId string, opt ...Option) *GroupMemberUser {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)
	rw := db.New(conn)
	gm, err := NewGroupMemberUser(ctx, groupId, userId)
	require.NoError(err)
	require.NotNil(gm)
	err = rw.Create(ctx, gm)
	require.NoError(err)
	require.NotEmpty(gm.CreateTime)
	return gm
}

func TestUserRole(t testing.TB, conn *db.DB, roleId, userId string, opt ...Option) *UserRole {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)
	rw := db.New(conn)
	r, err := NewUserRole(ctx, roleId, userId, opt...)
	require.NoError(err)

	err = rw.Create(ctx, r)
	require.NoError(err)
	return r
}

func TestGroupRole(t testing.TB, conn *db.DB, roleId, grpId string, opt ...Option) *GroupRole {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	r, err := NewGroupRole(context.Background(), roleId, grpId, opt...)
	require.NoError(err)

	err = rw.Create(context.Background(), r)
	require.NoError(err)
	return r
}

func TestManagedGroupRole(t testing.TB, conn *db.DB, roleId, managedGrpId string, opt ...Option) *ManagedGroupRole {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	r, err := NewManagedGroupRole(context.Background(), roleId, managedGrpId, opt...)
	require.NoError(err)

	err = rw.Create(context.Background(), r)
	require.NoError(err)
	return r
}

// testAccount is a temporary test function.  TODO - replace with an auth
// subsystem testAccount function.  If userId is zero value, then an auth
// account will be created with a null IamUserId
func testAccount(t testing.TB, conn *db.DB, scopeId, authMethodId, userId string) *authAccount {
	const (
		accountPrefix = "aa_"
	)
	t.Helper()
	ctx := context.Background()

	rw := db.New(conn)
	require := require.New(t)
	require.NotNil(conn)
	require.NotEmpty(scopeId)
	require.NotEmpty(authMethodId)

	if userId != "" {
		foundUser := AllocUser()
		foundUser.PublicId = userId
		err := rw.LookupByPublicId(context.Background(), &foundUser)
		require.NoError(err)
		require.Equal(scopeId, foundUser.ScopeId)
	}

	var count int
	underlyingDB, err := conn.SqlDB(ctx)
	require.NoError(err)
	err = underlyingDB.QueryRow(whereValidAuthMethod, authMethodId, scopeId).Scan(&count)
	require.NoError(err)
	require.Equal(1, count)

	id, err := db.NewPublicId(ctx, accountPrefix)
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
		underlyingDB, err := conn.SqlDB(ctx)
		require.NoError(err)
		dbassert := dbassert.New(t, underlyingDB)
		dbassert.IsNull(acct, "IamUserId")
	}
	return acct
}

// testAuthMethod is a temporary test function.  TODO - replace with an auth
// subsystem testAuthMethod function.
func testAuthMethod(t testing.TB, conn *db.DB, scopeId string) string {
	const (
		authMethodPrefix = "am_"
	)
	t.Helper()
	ctx := context.Background()
	require := require.New(t)
	require.NotNil(conn)
	require.NotEmpty(scopeId)
	id, err := db.NewPublicId(ctx, authMethodPrefix)
	require.NoError(err)

	rw := db.New(conn)
	_, err = rw.Exec(ctx, insertAuthMethod, []any{id, scopeId})
	require.NoError(err)
	return id
}
