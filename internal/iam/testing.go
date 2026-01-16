// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"crypto/rand"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/store"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	iamstore "github.com/hashicorp/boundary/internal/iam/store"
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

	return org, prj
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

// TestRole creates a role suitable for testing. It will use a default grant
// scope ID unless WithGrantScopeId is used. To prevent a grant scope from being
// created, pass in a grant scope ID option with the value "testing-none".
func TestRole(t testing.TB, conn *db.DB, scopeId string, opt ...Option) *Role {
	t.Helper()
	opts := getOpts(opt...)

	ctx := context.Background()
	require := require.New(t)
	rw := db.New(conn)

	id, err := newRoleId(ctx)
	require.NoError(err)
	grantScopeIds := opts.withGrantScopeIds

	// finalGrantScopes holds all 'GrantScopes' which will be in the final *Role object
	var finalGrantScopes []*RoleGrantScope

	grantThis := false
	// default to `this` when no grant scope is specified - this is done as a part of role creation
	// to avoid bumping role version with TestRoleGrantScope operation
	// of in 'role_grant_scope' tables
	// This is a part of grants refactor in for release 0.20.0 which moves 'this' grants to the role tables instead
	// Using WithGrantScopeIds to add 'this' grant scope will be handled by TestRoleGrantScope calls later
	// which bumps the role version to 2 since the 'this' grant scope will be added as a separate operation
	if len(grantScopeIds) == 0 {
		grantThis = true
	}
	var role *Role
	switch {
	case strings.HasPrefix(scopeId, globals.GlobalPrefix):
		g := &globalRole{
			GlobalRole: &iamstore.GlobalRole{
				PublicId:           id,
				ScopeId:            scopeId,
				Name:               opts.withName,
				Description:        opts.withDescription,
				GrantThisRoleScope: grantThis,
				GrantScope:         globals.GrantScopeIndividual, // handled by TestRoleGrantScope later
			},
		}
		require.NoError(rw.Create(ctx, g))
		require.NotEmpty(g.PublicId)
		role = g.toRole()
		// adding 'this' role grant scope is done manually to handle cases where 'this' grant is added by default
		// which will NOT update the role version and will not show up from call later on
		if grantThis {
			gs, _ := g.grantThisRoleScope()
			finalGrantScopes = append(finalGrantScopes, gs)
		}
	case strings.HasPrefix(scopeId, globals.OrgPrefix):
		o := &orgRole{
			OrgRole: &iamstore.OrgRole{
				PublicId:           id,
				ScopeId:            scopeId,
				Name:               opts.withName,
				Description:        opts.withDescription,
				GrantThisRoleScope: grantThis,
				GrantScope:         globals.GrantScopeIndividual, // handled by TestRoleGrantScope later
			},
		}
		require.NoError(rw.Create(ctx, o))
		require.NotEmpty(o.PublicId)
		role = o.toRole()
		// adding 'this' role grant scope is done manually to handle cases where 'this' grant is added by default
		// which will NOT update the role version and will not show up from call later on
		if grantThis {
			gs, _ := o.grantThisRoleScope()
			finalGrantScopes = append(finalGrantScopes, gs)
		}
	case strings.HasPrefix(scopeId, globals.ProjectPrefix):
		p := &projectRole{
			ProjectRole: &iamstore.ProjectRole{
				PublicId:           id,
				ScopeId:            scopeId,
				Name:               opts.withName,
				Description:        opts.withDescription,
				GrantThisRoleScope: grantThis,
			},
		}
		require.NoError(rw.Create(ctx, p))
		require.NotEmpty(p.PublicId)
		role = p.toRole()
		// adding 'this' role grant scope is done manually to handle cases where 'this' grant is added by default
		// which will NOT update the role version and will not show up from call later on
		if grantThis {
			gs, _ := p.grantThisRoleScope()
			finalGrantScopes = append(finalGrantScopes, gs)
		}
	default:
		t.Logf("invalid scope id: %s", scopeId)
		t.FailNow()
	}

	for _, gsi := range grantScopeIds {
		if gsi == "testing-none" {
			continue
		}
		gs := TestRoleGrantScope(t, conn, role, gsi)
		finalGrantScopes = append(finalGrantScopes, gs)
	}
	require.Equal(opts.withDescription, role.Description)
	require.Equal(opts.withName, role.Name)

	var final *Role
	switch {
	case strings.HasPrefix(scopeId, globals.GlobalPrefix):
		g := allocGlobalRole()
		g.PublicId = id
		require.NoError(rw.LookupByPublicId(ctx, &g))
		final = g.toRole()
	case strings.HasPrefix(scopeId, globals.OrgPrefix):
		o := allocOrgRole()
		o.PublicId = id
		require.NoError(rw.LookupByPublicId(ctx, &o))
		final = o.toRole()
	case strings.HasPrefix(scopeId, globals.ProjectPrefix):
		p := allocProjectRole()
		p.PublicId = id
		require.NoError(rw.LookupByPublicId(ctx, &p))
		final = p.toRole()
	default:
		t.Logf("invalid scope id: %s", scopeId)
		t.FailNow()
	}
	final.GrantScopes = finalGrantScopes
	return final
}

// TestRoleWithGrants creates a role suitable for testing along with grants
// Functional options for GrantScopeIDs aren't used to express that
// this function does not provide any default grant scope unlike TestRole
func TestRoleWithGrants(t testing.TB, conn *db.DB, scopeId string, grantScopeIDs []string, grants []string) *Role {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)
	rw := db.New(conn)
	grantsThis := false
	if slices.Contains(grantScopeIDs, globals.GrantScopeThis) || len(grantScopeIDs) == 0 {
		grantsThis = true
	}
	id, err := newRoleId(ctx)
	require.NoError(err)
	var role *Role
	switch {
	case strings.HasPrefix(scopeId, globals.GlobalPrefix):
		g := &globalRole{
			GlobalRole: &iamstore.GlobalRole{
				PublicId:           id,
				ScopeId:            scopeId,
				GrantThisRoleScope: grantsThis,
				GrantScope:         globals.GrantScopeIndividual, // handled by TestRoleGrantScope call after this
			},
		}
		require.NoError(rw.Create(ctx, g))
		require.NotEmpty(g.PublicId)
		role = g.toRole()
	case strings.HasPrefix(scopeId, globals.OrgPrefix):
		o := &orgRole{
			OrgRole: &iamstore.OrgRole{
				PublicId:           id,
				ScopeId:            scopeId,
				GrantThisRoleScope: grantsThis,
				GrantScope:         globals.GrantScopeIndividual, // handled by TestRoleGrantScope call after this
			},
		}
		require.NoError(rw.Create(ctx, o))
		require.NotEmpty(o.PublicId)
		role = o.toRole()
	case strings.HasPrefix(scopeId, globals.ProjectPrefix):
		p := &projectRole{
			ProjectRole: &iamstore.ProjectRole{
				PublicId: id,
				ScopeId:  scopeId,
			},
		}
		require.NoError(rw.Create(ctx, p))
		require.NotEmpty(p.PublicId)
		role = p.toRole()
	default:
		t.Logf("invalid scope id: %s", scopeId)
		t.FailNow()
	}
	for _, gsi := range grantScopeIDs {
		if gsi == "testing-none" {
			continue
		}
		gs := TestRoleGrantScope(t, conn, role, gsi)
		role.GrantScopes = append(role.GrantScopes, gs)
	}
	for _, g := range grants {
		_ = TestRoleGrant(t, conn, role.PublicId, g)
	}
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

func TestRoleGrantScope(t testing.TB, conn *db.DB, r *Role, grantScopeId string, opt ...Option) *RoleGrantScope {
	t.Helper()
	if r.ScopeId == grantScopeId {
		grantScopeId = globals.GrantScopeThis
	}
	switch grantScopeId {
	case globals.GrantScopeThis:
		return testRoleGrantScopeThis(t, conn, r)
	case globals.GrantScopeDescendants, globals.GrantScopeChildren:
		return testRoleGrantScopeSpecial(t, conn, r, grantScopeId)
	default:
		return testRoleGrantScopeIndividual(t, conn, r, grantScopeId)
	}
}

// testRoleGrantScopeThis is a utility function for adding 'this' to a role's Grant scopes
// this function is not meant to be called directly - use `TestRoleGrantScope` or `TestRoleWithGrants`
func testRoleGrantScopeThis(t testing.TB, conn *db.DB, r *Role) *RoleGrantScope {
	rw := db.New(conn)
	ctx := context.Background()
	var result *RoleGrantScope
	switch {
	case strings.HasPrefix(r.ScopeId, globals.GlobalPrefix):
		g := allocGlobalRole()
		g.PublicId = r.PublicId
		g.GrantThisRoleScope = true
		_, err := rw.Update(ctx, &g, []string{"GrantThisRoleScope"}, []string{})
		require.NoError(t, err)
		result = &RoleGrantScope{
			CreateTime:       g.GrantThisRoleScopeUpdateTime,
			RoleId:           g.PublicId,
			ScopeIdOrSpecial: globals.GrantScopeThis,
		}
	case strings.HasPrefix(r.ScopeId, globals.OrgPrefix):
		o := allocOrgRole()
		o.PublicId = r.PublicId
		o.GrantThisRoleScope = true
		_, err := rw.Update(ctx, &o, []string{"GrantThisRoleScope"}, []string{})
		require.NoError(t, err)
		result = &RoleGrantScope{
			CreateTime:       o.GrantThisRoleScopeUpdateTime,
			RoleId:           o.PublicId,
			ScopeIdOrSpecial: globals.GrantScopeThis,
		}
	case strings.HasPrefix(r.ScopeId, globals.ProjectPrefix):
		p := allocProjectRole()
		p.PublicId = r.PublicId
		p.GrantThisRoleScope = true
		_, err := rw.Update(ctx, &p, []string{"GrantThisRoleScope"}, []string{})
		require.NoError(t, err)
		result = &RoleGrantScope{
			CreateTime:       p.GrantThisRoleScopeUpdateTime,
			RoleId:           p.PublicId,
			ScopeIdOrSpecial: globals.GrantScopeThis,
		}
	default:
		t.Logf("invalid scope type for this grant: %s", r.ScopeId)
		t.FailNow()
	}
	return result
}

// testRoleGrantScopeThis is a utility function for adding special scopes (children, descendants) to a role's Grant scopes
// this function is not meant to be called directly - use `TestRoleGrantScope` or `TestRoleWithGrants`
func testRoleGrantScopeSpecial(t testing.TB, conn *db.DB, r *Role, grantScopeId string) *RoleGrantScope {
	rw := db.New(conn)
	ctx := context.Background()
	allowedGrantScopeId := []string{
		globals.GrantScopeChildren,
		globals.GrantScopeDescendants,
	}
	// ensure that only special scopes are passed in here
	require.Contains(t, allowedGrantScopeId, grantScopeId)
	var result *RoleGrantScope
	switch {
	case strings.HasPrefix(r.ScopeId, globals.GlobalPrefix):
		g := allocGlobalRole()
		g.PublicId = r.PublicId
		g.GrantScope = grantScopeId
		_, err := rw.Update(ctx, &g, []string{"GrantScope"}, []string{})
		require.NoError(t, err)
		result = &RoleGrantScope{
			CreateTime:       g.GrantScopeUpdateTime,
			RoleId:           g.PublicId,
			ScopeIdOrSpecial: grantScopeId,
		}
	case strings.HasPrefix(r.ScopeId, globals.OrgPrefix):
		// 'descendants' grants isn't allowed for org but not handling that case to reduce code duplication and
		// the constraint check in the DB will return an error anyway
		o := allocOrgRole()
		o.PublicId = r.PublicId
		o.GrantScope = grantScopeId
		_, err := rw.Update(ctx, &o, []string{"GrantScope"}, []string{})
		require.NoError(t, err)
		result = &RoleGrantScope{
			CreateTime:       o.GrantThisRoleScopeUpdateTime,
			RoleId:           o.PublicId,
			ScopeIdOrSpecial: grantScopeId,
		}
	default:
		t.Logf("invalid scope type for children grant: %s", r.ScopeId)
		t.FailNow()
	}
	return result
}

func testRoleGrantScopeIndividual(t testing.TB, conn *db.DB, r *Role, grantScopeId string) *RoleGrantScope {
	rw := db.New(conn)
	ctx := context.Background()

	var result *RoleGrantScope
	switch {
	case strings.HasPrefix(r.ScopeId, globals.GlobalPrefix):
		// perform a read to get 'role.GrantScope' because there are two allowed values: [children, individual]
		g := allocGlobalRole()
		g.PublicId = r.PublicId
		require.NoError(t, rw.LookupByPublicId(ctx, &g))
		switch {
		case strings.HasPrefix(grantScopeId, globals.OrgPrefix):
			orgGrantScope := &globalRoleIndividualOrgGrantScope{
				GlobalRoleIndividualOrgGrantScope: &iamstore.GlobalRoleIndividualOrgGrantScope{
					RoleId:     g.PublicId,
					ScopeId:    grantScopeId,
					GrantScope: g.GrantScope,
				},
			}
			require.NoError(t, rw.Create(ctx, orgGrantScope))
			result = &RoleGrantScope{
				CreateTime:       orgGrantScope.CreateTime,
				RoleId:           orgGrantScope.RoleId,
				ScopeIdOrSpecial: orgGrantScope.ScopeId,
			}
		case strings.HasPrefix(grantScopeId, globals.ProjectPrefix):
			projGrantScope := &globalRoleIndividualProjectGrantScope{
				GlobalRoleIndividualProjectGrantScope: &iamstore.GlobalRoleIndividualProjectGrantScope{
					RoleId:     g.PublicId,
					ScopeId:    grantScopeId,
					GrantScope: g.GrantScope,
				},
			}
			require.NoError(t, rw.Create(ctx, projGrantScope))
			result = &RoleGrantScope{
				CreateTime:       projGrantScope.CreateTime,
				RoleId:           projGrantScope.RoleId,
				ScopeIdOrSpecial: projGrantScope.ScopeId,
			}
		default:
			t.Logf("invalid scope id for global role invidual grant scope: %s", grantScopeId)
			t.FailNow()
		}
	case strings.HasPrefix(r.ScopeId, globals.OrgPrefix):
		o := &orgRoleIndividualGrantScope{
			OrgRoleIndividualGrantScope: &iamstore.OrgRoleIndividualGrantScope{
				RoleId:     r.PublicId,
				ScopeId:    grantScopeId,
				GrantScope: globals.GrantScopeIndividual,
			},
		}
		require.NoError(t, rw.Create(ctx, o))
		result = &RoleGrantScope{
			CreateTime:       o.CreateTime,
			RoleId:           o.RoleId,
			ScopeIdOrSpecial: o.ScopeId,
		}
	default:
		t.Logf("invalid scope for individual scope grant: %s", r.ScopeId)
		t.FailNow()
		return nil
	}

	return result
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

type TestRoleGrantsRequest struct {
	RoleScopeId string
	GrantScopes []string
	Grants      []string
}

// TestUserManagedGroupGrantsFunc returns a function that creates a user which has been given
// the request grants through managed group.
// Note: This method is not responsible for associating the user to the managed group. That action needs to be done
// by the caller
// This function returns iam.User and the AccountID from the account setup func
func TestUserManagedGroupGrantsFunc(
	t *testing.T,
	conn *db.DB,
	kmsCache *kms.Kms,
	scopeId string,
	managedGroupAccountSetupFunc auth.TestAuthMethodWithAccountInManagedGroup,
	testRoleGrants []TestRoleGrantsRequest,
) func() (*User, auth.Account) {
	return func() (*User, auth.Account) {
		t.Helper()
		ctx := context.Background()
		rw := db.New(conn)
		repo, err := NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		_, account, mg := managedGroupAccountSetupFunc(t, conn, kmsCache, scopeId)
		user := TestUser(t, repo, scopeId, WithAccountIds(account.GetPublicId()))
		for _, trg := range testRoleGrants {
			role := TestRoleWithGrants(t, conn, trg.RoleScopeId, trg.GrantScopes, trg.Grants)
			_ = TestManagedGroupRole(t, conn, role.PublicId, mg.GetPublicId())
		}
		user, acctIDs, err := repo.LookupUser(ctx, user.PublicId)
		require.NoError(t, err)
		require.Len(t, acctIDs, 1)
		return user, account
	}
}

// TestUserDirectGrantsFunc returns a function that creates and returns user which has been given
// the request grants via direct association.
// This function returns iam.User and the AccountID from the account setup func
func TestUserDirectGrantsFunc(
	t *testing.T,
	conn *db.DB,
	kmsCache *kms.Kms,
	scopeId string,
	setupFunc auth.TestAuthMethodWithAccountFunc,
	testRoleGrants []TestRoleGrantsRequest,
) func() (*User, auth.Account) {
	return func() (*User, auth.Account) {
		t.Helper()
		_, account := setupFunc(t, conn)
		ctx := context.Background()
		rw := db.New(conn)
		repo, err := NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		user := TestUser(t, repo, scopeId, WithAccountIds(account.GetPublicId()))
		require.NoError(t, err)
		for _, trg := range testRoleGrants {
			role := TestRoleWithGrants(t, conn, trg.RoleScopeId, trg.GrantScopes, trg.Grants)
			_ = TestUserRole(t, conn, role.PublicId, user.PublicId)
		}
		user, acctIDs, err := repo.LookupUser(ctx, user.PublicId)
		require.NoError(t, err)
		require.Len(t, acctIDs, 1)
		return user, account
	}
}

// TestUserGroupGrantsFunc returns a function that creates a user which has been given
// the request grants by being a part of a group.
// Group is created as a part of this method
// This function returns iam.User and the AccountID from the account setup func
func TestUserGroupGrantsFunc(
	t *testing.T,
	conn *db.DB,
	kmsCache *kms.Kms,
	scopeId string,
	setupFunc auth.TestAuthMethodWithAccountFunc,
	testRoleGrants []TestRoleGrantsRequest,
) func() (*User, auth.Account) {
	return func() (*User, auth.Account) {
		t.Helper()
		_, account := setupFunc(t, conn)
		ctx := context.Background()
		rw := db.New(conn)
		repo, err := NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		group := TestGroup(t, conn, scopeId)
		user := TestUser(t, repo, scopeId, WithAccountIds(account.GetPublicId()))
		for _, trg := range testRoleGrants {
			role := TestRoleWithGrants(t, conn, trg.RoleScopeId, trg.GrantScopes, trg.Grants)
			_ = TestGroupRole(t, conn, role.PublicId, group.PublicId)
		}
		_, err = repo.AddGroupMembers(ctx, group.PublicId, group.Version, []string{user.PublicId})
		require.NoError(t, err)
		user, acctIDs, err := repo.LookupUser(ctx, user.PublicId)
		require.NoError(t, err)
		require.Len(t, acctIDs, 1)
		return user, account
	}
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
