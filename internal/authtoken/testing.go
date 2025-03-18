// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package authtoken

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
)

// TestAuthToken, despite its name, does more than just return an auth token; it
// also creates an auth method, an account, and a user and binds them together,
// then creates an auth token against it
func TestAuthToken(t testing.TB, conn *db.DB, kms *kms.Kms, scopeId string, opt ...Option) *AuthToken {
	t.Helper()

	opts := getOpts(opt...)
	passwordOpts := password.GetOpts(opts.withPasswordOptions...)
	loginName := passwordOpts.WithLoginName
	if loginName == "" {
		loginName = "name1"
	}

	authMethod := password.TestAuthMethods(t, conn, scopeId, 1)[0]
	// auth account is only used to join auth method to user.
	// We don't do anything else with the auth account in the test setup.
	acct := password.TestAccount(t, conn, authMethod.GetPublicId(), loginName, opts.withPasswordOptions...)

	ctx := context.Background()
	rw := db.New(conn)
	iamRepo, err := iam.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	u := iam.TestUser(t, iamRepo, scopeId, append(opts.withIamOptions, iam.WithAccountIds(acct.PublicId))...)

	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	at, err := repo.CreateAuthToken(ctx, u, acct.GetPublicId(), opt...)
	require.NoError(t, err)
	return at
}

// TestRoleGrantsForToken contains information used by TestAuthTokenWithRoles to create
// roles and their associated grants (with grant scopes)
type TestRoleGrantsForToken struct {
	RoleScopeId  string
	GrantStrings []string
	GrantScopes  []string
}

// TestAuthTokenWithRoles creates auth token associated with roles as requested by the caller along
// with any required resources to achieve said token
func TestAuthTokenWithRoles(t testing.TB, conn *db.DB, kms *kms.Kms, scopeId string, roles []TestRoleGrantsForToken) *AuthToken {
	t.Helper()
	ctx := context.Background()
	rw := db.New(conn)
	atRepo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	iamRepo, err := iam.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	authMethod := password.TestAuthMethods(t, conn, scopeId, 1)[0]

	loginName, err := uuid.GenerateUUID()
	require.NoError(t, err)
	acct := password.TestAccount(t, conn, authMethod.GetPublicId(), loginName)
	user := iam.TestUser(t, iamRepo, scopeId, iam.WithAccountIds(acct.GetPublicId()))
	for _, r := range roles {
		role := iam.TestRoleWithGrants(t, conn, r.RoleScopeId, r.GrantScopes, r.GrantStrings)
		_ = iam.TestUserRole(t, conn, role.PublicId, user.PublicId)
	}
	fullGrantToken, err := atRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
	require.NoError(t, err)
	return fullGrantToken
}
