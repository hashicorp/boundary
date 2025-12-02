// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/scope"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

// TestRepo creates a repository for AppToken testing.
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

func testPublicId(t testing.TB, prefix string) string {
	t.Helper()
	publicId, err := db.NewPublicId(context.Background(), prefix)
	require.NoError(t, err)
	return publicId
}

// TestAppToken creates an app token for testing with the specified grants.
// TODO: Implement TestAppToken once AppToken functionality is added
func TestAppToken(t *testing.T, repo *Repository, scopeId string, grants []string, user *iam.User, grantThisScope bool, grantScope string) *AppToken {
	t.Helper()

	publicId := testPublicId(t, "appt_")
	tempTestAddGrants(t, repo, publicId, scopeId, grants, user, grantThisScope, grantScope)
	return &AppToken{
		PublicId:    publicId,
		ScopeId:     scopeId,
		Description: "test app token",
	}
}

// tempTestAddGrants is a temporary test function to add grants to the database for testing
// TODO: Replace with proper AppToken creation function once AppToken functionality is added
func tempTestAddGrants(t *testing.T, repo *Repository, tokenId, scopeId string, grants []string, user *iam.User, grantThisScope bool, grantScope string) {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)

	// Determine which table to insert into based on scope prefix
	var insertTokenSQL, insertPermissionSQL, insertGrantSQL string

	switch {
	case strings.HasPrefix(scopeId, globals.GlobalPrefix):
		insertTokenSQL = `
			insert into app_token_global (public_id, scope_id, description, created_by_user_id, create_time, update_time)
			values ($1, $2, $3, $4, now(), now())
		`
		insertPermissionSQL = `
			insert into app_token_permission_global (private_id, app_token_id, description, grant_this_scope, grant_scope, create_time)
			values ($1, $2, $3, $4, $5, now())
		`
		insertGrantSQL = `
			insert into app_token_permission_grant (permission_id, raw_grant, canonical_grant)
			values ($1, $2, $3)
		`
	case strings.HasPrefix(scopeId, globals.OrgPrefix):
		insertTokenSQL = `
			insert into app_token_org (public_id, scope_id, description, created_by_user_id, create_time, update_time)
			values ($1, $2, $3, $4, now(), now())
		`
		insertPermissionSQL = `
			insert into app_token_permission_org (private_id, app_token_id, description, grant_this_scope, grant_scope, create_time)
			values ($1, $2, $3, $4, $5, now())
		`
		insertGrantSQL = `
			insert into app_token_permission_grant (permission_id, raw_grant, canonical_grant)
			values ($1, $2, $3)
		`
	case strings.HasPrefix(scopeId, globals.ProjectPrefix):
		insertTokenSQL = `
			insert into app_token_project (public_id, scope_id, description, created_by_user_id,create_time, update_time)
			values ($1, $2, $3, $4, now(), now())
		`
		insertPermissionSQL = `
			insert into app_token_permission_project (private_id, app_token_id, description, grant_this_scope, create_time)
			values ($1, $2, $3, $4, now())
		`
		insertGrantSQL = `
			insert into app_token_permission_grant (permission_id, raw_grant, canonical_grant)
			values ($1, $2, $3)
		`
	default:
		t.Fatalf("invalid scope id: %s", scopeId)
	}

	// Insert the app token
	_, err := repo.writer.Exec(ctx, insertTokenSQL, []any{tokenId, scopeId, "test app token", user.PublicId})
	require.NoError(err)

	// Create a permission for this token
	permissionId := testPublicId(t, "aptp_")

	// Default to 'descendants' if not specified for global/org scopes
	if grantScope == "" && (strings.HasPrefix(scopeId, globals.GlobalPrefix) || strings.HasPrefix(scopeId, globals.OrgPrefix)) {
		grantScope = globals.GrantScopeDescendants
	}

	var permArgs []any
	if strings.HasPrefix(scopeId, globals.ProjectPrefix) {
		// Project permissions don't have grant_scope column
		permArgs = []any{permissionId, tokenId, "test permission", grantThisScope}
	} else {
		permArgs = []any{permissionId, tokenId, "test permission", grantThisScope, grantScope}
	}

	_, err = repo.writer.Exec(ctx, insertPermissionSQL, permArgs)
	require.NoError(err)

	// Parse and insert each grant
	for _, grant := range grants {
		// Parse the grant to get canonical form
		perm, err := perms.Parse(ctx, perms.GrantTuple{
			RoleScopeId:  scopeId,
			GrantScopeId: scopeId,
			Grant:        grant,
		}, perms.WithSkipFinalValidation(true))
		require.NoError(err)

		canonicalGrant := perm.CanonicalString()

		// Insert into iam_grant lookup table (required for query JOINs)
		// The database trigger will automatically extract and set the resource type
		_, err = repo.writer.Exec(ctx, `
			insert into iam_grant (canonical_grant)
			values ($1)
			on conflict (canonical_grant) do nothing
		`, []any{canonicalGrant})
		require.NoError(err)

		// Insert the grant with both raw_grant and canonical_grant
		_, err = repo.writer.Exec(ctx, insertGrantSQL, []any{permissionId, grant, canonicalGrant})
		require.NoError(err)
	}
}
