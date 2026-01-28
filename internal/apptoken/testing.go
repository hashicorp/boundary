// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"crypto/rand"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/scope"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testPermission struct {
	GrantScope  string
	GrantThis   bool
	Description string
	Scopes      []string
	Grants      []string
}

// TestRepo creates a repository for AppToken testing.
func TestRepo(t testing.TB, conn *db.DB, rootWrapper wrapping.Wrapper, opt ...Option) *Repository {
	t.Helper()
	ctx := t.Context()
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
	publicId, err := db.NewPublicId(t.Context(), prefix)
	require.NoError(t, err)
	return publicId
}

// TestAppToken creates an app token for testing with the specified grants.
// TODO: Implement TestAppToken once AppToken functionality is added
func TestAppToken(t *testing.T, repo *Repository, scopeId string, user *iam.User, timeToStaleSeconds uint32, expirationTime *timestamp.Timestamp, grants []string, grantThisScope bool, grantScope string) *AppToken {
	t.Helper()

	testToken := &AppToken{
		PublicId:           testPublicId(t, "apt_"),
		ScopeId:            scopeId,
		Description:        "test app token",
		CreatedByUserId:    user.PublicId,
		TimeToStaleSeconds: timeToStaleSeconds,
		ExpirationTime:     expirationTime,
	}
	tempTestAddGrants(t, repo, testToken, grants, grantThisScope, grantScope)
	return testToken
}

// tempTestAddGrants is a temporary test function to add grants to the database for testing
// TODO: Replace with proper AppToken creation function once AppToken functionality is added
func tempTestAddGrants(t *testing.T, repo *Repository, token *AppToken, grants []string, grantThisScope bool, grantScope string) {
	t.Helper()
	ctx := t.Context()
	require := require.New(t)

	// Determine which table to insert into based on scope prefix
	var insertTokenSQL, insertPermissionSQL string
	insertGrantSQL := `
            insert into app_token_permission_grant (permission_id, raw_grant, canonical_grant)
            values ($1, $2, $3)
        `

	switch {
	case strings.HasPrefix(token.ScopeId, globals.GlobalPrefix):
		insertTokenSQL = `
			insert into app_token_global (public_id, scope_id, name, description, created_by_user_id, time_to_stale_seconds, expiration_time)
			values ($1, $2, $3, $4, $5, $6, $7)
		`
		insertPermissionSQL = `
            insert into app_token_permission_global (private_id, app_token_id, description, grant_this_scope, grant_scope)
            values ($1, $2, $3, $4, $5)
        `

	case strings.HasPrefix(token.ScopeId, globals.OrgPrefix):
		insertTokenSQL = `
			insert into app_token_org (public_id, scope_id, name, description, created_by_user_id, time_to_stale_seconds, expiration_time)
			values ($1, $2, $3, $4, $5, $6, $7)
		`
		insertPermissionSQL = `
            insert into app_token_permission_org (private_id, app_token_id, description, grant_this_scope, grant_scope)
            values ($1, $2, $3, $4, $5)
        `
	case strings.HasPrefix(token.ScopeId, globals.ProjectPrefix):
		insertTokenSQL = `
			insert into app_token_project (public_id, scope_id, name, description, created_by_user_id, time_to_stale_seconds, expiration_time)
			values ($1, $2, $3, $4, $5, $6, $7)
		`
		insertPermissionSQL = `
            insert into app_token_permission_project (private_id, app_token_id, description, grant_this_scope)
            values ($1, $2, $3, $4)
        `
	default:
		t.Fatalf("invalid scope id: %s", token.ScopeId)
	}

	// Insert the app token
	name := fmt.Sprintf("Test App Token %s", token.PublicId)
	_, err := repo.writer.Exec(ctx, insertTokenSQL, []any{token.PublicId, token.ScopeId, name, "test app token", token.CreatedByUserId, token.TimeToStaleSeconds, token.ExpirationTime})
	require.NoError(err)

	// Create a permission for this token
	permissionId := testPublicId(t, "aptp_")

	// Default to 'descendants' if not specified for global/org scopes
	if grantScope == "" && (strings.HasPrefix(token.ScopeId, globals.GlobalPrefix) || strings.HasPrefix(token.ScopeId, globals.OrgPrefix)) {
		grantScope = globals.GrantScopeDescendants
	}

	var permArgs []any
	if strings.HasPrefix(token.ScopeId, globals.ProjectPrefix) {
		// Project permissions don't have grant_scope column
		permArgs = []any{permissionId, token.PublicId, "test permission", grantThisScope}
	} else {
		permArgs = []any{permissionId, token.PublicId, "test permission", grantThisScope, grantScope}
	}

	_, err = repo.writer.Exec(ctx, insertPermissionSQL, permArgs)
	require.NoError(err)

	// Parse and insert each grant
	for _, grant := range grants {
		// Parse the grant to get canonical form
		perm, err := perms.Parse(ctx, perms.GrantTuple{
			RoleScopeId:  token.ScopeId,
			GrantScopeId: token.ScopeId,
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

// these will eventually expand to cover org and proj
func testCheckPermission(t *testing.T, repo *Repository, appTokenId string, scopeId string, wantPerms []testPermission) error {
	assert := assert.New(t)

	var permQuery string
	// Map to aggregate results by permission_id
	permMap := make(map[string]*testPermission)

	switch {
	case strings.HasPrefix(scopeId, globals.GlobalPrefix):
		permQuery = `
            select atp.private_id as permission_id,
                   atpg.canonical_grant,
                   atpglobal.description,
                   atpglobal.grant_this_scope,
                   atpglobal.grant_scope as grant_scope,
                   atpgios.scope_id as individual_org_scope_id,
                   atpgips.scope_id as individual_project_scope_id
              from app_token_permission atp
         left join app_token_permission_grant atpg on atp.private_id = atpg.permission_id
         left join app_token_permission_global atpglobal on atp.private_id = atpglobal.private_id
         left join app_token_permission_global_individual_org_grant_scope atpgios on atp.private_id = atpgios.permission_id
         left join app_token_permission_global_individual_project_grant_scope atpgips on atp.private_id = atpgips.permission_id
             where atp.app_token_id = $1
          order by atp.private_id, atpg.canonical_grant, atpgios.scope_id, atpgips.scope_id
        `
		rows, err := repo.reader.Query(t.Context(), permQuery, []any{appTokenId})
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var permissionId, canonicalGrant, permissionGrantScope string
			// *string for columns that can be null from left joins
			var description, individualOrgScopeId, individualProjectScopeId *string
			var grantThisScope bool

			if err := rows.Scan(
				&permissionId,
				&canonicalGrant,
				&description,
				&grantThisScope,
				&permissionGrantScope,
				&individualOrgScopeId,
				&individualProjectScopeId,
			); err != nil {
				return err
			}

			// Get or create the testPermission for this permission_id
			perm, exists := permMap[permissionId]
			if !exists {
				perm = &testPermission{
					Description: *description,
					GrantThis:   grantThisScope,
					GrantScope:  permissionGrantScope,
					Grants:      []string{},
					Scopes:      []string{},
				}
				permMap[permissionId] = perm
			}

			// Add grant if present and not already added
			if !slices.Contains(perm.Grants, canonicalGrant) {
				perm.Grants = append(perm.Grants, canonicalGrant)
			}

			// Add org scope if present and not already added
			if individualOrgScopeId != nil && !slices.Contains(perm.Scopes, *individualOrgScopeId) {
				perm.Scopes = append(perm.Scopes, *individualOrgScopeId)
			}

			// Add project scope if present and not already added
			if individualProjectScopeId != nil && !slices.Contains(perm.Scopes, *individualProjectScopeId) {
				perm.Scopes = append(perm.Scopes, *individualProjectScopeId)
			}
		}
	case strings.HasPrefix(scopeId, globals.OrgPrefix):
		permQuery = `
            select atp.private_id as permission_id,
                   atpg.canonical_grant,
                   atpo.description,
                   atpo.grant_this_scope,
                   atpo.grant_scope as grant_scope,
                   atpis.scope_id as individual_scope_id
              from app_token_permission atp
         left join app_token_permission_grant atpg on atp.private_id = atpg.permission_id
         left join app_token_permission_org atpo on atp.private_id = atpo.private_id
         left join app_token_permission_org_individual_grant_scope atpis on atp.private_id = atpis.permission_id
             where atp.app_token_id = $1
          order by atp.private_id, atpg.canonical_grant, atpis.scope_id
        `
		rows, err := repo.reader.Query(t.Context(), permQuery, []any{appTokenId})
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var permissionId, canonicalGrant, permissionGrantScope string
			// *string for columns that can be null from left joins
			var description, individualScopeId *string
			var grantThisScope bool

			if err := rows.Scan(
				&permissionId,
				&canonicalGrant,
				&description,
				&grantThisScope,
				&permissionGrantScope,
				&individualScopeId,
			); err != nil {
				return err
			}

			// Get or create the testPermission for this permission_id
			perm, exists := permMap[permissionId]
			if !exists {
				perm = &testPermission{
					Description: *description,
					GrantThis:   grantThisScope,
					GrantScope:  permissionGrantScope,
					Grants:      []string{},
					Scopes:      []string{},
				}
				permMap[permissionId] = perm
			}

			// Add grant if present and not already added
			if !slices.Contains(perm.Grants, canonicalGrant) {
				perm.Grants = append(perm.Grants, canonicalGrant)
			}

			// Add org scope if present and not already added
			if individualScopeId != nil && !slices.Contains(perm.Scopes, *individualScopeId) {
				perm.Scopes = append(perm.Scopes, *individualScopeId)
			}
		}
	case strings.HasPrefix(scopeId, globals.ProjectPrefix):
		permQuery = `
            select atp.private_id as permission_id,
                   atpg.canonical_grant,
                   atpp.description,
                   atpp.grant_this_scope
              from app_token_permission atp
         left join app_token_permission_grant atpg on atp.private_id = atpg.permission_id
         left join app_token_permission_project atpp on atp.private_id = atpp.private_id
             where atp.app_token_id = $1
          order by atp.private_id, atpg.canonical_grant
        `
		rows, err := repo.reader.Query(t.Context(), permQuery, []any{appTokenId})
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var permissionId, canonicalGrant string
			// *string for columns that can be null from left joins
			var description *string
			var grantThisScope bool

			if err := rows.Scan(
				&permissionId,
				&canonicalGrant,
				&description,
				&grantThisScope,
			); err != nil {
				return err
			}

			// Get or create the testPermission for this permission_id
			perm, exists := permMap[permissionId]
			if !exists {
				perm = &testPermission{
					Description: *description,
					GrantThis:   grantThisScope,
					Grants:      []string{},
				}
				permMap[permissionId] = perm
			}

			// Add grant if present and not already added
			if !slices.Contains(perm.Grants, canonicalGrant) {
				perm.Grants = append(perm.Grants, canonicalGrant)
			}
		}

	default:
		return fmt.Errorf("unsupported scope id prefix for permission check: %s", scopeId)
	}

	// Convert map to slice
	var grantedPerms []testPermission
	for _, perm := range permMap {
		grantedPerms = append(grantedPerms, *perm)
	}

	// Sort inner slices for all permissions
	for i := range wantPerms {
		sort.Strings(wantPerms[i].Grants)
		sort.Strings(wantPerms[i].Scopes)
	}
	for i := range grantedPerms {
		sort.Strings(grantedPerms[i].Grants)
		sort.Strings(grantedPerms[i].Scopes)
	}

	assert.ElementsMatch(wantPerms, grantedPerms)
	return nil
}

func testCheckAppTokenCipher(t *testing.T, repo *Repository, appTokenId string) error {
	assert := assert.New(t)
	cipherQuery := `
        select token,
               key_id
          from app_token_cipher
         where app_token_id = $1
    `
	rows, err := repo.reader.Query(t.Context(), cipherQuery, []any{appTokenId})
	if err != nil {
		return err
	}
	defer rows.Close()

	var token, keyId string
	for rows.Next() {
		if err := rows.Scan(&token, &keyId); err != nil {
			return err
		}
	}
	assert.NotEmpty(token)
	assert.NotEmpty(keyId)
	return nil
}

// tempTestRevokeGlobalAppToken is a temporary test function to revoke a global app token
// TODO: Replace with proper AppToken.Revoke function once added
func tempTestRevokeGlobalAppToken(t *testing.T, repo *Repository, tokenId string) {
	t.Helper()
	ctx := t.Context()
	require := require.New(t)

	_, err := repo.writer.Exec(ctx, `
		update app_token_global
		set revoked = true, update_time = now()
		where public_id = $1
	`, []any{tokenId})
	require.NoError(err)
}

// tempTestDeleteAppToken is a temporary test function to delete an app token from the database
// TODO: Replace with proper AppToken deletion function once added
func tempTestDeleteAppToken(t *testing.T, repo *Repository, tokenId string, scopeId string) {
	t.Helper()
	ctx := t.Context()
	require := require.New(t)

	var deleteSQL string
	switch {
	case strings.HasPrefix(scopeId, globals.GlobalPrefix):
		deleteSQL = `delete from app_token_global where public_id = $1;`
	case strings.HasPrefix(scopeId, globals.OrgPrefix):
		deleteSQL = `delete from app_token_org where public_id = $1;`
	case strings.HasPrefix(scopeId, globals.ProjectPrefix):
		deleteSQL = `delete from app_token_project where public_id = $1;`
	default:
		t.Fatalf("invalid scope id: %s", scopeId)
	}

	_, err := repo.writer.Exec(ctx, deleteSQL, []any{tokenId})
	require.NoError(err)
}

// testUpdateAppToken is a test helper to update fields on an app token directly in the database
func testUpdateAppToken(t *testing.T, repo *Repository, tokenId string, scopeId string, fields map[string]any) {
	t.Helper()
	ctx := t.Context()
	require := require.New(t)

	var updateSQL strings.Builder
	updateSQL.WriteString("update ")

	switch {
	case strings.HasPrefix(scopeId, globals.GlobalPrefix):
		updateSQL.WriteString("app_token_global ")
	case strings.HasPrefix(scopeId, globals.OrgPrefix):
		updateSQL.WriteString("app_token_org ")
	case strings.HasPrefix(scopeId, globals.ProjectPrefix):
		updateSQL.WriteString("app_token_project ")
	default:
		t.Fatalf("invalid scope id: %s", scopeId)
	}

	updateSQL.WriteString("set ")

	args := []any{}
	i := 1
	for field, value := range fields {
		if i > 1 {
			updateSQL.WriteString(", ")
		}
		updateSQL.WriteString(fmt.Sprintf("%s = $%d", field, i))
		args = append(args, value)
		i++
	}

	updateSQL.WriteString(fmt.Sprintf("where public_id = $%d", i))
	args = append(args, tokenId)

	_, err := repo.writer.Exec(ctx, updateSQL.String(), args)
	require.NoError(err)
}
