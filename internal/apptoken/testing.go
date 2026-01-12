// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testPermission struct {
	GrantScope  string
	GrantThis   bool
	Description string
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

// these will eventually expand to cover org and proj
func testCheckPermissionGlobal(t *testing.T, repo *Repository, appTokenId string, wantPerms []testPermission) error {
	assert := assert.New(t)

	permQuery := `
		select grant_scope,
		       grant_this_scope,
			   description
		  from app_token_permission_global
		 where app_token_id = $1
	`
	rows, err := repo.reader.Query(context.Background(), permQuery, []any{appTokenId})
	if err != nil {
		return err
	}
	defer rows.Close()

	var grantedPerms []testPermission
	for rows.Next() {
		var grantScope string
		var grantThisScope bool
		var description string
		if err := rows.Scan(&grantScope, &grantThisScope, &description); err != nil {
			return err
		}
		grantedPerms = append(grantedPerms, testPermission{
			Description: description,
			GrantScope:  grantScope,
			GrantThis:   grantThisScope,
		})
	}
	assert.Equal(wantPerms, grantedPerms)
	return nil
}

func testCheckPermissionGrants(t *testing.T, repo *Repository, appTokenId string, wantGrants []string) error {
	assert := assert.New(t)
	permGrantsQuery := `
		select permission_id,
		   	   canonical_grant,
			   raw_grant
		  from app_token_permission_grant
		 where permission_id in (
			select private_id
			  from app_token_permission
			 where app_token_id = $1
		)
	`
	rows, err := repo.reader.Query(context.Background(), permGrantsQuery, []any{appTokenId})
	if err != nil {
		return err
	}
	defer rows.Close()

	var foundGrants []string
	for rows.Next() {
		var permissionId, canonicalGrant, rawGrant string
		if err := rows.Scan(&permissionId, &canonicalGrant, &rawGrant); err != nil {
			return err
		}
		foundGrants = append(foundGrants, canonicalGrant)
	}
	assert.ElementsMatch(wantGrants, foundGrants)
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
	rows, err := repo.reader.Query(context.Background(), cipherQuery, []any{appTokenId})
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

func testCheckAppTokenIndividualPermissionGrants(t *testing.T, repo *Repository, appTokenId string, wantScopes []string) error {
	assert := assert.New(t)
	var foundScopes []string
	permIndivOrgGrantsQuery := `
			select scope_id
			  from app_token_permission_global_individual_org_grant_scope where permission_id in (
				select private_id
				  from app_token_permission
				 where app_token_id = $1
			)
		`
	permIndivProjectGrantsQuery := `
			select scope_id
			  from app_token_permission_global_individual_project_grant_scope where permission_id in (
				select private_id
				  from app_token_permission
				 where app_token_id = $1
			)
		`
	rows, err := repo.reader.Query(context.Background(), permIndivOrgGrantsQuery, []any{appTokenId})
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var scopeId string
		if err := rows.Scan(&scopeId); err != nil {
			return err
		}
		foundScopes = append(foundScopes, scopeId)
	}

	rows2, err := repo.reader.Query(context.Background(), permIndivProjectGrantsQuery, []any{appTokenId})
	if err != nil {
		return err
	}
	defer rows2.Close()
	for rows2.Next() {
		var scopeId string
		if err := rows2.Scan(&scopeId); err != nil {
			return err
		}
		foundScopes = append(foundScopes, scopeId)
	}

	assert.ElementsMatch(wantScopes, foundScopes)
	return nil
}

// these will eventually expand to cover org and proj
func testCheckPermissionGlobal(t *testing.T, repo *Repository, appTokenId string, wantPerms []testPermission) error {
	assert := assert.New(t)

	permQuery := `
		select grant_scope, grant_this_scope from app_token_permission_global where app_token_id = $1
	`
	rows, err := repo.reader.Query(context.Background(), permQuery, []any{appTokenId})
	if err != nil {
		return err
	}
	defer rows.Close()

	var grantedPerms []testPermission
	for rows.Next() {
		var grantScope string
		var grantThisScope bool
		if err := rows.Scan(&grantScope, &grantThisScope); err != nil {
			return err
		}
		grantedPerms = append(grantedPerms, testPermission{
			GrantScope: grantScope,
			GrantThis:  grantThisScope,
		})
	}
	assert.Equal(grantedPerms, wantPerms)
	return nil
}

func testCheckPermissionGrants(t *testing.T, repo *Repository, appTokenId string, wantGrants []string) error {
	assert := assert.New(t)
	permGrantsQuery := `
		select permission_id, canonical_grant, raw_grant from app_token_permission_grant where permission_id in (
			select private_id from app_token_permission where app_token_id = $1
		)
	`
	rows, err := repo.reader.Query(context.Background(), permGrantsQuery, []any{appTokenId})
	if err != nil {
		return err
	}
	defer rows.Close()

	var foundGrants []string
	for rows.Next() {
		var permissionId, canonicalGrant, rawGrant string
		if err := rows.Scan(&permissionId, &canonicalGrant, &rawGrant); err != nil {
			return err
		}
		foundGrants = append(foundGrants, canonicalGrant)
	}
	assert.ElementsMatch(wantGrants, foundGrants)
	return nil
}

func testCheckAppTokenCipher(t *testing.T, repo *Repository, appTokenId string) error {
	assert := assert.New(t)
	cipherQuery := `
		select token, key_id from app_token_cipher where app_token_id = $1
	`
	rows, err := repo.reader.Query(context.Background(), cipherQuery, []any{appTokenId})
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

func testCheckAppTokenIndividualPermissionGrants(t *testing.T, repo *Repository, appTokenId string, wantScopes []string) error {
	assert := assert.New(t)
	var foundScopes []string
	permIndivOrgGrantsQuery := `
			select scope_id from app_token_permission_global_individual_org_grant_scope where permission_id in (
				select private_id from app_token_permission where app_token_id = $1
			)
		`
	permIndivProjectGrantsQuery := `
			select scope_id from app_token_permission_global_individual_project_grant_scope where permission_id in (
				select private_id from app_token_permission where app_token_id = $1
			)
		`
	rows, err := repo.reader.Query(context.Background(), permIndivOrgGrantsQuery, []any{appTokenId})
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var scopeId string
		if err := rows.Scan(&scopeId); err != nil {
			return err
		}
		foundScopes = append(foundScopes, scopeId)
	}

	rows2, err := repo.reader.Query(context.Background(), permIndivProjectGrantsQuery, []any{appTokenId})
	if err != nil {
		return err
	}
	defer rows2.Close()
	for rows2.Next() {
		var scopeId string
		if err := rows2.Scan(&scopeId); err != nil {
			return err
		}
		foundScopes = append(foundScopes, scopeId)
	}

	assert.ElementsMatch(wantScopes, foundScopes)
	return nil
}
