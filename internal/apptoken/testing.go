// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/globals"
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
func testCheckPermission(t *testing.T, repo *Repository, appTokenId string, scopeId string, wantPerms []testPermission) error {
	assert := assert.New(t)

	var permQuery string
	switch {
	case strings.HasPrefix(scopeId, globals.GlobalPrefix):
		permQuery = `
			select grant_scope, grant_this_scope, description from app_token_permission_global where app_token_id = $1
		`
	case strings.HasPrefix(scopeId, globals.OrgPrefix):
		permQuery = `
			select grant_scope, grant_this_scope, description from app_token_permission_org where app_token_id = $1
		`
	case strings.HasPrefix(scopeId, globals.ProjectPrefix):
		permQuery = `
			select '', grant_this_scope, description from app_token_permission_project where app_token_id = $1
		`
	default:
		return fmt.Errorf("unknown scope id prefix: %s", scopeId)
	}

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
			GrantScope:  grantScope,
			GrantThis:   grantThisScope,
			Description: description,
		})
	}
	assert.Equal(wantPerms, grantedPerms)
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
	permGlobalIndivOrgGrantsQuery := `
			select scope_id from app_token_permission_global_individual_org_grant_scope where permission_id in (
				select private_id from app_token_permission where app_token_id = $1
			)
		`
	permGlobalIndivProjectGrantsQuery := `
			select scope_id from app_token_permission_global_individual_project_grant_scope where permission_id in (
				select private_id from app_token_permission where app_token_id = $1
			)
		`
	permOrgIndivGrantsQuery := `
			select scope_id from app_token_permission_org_individual_grant_scope where permission_id in (
				select private_id from app_token_permission where app_token_id = $1
			)
		`
	rowsGlobalIndOrg, err := repo.reader.Query(context.Background(), permGlobalIndivOrgGrantsQuery, []any{appTokenId})
	if err != nil {
		return err
	}
	defer rowsGlobalIndOrg.Close()

	for rowsGlobalIndOrg.Next() {
		var scopeId string
		if err := rowsGlobalIndOrg.Scan(&scopeId); err != nil {
			return err
		}
		foundScopes = append(foundScopes, scopeId)
	}

	rowsGlobalIndProj, err := repo.reader.Query(context.Background(), permGlobalIndivProjectGrantsQuery, []any{appTokenId})
	if err != nil {
		return err
	}
	defer rowsGlobalIndProj.Close()
	for rowsGlobalIndProj.Next() {
		var scopeId string
		if err := rowsGlobalIndProj.Scan(&scopeId); err != nil {
			return err
		}
		foundScopes = append(foundScopes, scopeId)
	}

	rowsOrgInd, err := repo.reader.Query(context.Background(), permOrgIndivGrantsQuery, []any{appTokenId})
	if err != nil {
		return err
	}
	defer rowsOrgInd.Close()
	for rowsOrgInd.Next() {
		var scopeId string
		if err := rowsOrgInd.Scan(&scopeId); err != nil {
			return err
		}
		foundScopes = append(foundScopes, scopeId)
	}

	assert.ElementsMatch(wantScopes, foundScopes)
	return nil
}
