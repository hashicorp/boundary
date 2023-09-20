// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListDeletedIds(t *testing.T) {
	testConn, _ := db.TestSetup(t, "postgres")
	rw := db.New(testConn)
	testWrapper := db.TestWrapper(t)

	ctx := context.Background()
	testKms := kms.TestKms(t, testConn, testWrapper)
	iamRepo := iam.TestRepo(t, testConn, testWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := testKms.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	repo, err := auth.NewAccountRepository(ctx, rw)
	assert.NoError(t, err)

	ldapRepo, err := ldap.NewRepository(ctx, rw, rw, testKms)
	assert.NoError(t, err)

	// Expect no entries at the start
	deletedIds, err := repo.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Empty(t, deletedIds)

	// Create and delete account
	authMethod := ldap.TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
	account := ldap.TestAccount(t, testConn, authMethod, "create-success")
	_, err = ldapRepo.DeleteAccount(ctx, account.GetPublicId())
	require.NoError(t, err)

	// Expect a single entry
	deletedIds, err = repo.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Equal(t, []string{account.PublicId}, deletedIds)

	// Try again with the time set to now, expect no entries
	deletedIds, err = repo.ListDeletedIds(ctx, time.Now())
	require.NoError(t, err)
	require.Empty(t, deletedIds)
}

func TestGetTotalItems(t *testing.T) {
	testConn, _ := db.TestSetup(t, "postgres")
	rw := db.New(testConn)
	testWrapper := db.TestWrapper(t)

	ctx := context.Background()
	sqlDb, err := testConn.SqlDB(ctx)
	require.NoError(t, err)
	testKms := kms.TestKms(t, testConn, testWrapper)
	iamRepo := iam.TestRepo(t, testConn, testWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := testKms.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	repo, err := auth.NewAccountRepository(ctx, rw)
	assert.NoError(t, err)

	ldapRepo, err := ldap.NewRepository(ctx, rw, rw, testKms)
	assert.NoError(t, err)

	// Check total entries at start, expect 0
	numItems, err := repo.GetTotalItems(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	// Create an ldap account
	ldapAuthMethod := ldap.TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
	ldapAccount := ldap.TestAccount(t, testConn, ldapAuthMethod, "create-success")

	// create 3 pw accounts
	pwAuthMethods := password.TestAuthMethods(t, testConn, org.GetPublicId(), 3)
	_ = password.TestMultipleAccounts(t, testConn, pwAuthMethods[0].GetPublicId(), 3)

	// create an oidc account
	oidcAuthMethod := oidc.TestAuthMethod(
		t, testConn, databaseWrapper, org.PublicId, "active-private",
		"alice-rp", "fido",
		oidc.WithSigningAlgs("RS256"),
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice1.com")[0]),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	_ = oidc.TestAccount(t, testConn, oidcAuthMethod, "create-success")

	// Run analyze to update postgres meta tables
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	// 1 ldap + 3 pw + 1 oidc = 5 accounts
	numItems, err = repo.GetTotalItems(ctx)
	require.NoError(t, err)
	assert.Equal(t, 5, numItems)

	// // Delete the ldap account, expect 4
	_, err = ldapRepo.DeleteAccount(ctx, ldapAccount.GetPublicId())
	require.NoError(t, err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	numItems, err = repo.GetTotalItems(ctx)
	require.NoError(t, err)
	assert.Equal(t, 4, numItems)
}

func TestNow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	repo, err := auth.NewAccountRepository(ctx, rw)
	assert.NoError(t, err)

	now, err := repo.Now(ctx)
	require.NoError(t, err)
	// Check that it's within 1 second of now according to the system
	// If this is flaky... just increase the limit 😬.
	assert.True(t, now.Before(time.Now().Add(time.Second)))
	assert.True(t, now.After(time.Now().Add(-time.Second)))
}
