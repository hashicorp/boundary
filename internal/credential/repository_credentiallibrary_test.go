// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialLibraryRepository_ListDeletedIds(t *testing.T) {
	t.Parallel()
	_, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	css := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 3)
	var libs []*vault.CredentialLibrary
	var sshLibs []*vault.SSHCertificateCredentialLibrary
	for _, cs := range css[:2] { // Leave the third store empty
		libs = append(libs, vault.TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 2)...)
		sshLibs = append(sshLibs, vault.TestSSHCertificateCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 2)...)
	}

	repo, err := credential.NewCredentialLibraryRepository(ctx, rw)
	require.NoError(err)
	require.NotNil(repo)
	vaultRepo, err := vault.NewRepository(ctx, rw, rw, kms, sche)
	require.NoError(err)

	// Expect no entries at the start
	deletedIds, err := repo.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	require.Empty(deletedIds)

	// Delete a vault library in the first store
	_, err = vaultRepo.DeleteCredentialLibrary(ctx, prj.GetPublicId(), libs[0].GetPublicId())
	require.NoError(err)

	// Expect a single entry
	deletedIds, err = repo.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	require.Equal([]string{libs[0].GetPublicId()}, deletedIds)

	// Delete a ssh cert library in the first store
	_, err = vaultRepo.DeleteSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), sshLibs[0].GetPublicId())
	require.NoError(err)

	// Expect two entries
	deletedIds, err = repo.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	require.Equal([]string{libs[0].GetPublicId(), sshLibs[0].GetPublicId()}, deletedIds)

	// Try again with the time set to now, expect no entries
	deletedIds, err = repo.ListDeletedIds(ctx, time.Now())
	require.NoError(err)
	require.Empty(deletedIds)
}

func TestCredentialLibraryRepository_EstimatedCount(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(err)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	css := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 3)

	repo, err := credential.NewCredentialLibraryRepository(ctx, rw)
	require.NoError(err)
	require.NotNil(repo)
	vaultRepo, err := vault.NewRepository(ctx, rw, rw, kms, sche)
	require.NoError(err)

	// Check total entries at start, expect 0
	numItems, err := repo.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(0, numItems)

	// Create some libraries
	var libs []*vault.CredentialLibrary
	var sshLibs []*vault.SSHCertificateCredentialLibrary
	for _, cs := range css[:2] { // Leave the third store empty
		libs = append(libs, vault.TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 2)...)
		sshLibs = append(sshLibs, vault.TestSSHCertificateCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 2)...)
	}
	// Run analyze to update postgres meta tables
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(8, numItems)

	// Delete a library from the first store
	_, err = vaultRepo.DeleteCredentialLibrary(ctx, prj.GetPublicId(), libs[0].GetPublicId())
	require.NoError(err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(7, numItems)

	// Delete an ssh certificate library from the second store
	_, err = vaultRepo.DeleteSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), sshLibs[2].GetPublicId())
	require.NoError(err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(6, numItems)
}

func TestCredentialLibraryRepository_Now(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	ctx := context.Background()
	repo, err := credential.NewCredentialLibraryRepository(ctx, rw)
	require.NoError(t, err)

	now, err := repo.Now(ctx)
	require.NoError(t, err)
	// Check that it's within 1 second of now according to the system
	// If this is flaky... just increase the limit 😬.
	assert.True(t, now.Before(time.Now().Add(time.Second)))
	assert.True(t, now.After(time.Now().Add(-time.Second)))
}
