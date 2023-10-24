// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1
package vault_test

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

func TestRepository_ListCredentialLibraries_Pagination(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	css := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 3)

	for _, cs := range css[:2] { // Leave the third store empty
		vault.TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 1)
		vault.TestSSHCertificateCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 1)
		vault.TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 1)
		vault.TestSSHCertificateCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 1)
		vault.TestSSHCertificateCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 1)
	}
	repo, err := vault.NewRepository(ctx, rw, rw, kms, sche)
	require.NoError(err)
	require.NotNil(repo)

	service, err := vault.NewLibraryService(ctx, rw, repo)
	require.NoError(err)

	for _, cs := range css[:2] {
		page1, err := service.List(ctx, cs.GetPublicId(), credential.WithLimit(2))
		require.NoError(err)
		require.Len(page1, 2)
		page2, err := service.List(ctx, cs.GetPublicId(), credential.WithLimit(2), credential.WithStartPageAfterItem(page1[1]))
		require.NoError(err)
		require.Len(page2, 2)
		for _, item := range page1 {
			assert.NotEqual(item.GetPublicId(), page2[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page2[1].GetPublicId())
		}
		page3, err := service.List(ctx, cs.GetPublicId(), credential.WithLimit(2), credential.WithStartPageAfterItem(page2[1]))
		require.NoError(err)
		require.Len(page3, 1)
		for _, item := range append(page1, page2...) {
			assert.NotEqual(item.GetPublicId(), page3[0].GetPublicId())
		}
		page4, err := service.List(ctx, cs.GetPublicId(), credential.WithLimit(2), credential.WithStartPageAfterItem(page3[0]))
		require.NoError(err)
		require.Empty(page4)
	}

	emptyPage, err := service.List(ctx, css[2].GetPublicId(), credential.WithLimit(2))
	require.NoError(err)
	require.Empty(emptyPage)
}

func TestRepository_ListDeletedLibraryIds(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	store := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	genericLibs := vault.TestCredentialLibraries(t, conn, wrapper, store.GetPublicId(), 2)
	sshLibs := vault.TestSSHCertificateCredentialLibraries(t, conn, wrapper, store.GetPublicId(), 2)
	var libs []credential.Library
	for _, lib := range genericLibs {
		libs = append(libs, lib)
	}
	for _, lib := range sshLibs {
		libs = append(libs, lib)
	}

	repo, err := vault.NewRepository(ctx, rw, rw, kms, sche)
	require.NoError(err)
	require.NotNil(repo)

	service, err := vault.NewLibraryService(ctx, rw, repo)
	require.NoError(err)

	// Expect no entries at the start
	deletedIds, ttime, err := service.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	require.Empty(deletedIds)
	// Expect transaction timestamp to be within ~10 seconds of now
	require.True(time.Now().Before(ttime.Add(10 * time.Second)))
	require.True(time.Now().After(ttime.Add(-10 * time.Second)))

	// Delete a generic library
	_, err = repo.DeleteCredentialLibrary(ctx, prj.GetPublicId(), libs[0].GetPublicId())
	require.NoError(err)

	// Expect a single entry
	deletedIds, ttime, err = service.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	require.Equal([]string{libs[0].GetPublicId()}, deletedIds)
	require.True(time.Now().Before(ttime.Add(10 * time.Second)))
	require.True(time.Now().After(ttime.Add(-10 * time.Second)))

	// Delete an ssh cert library
	_, err = repo.DeleteSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), libs[2].GetPublicId())
	require.NoError(err)

	// Expect two entries
	deletedIds, ttime, err = service.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	require.ElementsMatch([]string{libs[0].GetPublicId(), libs[2].GetPublicId()}, deletedIds)
	require.True(time.Now().Before(ttime.Add(10 * time.Second)))
	require.True(time.Now().After(ttime.Add(-10 * time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = service.ListDeletedIds(ctx, time.Now())
	require.NoError(err)
	require.Empty(deletedIds)
	require.True(time.Now().Before(ttime.Add(10 * time.Second)))
	require.True(time.Now().After(ttime.Add(-10 * time.Second)))
}

func TestRepository_EstimatedLibraryCount(t *testing.T) {
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
	store := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]

	repo, err := vault.NewRepository(ctx, rw, rw, kms, sche)
	require.NoError(err)
	require.NotNil(repo)

	service, err := vault.NewLibraryService(ctx, rw, repo)
	require.NoError(err)

	// Check total entries at start, expect 0
	numItems, err := service.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(0, numItems)

	// Create some libraries
	genericLibs := vault.TestCredentialLibraries(t, conn, wrapper, store.GetPublicId(), 2)
	sshLibs := vault.TestSSHCertificateCredentialLibraries(t, conn, wrapper, store.GetPublicId(), 2)
	var libs []credential.Library
	for _, lib := range genericLibs {
		libs = append(libs, lib)
	}
	for _, lib := range sshLibs {
		libs = append(libs, lib)
	}
	// Run analyze to update postgres meta tables
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = service.EstimatedCount(ctx)
	require.NoError(err)

	assert.Equal(4, numItems)

	// Delete a few libraries
	_, err = repo.DeleteCredentialLibrary(ctx, prj.GetPublicId(), libs[0].GetPublicId())
	require.NoError(err)
	_, err = repo.DeleteSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), libs[2].GetPublicId())
	require.NoError(err)

	// Run analyze to update postgres meta tables
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = service.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(2, numItems)
}
