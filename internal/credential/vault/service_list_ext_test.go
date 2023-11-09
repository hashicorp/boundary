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

type fakeWriter struct {
	db.Writer
}

func TestNewLibraryListingService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		got, err := vault.NewLibraryListingService(ctx, &fakeWriter{}, &vault.Repository{})
		require.NoError(t, err)
		require.NotNil(t, got)
	})
	t.Run("nil-writer", func(t *testing.T) {
		t.Parallel()
		_, err := vault.NewLibraryListingService(ctx, nil, &vault.Repository{})
		require.Error(t, err)
	})
	t.Run("nil-interface-writer", func(t *testing.T) {
		t.Parallel()
		_, err := vault.NewLibraryListingService(ctx, (*fakeWriter)(nil), &vault.Repository{})
		require.Error(t, err)
	})
	t.Run("nil-repo", func(t *testing.T) {
		t.Parallel()
		_, err := vault.NewLibraryListingService(ctx, &fakeWriter{}, nil)
		require.Error(t, err)
	})
}

func TestLibraryListingService_List(t *testing.T) {
	t.Parallel()
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
	require.NoError(t, err)
	require.NotNil(t, repo)

	service, err := vault.NewLibraryListingService(ctx, rw, repo)
	require.NoError(t, err)

	t.Run("empty credential store id", func(t *testing.T) {
		_, err := service.List(ctx, "")
		require.ErrorContains(t, err, "missing credential store id")
	})

	t.Run("pagination", func(t *testing.T) {
		for _, cs := range css[:2] {
			page1, err := service.List(ctx, cs.GetPublicId(), credential.WithLimit(2))
			require.NoError(t, err)
			require.Len(t, page1, 2)
			page2, err := service.List(ctx, cs.GetPublicId(), credential.WithLimit(2), credential.WithStartPageAfterItem(page1[1]))
			require.NoError(t, err)
			require.Len(t, page2, 2)
			for _, item := range page1 {
				assert.NotEqual(t, item.GetPublicId(), page2[0].GetPublicId())
				assert.NotEqual(t, item.GetPublicId(), page2[1].GetPublicId())
			}
			page3, err := service.List(ctx, cs.GetPublicId(), credential.WithLimit(2), credential.WithStartPageAfterItem(page2[1]))
			require.NoError(t, err)
			require.Len(t, page3, 1)
			for _, item := range append(page1, page2...) {
				assert.NotEqual(t, item.GetPublicId(), page3[0].GetPublicId())
			}
			page4, err := service.List(ctx, cs.GetPublicId(), credential.WithLimit(2), credential.WithStartPageAfterItem(page3[0]))
			require.NoError(t, err)
			require.Empty(t, page4)
		}

		emptyPage, err := service.List(ctx, css[2].GetPublicId(), credential.WithLimit(2))
		require.NoError(t, err)
		require.Empty(t, emptyPage)
	})
}

func TestLibraryListingService_ListDeletedIds(t *testing.T) {
	t.Parallel()
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
	require.NoError(t, err)
	require.NotNil(t, repo)

	service, err := vault.NewLibraryListingService(ctx, rw, repo)
	require.NoError(t, err)

	t.Run("missing since", func(t *testing.T) {
		_, _, err := service.ListDeletedIds(ctx, time.Time{})
		require.ErrorContains(t, err, "missing since")
	})

	t.Run("listing", func(t *testing.T) {
		// Expect no entries at the start
		deletedIds, ttime, err := service.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
		require.NoError(t, err)
		require.Empty(t, deletedIds)
		// Expect transaction timestamp to be within ~10 seconds of now
		require.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		require.True(t, time.Now().After(ttime.Add(-10*time.Second)))

		// Delete a generic library
		_, err = repo.DeleteCredentialLibrary(ctx, prj.GetPublicId(), libs[0].GetPublicId())
		require.NoError(t, err)

		// Expect a single entry
		deletedIds, ttime, err = service.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
		require.NoError(t, err)
		require.Equal(t, []string{libs[0].GetPublicId()}, deletedIds)
		require.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		require.True(t, time.Now().After(ttime.Add(-10*time.Second)))

		// Delete an ssh cert library
		_, err = repo.DeleteSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), libs[2].GetPublicId())
		require.NoError(t, err)

		// Expect two entries
		deletedIds, ttime, err = service.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
		require.NoError(t, err)
		require.ElementsMatch(t, []string{libs[0].GetPublicId(), libs[2].GetPublicId()}, deletedIds)
		require.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		require.True(t, time.Now().After(ttime.Add(-10*time.Second)))

		// Try again with the time set to now, expect no entries
		deletedIds, ttime, err = service.ListDeletedIds(ctx, time.Now())
		require.NoError(t, err)
		require.Empty(t, deletedIds)
		require.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		require.True(t, time.Now().After(ttime.Add(-10*time.Second)))
	})
}

func TestLibraryListingService_EstimatedCount(t *testing.T) {
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

	service, err := vault.NewLibraryListingService(ctx, rw, repo)
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
