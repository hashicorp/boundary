// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialRepository_ListDeletedIds(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	store := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	obj, _, err := static.TestJsonObject()
	assert.NoError(err)
	jsonCreds := static.TestJsonCredentials(t, conn, wrapper, store.GetPublicId(), prj.GetPublicId(), obj, 2)
	sshCreds := static.TestSshPrivateKeyCredentials(t, conn, wrapper, "username", static.TestSshPrivateKeyPem, store.GetPublicId(), prj.GetPublicId(), 2)
	pwCreds := static.TestUsernamePasswordCredentials(t, conn, wrapper, "username", "testpassword", store.GetPublicId(), prj.GetPublicId(), 2)

	repo, err := credential.NewCredentialRepository(ctx, rw)
	require.NoError(err)
	require.NotNil(repo)
	staticRepo, err := static.NewRepository(ctx, rw, rw, kms)
	require.NoError(err)

	// Expect no entries at the start
	deletedIds, err := repo.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	require.Empty(deletedIds)

	// Delete a json credential
	_, err = staticRepo.DeleteCredential(ctx, prj.GetPublicId(), jsonCreds[0].GetPublicId())
	require.NoError(err)

	// Expect one entry
	deletedIds, err = repo.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	assert.Equal([]string{jsonCreds[0].GetPublicId()}, deletedIds)

	// Delete a ssh credential
	_, err = staticRepo.DeleteCredential(ctx, prj.GetPublicId(), sshCreds[0].GetPublicId())
	require.NoError(err)

	// Expect two entries
	deletedIds, err = repo.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	assert.Equal([]string{jsonCreds[0].GetPublicId(), sshCreds[0].GetPublicId()}, deletedIds)

	// Delete a pw credential
	_, err = staticRepo.DeleteCredential(ctx, prj.GetPublicId(), pwCreds[0].GetPublicId())
	require.NoError(err)

	// Expect three entries
	deletedIds, err = repo.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	assert.Equal([]string{jsonCreds[0].GetPublicId(), sshCreds[0].GetPublicId(), pwCreds[0].GetPublicId()}, deletedIds)

	// Try again with the time set to now, expect no entries
	deletedIds, err = repo.ListDeletedIds(ctx, time.Now())
	require.NoError(err)
	require.Empty(deletedIds)
}

func TestCredentialRepository_EstimatedCount(t *testing.T) {
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
	staticStore := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	vaultStore := vault.TestCredentialStore(t, conn, wrapper, prj.GetPublicId(), "http://some-vault-addr.com", "some-token", "some-accessor")
	vaultLib := vault.TestCredentialLibraries(t, conn, wrapper, vaultStore.GetPublicId(), 1)[0]
	sess := session.TestSession(t, conn, wrapper, session.TestSessionParams(t, conn, wrapper, iam.TestRepo(t, conn, wrapper)))

	repo, err := credential.NewCredentialRepository(ctx, rw)
	require.NoError(err)
	require.NotNil(repo)
	staticRepo, err := static.NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	vaultRepo, err := vault.NewRepository(ctx, rw, rw, kms, sche)
	require.NoError(err)

	// Check total entries at start, expect 0
	numItems, err := repo.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(0, numItems)

	// Create some credentials
	_ = vault.TestCredentials(t, conn, wrapper, vaultLib.GetPublicId(), sess.GetPublicId(), 2)
	obj, _, err := static.TestJsonObject()
	assert.NoError(err)
	jsonCreds := static.TestJsonCredentials(t, conn, wrapper, staticStore.GetPublicId(), prj.GetPublicId(), obj, 2)
	sshCreds := static.TestSshPrivateKeyCredentials(t, conn, wrapper, "username", static.TestSshPrivateKeyPem, staticStore.GetPublicId(), prj.GetPublicId(), 2)
	pwCreds := static.TestUsernamePasswordCredentials(t, conn, wrapper, "username", "testpassword", staticStore.GetPublicId(), prj.GetPublicId(), 2)
	// Run analyze to update postgres meta tables
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(8, numItems)

	// Delete a json credential
	_, err = staticRepo.DeleteCredential(ctx, prj.GetPublicId(), jsonCreds[0].GetPublicId())
	require.NoError(err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(7, numItems)

	// Delete a ssh credential
	_, err = staticRepo.DeleteCredential(ctx, prj.GetPublicId(), sshCreds[0].GetPublicId())
	require.NoError(err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(6, numItems)

	// Delete a pw credential
	_, err = staticRepo.DeleteCredential(ctx, prj.GetPublicId(), pwCreds[0].GetPublicId())
	require.NoError(err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(5, numItems)

	// Vault credentials can't be deleted, only revoked. This doesn't affect the count.
	err = vaultRepo.Revoke(ctx, sess.GetPublicId())
	require.NoError(err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(5, numItems)
}

func TestCredentialRepository_Now(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	ctx := context.Background()
	repo, err := credential.NewCredentialRepository(ctx, rw)
	require.NoError(t, err)

	now, err := repo.Now(ctx)
	require.NoError(t, err)
	// Check that it's within 1 second of now according to the system
	// If this is flaky... just increase the limit 😬.
	assert.True(t, now.Before(time.Now().Add(time.Second)))
	assert.True(t, now.After(time.Now().Add(-time.Second)))
}
