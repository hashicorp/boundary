// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server_test

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/require"
)

func TestVerifyUnknownAndUnmappedWorkers(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	require.NoError(t, kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))

	serverRepo, err := server.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	workerAuthRepo, err := server.NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	// Set up resources
	var w1KeyId, w2KeyId string
	w1 := server.TestPkiWorker(t, conn, wrapper, server.WithTestPkiWorkerAuthorizedKeyId(&w1KeyId))
	_ = server.TestPkiWorker(t, conn, wrapper, server.WithTestPkiWorkerAuthorizedKeyId(&w2KeyId))
	w3 := server.TestKmsWorker(t, conn, wrapper)

	t.Run("With 1 PKI, 1 KMS and 1 unmapped worker", func(t *testing.T) {
		t.Parallel()
		authzWorkers, err := server.VerifyKnownAndUnmappedWorkers(ctx, serverRepo, workerAuthRepo, []string{w1.PublicId, w3.PublicId, "invalid-worker-id"}, []string{w2KeyId, "invalid-worker-key-id"})
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(authzWorkers.WorkerPublicIds, []string{w1.PublicId, w3.PublicId}))
		require.Empty(t, cmp.Diff(authzWorkers.UnmappedWorkerKeyIds, []string{w2KeyId}))
	})

	t.Run("missing repository", func(t *testing.T) {
		t.Parallel()
		authzWorkers, err := server.VerifyKnownAndUnmappedWorkers(ctx, nil, workerAuthRepo, []string{w1.PublicId, w3.PublicId}, []string{w2KeyId})
		require.ErrorContains(t, err, "repository is required")
		require.Nil(t, authzWorkers)
	})

	t.Run("missing worker auth repository", func(t *testing.T) {
		t.Parallel()
		authzWorkers, err := server.VerifyKnownAndUnmappedWorkers(ctx, serverRepo, nil, []string{w1.PublicId, w3.PublicId}, []string{w2KeyId})
		require.ErrorContains(t, err, "worker auth repository is required")
		require.Nil(t, authzWorkers)
	})
}
