// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestTestKmsWorker(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	const (
		name        = "test name"
		description = "test description"
		address     = "test address"
	)
	tWorker := TestKmsWorker(t, conn, wrapper, WithName(name), WithDescription(description), WithAddress(address), WithOperationalState(ShutdownOperationalState.String()))
	assert.NotNil(t, tWorker)
	assert.True(t, strings.HasPrefix(tWorker.GetPublicId(), globals.WorkerPrefix))

	lkpWorker := NewWorker(scope.Global.String())
	lkpWorker.PublicId = tWorker.GetPublicId()
	rw := db.New(conn)
	require.NoError(t, rw.LookupById(context.Background(), lkpWorker))
	assert.NotNil(t, lkpWorker)
	assert.NotNil(t, lkpWorker.GetLastStatusTime())
	assert.Equal(t, KmsWorkerType.String(), lkpWorker.GetType())
	assert.Equal(t, name, lkpWorker.GetName())
	assert.Equal(t, description, lkpWorker.GetDescription())
	assert.Equal(t, address, lkpWorker.GetAddress())
	assert.Equal(t, ShutdownOperationalState.String(), lkpWorker.OperationalState)
}

func TestTestPkiWorker(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	require.NoError(t, kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))
	const (
		name        = "test name"
		description = "test description"
	)
	tWorker := TestPkiWorker(t, conn, wrapper, WithName(name), WithDescription(description))
	assert.NotNil(t, tWorker)
	assert.True(t, strings.HasPrefix(tWorker.GetPublicId(), globals.WorkerPrefix))

	lkpWorker := NewWorker(scope.Global.String())
	lkpWorker.PublicId = tWorker.GetPublicId()
	rw := db.New(conn)
	require.NoError(t, rw.LookupById(context.Background(), lkpWorker))
	assert.NotNil(t, lkpWorker)
	assert.Equal(t, PkiWorkerType.String(), lkpWorker.GetType())
	assert.Equal(t, name, lkpWorker.GetName())
	assert.Equal(t, description, lkpWorker.GetDescription())
	assert.Nil(t, lkpWorker.GetLastStatusTime())

	var keyId string
	authorizedWorker := TestPkiWorker(t, conn, wrapper, WithTestPkiWorkerAuthorizedKeyId(&keyId))
	assert.NotNil(t, authorizedWorker)
	assert.True(t, strings.HasPrefix(authorizedWorker.GetPublicId(), globals.WorkerPrefix))
	assert.NotEmpty(t, keyId)
}

func TestTestLookupWorkerByName(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	w := TestKmsWorker(t, conn, wrapper)
	t.Run("success", func(t *testing.T) {
		got, err := TestLookupWorkerByName(ctx, t, w.GetName(), repo)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(w.Worker, got.Worker, protocmp.Transform()))
	})
	t.Run("not found", func(t *testing.T) {
		got, err := TestLookupWorkerByName(ctx, t, "unknown_name", repo)
		require.NoError(t, err)
		assert.Nil(t, got)
	})
}
