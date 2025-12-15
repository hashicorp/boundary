// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRotateRoots(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsCache := kms.TestKms(t, conn, wrapper)
	err := kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader))
	require.NoError(err)

	rw := db.New(conn)
	workerAuthRepo, err := NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(err)

	// Check that we have no roots first
	rootIds, err := workerAuthRepo.List(ctx, (*types.RootCertificate)(nil))
	require.NoError(err)
	assert.Len(rootIds, 0)

	// Generate roots
	roots, err := RotateRoots(ctx, workerAuthRepo, nodeenrollment.WithCertificateLifetime(time.Second*5))
	require.NoError(err)

	// Check that we have roots now
	rootIds, err = workerAuthRepo.List(ctx, (*types.RootCertificate)(nil))
	require.NoError(err)
	assert.Len(rootIds, 2)
	certAuthority := &types.RootCertificates{Id: CaId}
	err = workerAuthRepo.Load(ctx, certAuthority)
	require.NoError(err)
	require.NotNil(certAuthority.GetNext())
	require.NotNil(certAuthority.GetCurrent())

	initialNext := roots.GetNext()
	initialCurrent := roots.GetCurrent()

	// Rotate roots and assert that they've rotated
	newRoots, err := RotateRoots(ctx, workerAuthRepo, nodeenrollment.WithCertificateLifetime(time.Second*5))
	require.NoError(err)

	require.NotNil(newRoots.GetNext())
	require.NotNil(newRoots.GetCurrent())
	rotatedNext := newRoots.GetNext()
	rotatedCurrent := newRoots.GetCurrent()

	// Next and current should have changed
	assert.NotEqual(initialNext.PublicKeyPkix, rotatedNext.PublicKeyPkix)
	assert.NotEqual(initialCurrent.PublicKeyPkix, rotatedCurrent.PublicKeyPkix)

	// And the old next root should now be current
	assert.Equal(initialNext.PublicKeyPkix, rotatedCurrent.PublicKeyPkix)
}

func TestRotateRootsFailure(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")

	kmsCache := kms.TestKms(t, conn, wrapper)
	err := kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader))
	require.NoError(err)

	workerAuthRepo, err := NewRepositoryStorage(ctx, &db.Db{}, &db.Db{}, kmsCache)
	require.NoError(err)

	_, err = RotateRoots(ctx, workerAuthRepo)
	require.Error(err)
}
