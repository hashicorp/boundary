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

func TestReinitializeRoots(t *testing.T) {
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
	_, err = RotateRoots(ctx, workerAuthRepo, nodeenrollment.WithCertificateLifetime(time.Second*5))
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

	initialNext := certAuthority.GetNext()
	initialCurrent := certAuthority.GetCurrent()

	// Reinitialize roots and assert that they're entirely new
	newCerts, err := ReinitializeRoots(ctx, workerAuthRepo, nodeenrollment.WithCertificateLifetime(time.Second*5))
	require.NoError(err)

	require.NotNil(newCerts.GetNext())
	require.NotNil(newCerts.GetCurrent())
	reinitNext := newCerts.GetNext()
	reinitCurrent := newCerts.GetCurrent()

	// Next and current should have changed
	assert.NotEqual(initialNext.PublicKeyPkix, reinitNext.PublicKeyPkix)
	assert.NotEqual(initialCurrent.PublicKeyPkix, reinitCurrent.PublicKeyPkix)
	assert.NotEqual(initialNext.PublicKeyPkix, reinitCurrent.PublicKeyPkix)
	assert.NotEqual(initialCurrent.PublicKeyPkix, reinitNext.PublicKeyPkix)
}

func TestReinitializeFailure(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")

	kmsCache := kms.TestKms(t, conn, wrapper)
	err := kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader))
	require.NoError(err)

	workerAuthRepo, err := NewRepositoryStorage(ctx, &db.Db{}, &db.Db{}, kmsCache)
	require.NoError(err)

	_, err = ReinitializeRoots(ctx, workerAuthRepo)
	require.Error(err)
}
