// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
