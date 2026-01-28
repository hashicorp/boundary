// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package kms

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExternalWrappers(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)

	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rootWrapper := db.TestWrapper(t)
	recoveryWrapper := db.TestWrapper(t)
	workerAuthWrapper := db.TestWrapper(t)
	workerAuthStorageWrapper := db.TestWrapper(t)
	bsrWrapper := db.TestWrapper(t)

	k := TestKms(t, conn, rootWrapper)
	err := k.AddExternalWrappers(testCtx,
		WithRecoveryWrapper(recoveryWrapper),
		WithWorkerAuthWrapper(workerAuthWrapper),
		WithWorkerAuthStorageWrapper(workerAuthStorageWrapper),
		WithBsrWrapper(bsrWrapper),
	)
	require.NoError(err)

	assert.Equal(rootWrapper, k.GetExternalWrappers(testCtx).Root())
	assert.Equal(recoveryWrapper, k.GetExternalWrappers(testCtx).Recovery())
	assert.Equal(workerAuthWrapper, k.GetExternalWrappers(testCtx).WorkerAuth())
	assert.Equal(bsrWrapper, k.GetExternalWrappers(testCtx).Bsr())
}
