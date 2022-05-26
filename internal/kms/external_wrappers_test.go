package kms

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
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
	workerStorageWrapper := db.TestWrapper(t)

	k := TestKms(t, conn, rootWrapper)
	err := k.AddExternalWrappers(testCtx, WithRecoveryWrapper(recoveryWrapper), WithWorkerAuthWrapper(workerAuthWrapper), WithWorkerStorageWrapper(workerStorageWrapper))
	require.NoError(err)

	assert.Equal(rootWrapper, k.GetExternalWrappers(testCtx).Root())
	assert.Equal(recoveryWrapper, k.GetExternalWrappers(testCtx).Recovery())
	assert.Equal(workerAuthWrapper, k.GetExternalWrappers(testCtx).WorkerAuth())
	assert.Equal(workerStorageWrapper, k.GetExternalWrappers(testCtx).WorkerStorage())

	err = k.AddExternalWrappers(testCtx, WithRootWrapper(&invalidWrapper{}))
	assert.Error(err)
	err = k.AddExternalWrappers(testCtx, WithRecoveryWrapper(&invalidWrapper{}))
	assert.Error(err)
	err = k.AddExternalWrappers(testCtx, WithWorkerAuthWrapper(&invalidWrapper{}))
	assert.Error(err)
	err = k.AddExternalWrappers(testCtx, WithWorkerStorageWrapper(&invalidWrapper{}))
	assert.Error(err)
}

type invalidWrapper struct {
	wrapping.Wrapper
}

func (w *invalidWrapper) KeyId(context.Context) (string, error) {
	return "", fmt.Errorf("invalid-error")
}
