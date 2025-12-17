// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpsertSessionInfo(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	testRepo, err := NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	iam.TestScopes(t, iamRepo)

	tests := []struct {
		name           string
		workerId       string
		expectedErrMsg string
	}{
		{
			name:           "empty worker id",
			expectedErrMsg: "missing worker id",
		},
		{
			name:           "worker does not exist",
			workerId:       "w_dne",
			expectedErrMsg: "server.(Repository).UpsertSessionInfo: failed for w_dne: db.DoTx: db.Create: wt_public_id_check constraint failed: check constraint violated: integrity violation: error #1000",
		},
		{
			name: "success",
			workerId: func() string {
				return TestPkiWorker(t, conn, wrapper).PublicId
			}(),
		},
		{
			name: "upsert on conflict",
			workerId: func() string {
				workerId := TestPkiWorker(t, conn, wrapper).PublicId
				require.NoError(t, testRepo.UpsertSessionInfo(context.Background(), workerId))
				return workerId
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := testRepo.UpsertSessionInfo(context.Background(), tt.workerId)
			if tt.expectedErrMsg != "" {
				require.Error(err)
				assert.ErrorContains(err, tt.expectedErrMsg)
				return
			}
			require.NoError(err)
		})
	}
}
