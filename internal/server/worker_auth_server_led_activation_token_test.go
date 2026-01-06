// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-dbw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkerAuthActivationTokenConstraints(t *testing.T) {
	t.Parallel()
	tlRequire, tlAssert := require.New(t), assert.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)

	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrap)
	tlRequire.NoError(kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))

	repo, err := NewRepository(ctx, rw, rw, kmsCache)
	tlRequire.NoError(err)

	// First create a worker without an activation token so we can verify it doesn't show up in the table
	origWorker := NewWorker(scope.Global.String())
	origWorker, err = repo.CreateWorker(ctx, origWorker)
	tlRequire.NoError(err)
	tlAssert.Empty(origWorker.ControllerGeneratedActivationToken)
	activationToken := allocWorkerAuthServerLedActivationToken()
	err = rw.LookupWhere(ctx, activationToken, "worker_id = ?", []any{origWorker.PublicId})
	tlRequire.Error(err)
	tlAssert.ErrorIs(err, dbw.ErrRecordNotFound)

	// Now create a worker with an activation token and verify we can find it
	worker := NewWorker(scope.Global.String())
	worker, err = repo.CreateWorker(ctx, worker, WithCreateControllerLedActivationToken(true))
	tlRequire.NoError(err)
	tlAssert.NotEmpty(worker.ControllerGeneratedActivationToken)
	activationToken = allocWorkerAuthServerLedActivationToken()
	err = rw.LookupWhere(ctx, activationToken, "worker_id = ?", []any{worker.PublicId})
	tlRequire.NoError(err)
	tlAssert.Empty(activationToken.CreationTime)
	tlAssert.NotEmpty(activationToken.KeyId)
	tlAssert.NotEmpty(activationToken.TokenId)
	tlAssert.NotEmpty(activationToken.CreationTimeEncrypted)

	// Run some test cases. All are expected to result in error.
	cases := []struct {
		name            string
		createModifyFn  func(*testing.T, *WorkerAuthServerLedActivationToken) *WorkerAuthServerLedActivationToken
		updateModifyFn  func(*testing.T, *WorkerAuthServerLedActivationToken) (string, []any) // If set, will update instead of create
		wantErrContains string
	}{
		{
			name: "fully-duplicate",
			createModifyFn: func(t *testing.T, in *WorkerAuthServerLedActivationToken) *WorkerAuthServerLedActivationToken {
				return in
			},
			wantErrContains: "worker_auth_server_led_activation_token_pkey",
		},
		{
			name: "same-token-id",
			createModifyFn: func(t *testing.T, in *WorkerAuthServerLedActivationToken) *WorkerAuthServerLedActivationToken {
				in.WorkerId = origWorker.PublicId
				return in
			},
			wantErrContains: "worker_auth_server_led_activation_token_token_id_uq",
		},
		{
			name: "same-worker-id",
			createModifyFn: func(t *testing.T, in *WorkerAuthServerLedActivationToken) *WorkerAuthServerLedActivationToken {
				in.TokenId = in.TokenId[0:5]
				return in
			},
			wantErrContains: "worker_auth_server_led_activation_token_pkey",
		},
		{
			name: "modify-worker-id",
			updateModifyFn: func(t *testing.T, in *WorkerAuthServerLedActivationToken) (string, []any) {
				return "update worker_auth_server_led_activation_token set worker_id = ? where token_id = ?", []any{origWorker.PublicId, in.TokenId}
			},
			wantErrContains: "immutable column: worker_auth_server_led_activation_token.worker_id: integrity violation",
		},
		{
			name: "modify-token-id",
			updateModifyFn: func(t *testing.T, in *WorkerAuthServerLedActivationToken) (string, []any) {
				return "update worker_auth_server_led_activation_token set token_id = ? where worker_id = ?", []any{in.TokenId[0:5], in.WorkerId}
			},
			wantErrContains: "immutable column: worker_auth_server_led_activation_token.token_id: integrity violation",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			testActivationToken := activationToken.clone()
			var err error
			if tc.updateModifyFn != nil {
				queryStr, args := tc.updateModifyFn(t, testActivationToken)
				var rowsUpdated int
				rowsUpdated, err = rw.Exec(ctx, queryStr, args)
				assert.Empty(rowsUpdated)
			} else {
				err = rw.Create(ctx, tc.createModifyFn(t, testActivationToken))
			}
			require.Error(err)
			assert.Contains(err.Error(), tc.wantErrContains)
		})
	}
}
