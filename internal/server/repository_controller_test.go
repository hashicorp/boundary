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

const (
	removeControllerSql = `delete from server_controller where private_id = $1`
)

func TestRepository_UpsertController(t *testing.T) {
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
		name       string
		controller *Controller
		wantCount  int
		wantErr    bool
	}{
		{
			name:    "nil-controller",
			wantErr: true,
		},
		{
			name:       "empty-id",
			controller: NewController("", WithAddress("127.0.0.1")),
			wantErr:    true,
		},
		{
			name:       "empty-address",
			controller: NewController("test-controller"),
			wantErr:    true,
		},
		{
			name:       "valid-ipv4-controller",
			controller: NewController("ipv4-controller", WithAddress("127.0.0.1")),
			wantCount:  1,
		},
		{
			name:       "valid-ipv6-controller",
			controller: NewController("test-ipv6-controller", WithAddress("[2001:4860:4860:0:0:0:0:8888]")),
			wantCount:  1,
		},
		{
			name:       "valid-abbreviated-ipv6-controller",
			controller: NewController("test-abbreviated-ipv6-controller", WithAddress("[2001:4860:4860::8888]")),
			wantCount:  1,
		},
		{
			name:       "valid-controller-short-name",
			controller: NewController("test", WithAddress("127.0.0.1")),
			wantCount:  1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := testRepo.UpsertController(ctx, tt.controller)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, got)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCount, got)
		})
	}
}

func TestRepository_UpdateControllerStatus(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	testRepo, err := NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iam.TestScopes(t, iamRepo)

	tests := map[string]struct {
		originalController *Controller
		updatedController  *Controller
		wantCount          int
		wantErr            bool
		cleanUpFunc        func(t *testing.T, rw *db.Db, privateId string)
	}{
		"nil-controller": {
			wantErr: true,
		},
		"empty-id": {
			updatedController: NewController("", WithAddress("127.0.0.1")),
			wantErr:           true,
		},
		"empty-address": {
			updatedController: NewController("test-controller"),
			wantErr:           true,
		},
		"controller-not-found": {
			updatedController: NewController("test-controller", WithAddress("127.0.0.1"), WithDescription("new ipv4 description")),
			wantErr:           true,
		},
		"valid-ipv4-controller": {
			originalController: NewController("ipv4-controller", WithAddress("127.0.0.1"), WithDescription("ipv4 description")),
			updatedController:  NewController("ipv4-controller", WithAddress("127.0.0.2"), WithDescription("new ipv4 description")),
			wantCount:          1,
			cleanUpFunc: func(t *testing.T, rw *db.Db, privateId string) {
				t.Helper()
				c, err := rw.Exec(ctx, removeControllerSql, []any{privateId})
				require.NoError(t, err)
				require.Equal(t, 1, c)
			},
		},
		"valid-ipv6-controller": {
			originalController: NewController("test-ipv6-controller", WithAddress("[2001:4860:4860:0:0:0:0:8888]"), WithDescription("ipv6 description")),
			updatedController:  NewController("test-ipv6-controller", WithAddress("[2001:4860:4860:0:0:0:0:9999]"), WithDescription("new ipv6 description")),
			wantCount:          1,
			cleanUpFunc: func(t *testing.T, rw *db.Db, privateId string) {
				t.Helper()
				c, err := rw.Exec(ctx, removeControllerSql, []any{privateId})
				require.NoError(t, err)
				require.Equal(t, 1, c)
			},
		},
		"valid-abbreviated-ipv6-controller": {
			originalController: NewController("test-abbreviated-ipv6-controller", WithAddress("[2001:4860:4860::8888]"), WithDescription("abbreviated ipv6 description")),
			updatedController:  NewController("test-abbreviated-ipv6-controller", WithAddress("[2001:4860:4860::9999]"), WithDescription("new abbreviated ipv6 description")),
			wantCount:          1,
			cleanUpFunc: func(t *testing.T, rw *db.Db, privateId string) {
				t.Helper()
				c, err := rw.Exec(ctx, removeControllerSql, []any{privateId})
				require.NoError(t, err)
				require.Equal(t, 1, c)
			},
		},
		"valid-controller-short-name": {
			originalController: NewController("test", WithAddress("127.0.0.1"), WithDescription("short name description")),
			updatedController:  NewController("test", WithAddress("127.0.0.2"), WithDescription("new short name description")),
			wantCount:          1,
			cleanUpFunc: func(t *testing.T, rw *db.Db, privateId string) {
				t.Helper()
				c, err := rw.Exec(ctx, removeControllerSql, []any{privateId})
				require.NoError(t, err)
				require.Equal(t, 1, c)
			},
		},
		// Test case for updating a controller with the same attributes validating update_time is updated
		"duplicate-ipv4-controller-update": {
			originalController: NewController("ipv4-controller", WithAddress("127.0.0.1"), WithDescription("new ipv4 description")),
			updatedController:  NewController("ipv4-controller", WithAddress("127.0.0.1"), WithDescription("new ipv4 description")),
			wantCount:          1,
			cleanUpFunc: func(t *testing.T, rw *db.Db, privateId string) {
				t.Helper()
				c, err := rw.Exec(ctx, removeControllerSql, []any{privateId})
				require.NoError(t, err)
				require.Equal(t, 1, c)
			},
		},
		"duplicate-ipv6-controller-update": {
			originalController: NewController("test-ipv6-controller", WithAddress("[2001:4860:4860:0:0:0:0:8888]"), WithDescription("ipv6 description")),
			updatedController:  NewController("test-ipv6-controller", WithAddress("[2001:4860:4860:0:0:0:0:8888]"), WithDescription("ipv6 description")),
			wantCount:          1,
			cleanUpFunc: func(t *testing.T, rw *db.Db, privateId string) {
				t.Helper()
				c, err := rw.Exec(ctx, removeControllerSql, []any{privateId})
				require.NoError(t, err)
				require.Equal(t, 1, c)
			},
		},
		"valid-ipv4-controller-remove-description": {
			originalController: NewController("test", WithAddress("127.0.0.1"), WithDescription("short name description")),
			updatedController:  NewController("test", WithAddress("127.0.0.2")),
			wantCount:          1,
			cleanUpFunc: func(t *testing.T, rw *db.Db, privateId string) {
				t.Helper()
				c, err := rw.Exec(ctx, removeControllerSql, []any{privateId})
				require.NoError(t, err)
				require.Equal(t, 1, c)
			},
		},
		"valid-ipv4-controller-no-description": {
			originalController: NewController("test", WithAddress("127.0.0.1")),
			updatedController:  NewController("test", WithAddress("127.0.0.2")),
			wantCount:          1,
			cleanUpFunc: func(t *testing.T, rw *db.Db, privateId string) {
				t.Helper()
				c, err := rw.Exec(ctx, removeControllerSql, []any{privateId})
				require.NoError(t, err)
				require.Equal(t, 1, c)
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			var originalControllerEntry *Controller
			if tt.originalController != nil {
				_, err := testRepo.UpsertController(ctx, tt.originalController)
				require.NoError(err)

				controllerList, err := testRepo.ListControllers(ctx, []Option{}...)
				require.NoError(err)
				originalControllerEntry = controllerList[0]
			}

			got, err := testRepo.UpdateControllerStatus(ctx, tt.updatedController)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, got)
				if tt.cleanUpFunc != nil {
					tt.cleanUpFunc(t, rw, tt.updatedController.PrivateId)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCount, got)

			controllerList, err := testRepo.ListControllers(ctx, []Option{}...)
			require.NoError(err)
			require.Len(controllerList, 1)

			updatedControllerEntry := controllerList[0]

			assert.Equal(tt.updatedController.PrivateId, updatedControllerEntry.PrivateId)
			assert.Equal(tt.updatedController.Address, updatedControllerEntry.Address)
			assert.Equal(tt.updatedController.Description, updatedControllerEntry.Description)
			assert.True(updatedControllerEntry.UpdateTime.AsTime().After(originalControllerEntry.UpdateTime.AsTime()))
			tt.cleanUpFunc(t, rw, tt.updatedController.PrivateId)
		})
	}
}
