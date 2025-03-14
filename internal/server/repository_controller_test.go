// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		controller *store.Controller
		wantCount  int
		wantErr    bool
	}{
		{
			name:    "nil-controller",
			wantErr: true,
		},
		{
			name: "empty-id",
			controller: &store.Controller{
				PrivateId: "",
				Address:   "127.0.0.1",
			},
			wantErr: true,
		},
		{
			name: "empty-address",
			controller: &store.Controller{
				PrivateId: "test-controller",
				Address:   "",
			},
			wantErr: true,
		},
		{
			name: "valid-ipv4-controller",
			controller: &store.Controller{
				PrivateId: "test-ipv4-controller",
				Address:   "127.0.0.1",
			},
			wantCount: 1,
		},
		{
			name: "valid-ipv6-controller",
			controller: &store.Controller{
				PrivateId: "test-ipv6-controller",
				Address:   "[2001:4860:4860:0:0:0:0:8888]",
			},
			wantCount: 1,
		},
		{
			name: "valid-abbreviated-ipv6-controller",
			controller: &store.Controller{
				PrivateId: "test-abbreviated-ipv6-controller",
				Address:   "[2001:4860:4860::8888]",
			},
			wantCount: 1,
		},
		{
			name: "valid-controller-short-name",
			controller: &store.Controller{
				PrivateId: "test",
				Address:   "127.0.0.1",
			},
			wantCount: 1,
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

func TestRepository_UpdateController(t *testing.T) {
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
		name               string
		originalController *store.Controller
		updatedController  *store.Controller
		wantCount          int
		wantErr            bool
	}{
		{
			name:    "nil-controller",
			wantErr: true,
		},
		{
			name: "empty-id",
			updatedController: &store.Controller{
				PrivateId: "",
				Address:   "127.0.0.1",
			},
			wantErr: true,
		},
		{
			name: "empty-address",
			updatedController: &store.Controller{
				PrivateId: "test-controller",
				Address:   "",
			},
			wantErr: true,
		},
		{
			name: "controller-not-found",
			originalController: &store.Controller{
				PrivateId:   "test-ipv4-controller",
				Address:     "127.0.0.1",
				Description: "ipv4 description",
			},
			updatedController: &store.Controller{
				PrivateId:   "test-new-ipv4-controller",
				Address:     "127.0.0.1",
				Description: "new ipv4 description",
			},
			wantErr: true,
		},
		{
			name: "valid-ipv4-controller",
			originalController: &store.Controller{
				PrivateId:   "ipv4-controller",
				Address:     "127.0.0.1",
				Description: "ipv4 description",
			},
			updatedController: &store.Controller{
				PrivateId:   "ipv4-controller",
				Address:     "127.0.0.2",
				Description: "new ipv4 description",
			},
			wantCount: 1,
		},
		{
			name: "valid-ipv6-controller",
			originalController: &store.Controller{
				PrivateId:   "test-ipv6-controller",
				Address:     "[2001:4860:4860:0:0:0:0:8888]",
				Description: "ipv6 description",
			},
			updatedController: &store.Controller{
				PrivateId:   "test-ipv6-controller",
				Address:     "[2001:4860:4860:0:0:0:0:9999]",
				Description: "new ipv6 description",
			},
			wantCount: 1,
		},
		{
			name: "valid-abbreviated-ipv6-controller",
			originalController: &store.Controller{
				PrivateId:   "test-abbreviated-ipv6-controller",
				Address:     "[2001:4860:4860::8888]",
				Description: "abbreviated ipv6 description",
			},
			updatedController: &store.Controller{
				PrivateId:   "test-abbreviated-ipv6-controller",
				Address:     "[2001:4860:4860::9999]",
				Description: "new abbreviated ipv6 description",
			},
			wantCount: 1,
		},
		{
			name: "valid-controller-short-name",
			originalController: &store.Controller{
				PrivateId:   "test",
				Address:     "127.0.0.1",
				Description: "short name description",
			},
			updatedController: &store.Controller{
				PrivateId:   "test",
				Address:     "127.0.0.2",
				Description: "new short name description",
			},
			wantCount: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			// Insert the original controller attributes if they exist
			if tt.originalController != nil {
				_, err := testRepo.UpsertController(ctx, tt.originalController)
				require.NoError(err)
			}

			// Update the controller with the updated attributes
			got, err := testRepo.UpdateController(ctx, tt.updatedController)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, got)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCount, got)

			// Retrieve the updated controller in the database and assert updated successfully
			controllerList, err := testRepo.ListControllers(ctx, []Option{}...)
			require.NoError(err)
			updatedControllerEntry := controllerList[len(controllerList)-1]

			assert.Equal(tt.updatedController.PrivateId, updatedControllerEntry.PrivateId)
			assert.Equal(tt.updatedController.Address, updatedControllerEntry.Address)
			assert.Equal(tt.updatedController.Description, updatedControllerEntry.Description)
		})
	}
}
