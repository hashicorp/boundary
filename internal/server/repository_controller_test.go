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
