// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/require"
)

type fakeVaultLibraryRepository struct {
	credential.LibraryService
}

type fakeWriter struct {
	db.Writer
}
type fakeStoreRepository struct {
	credential.StoreRepository
}

func TestNewStoreService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		got, err := credential.NewStoreService(ctx, &fakeWriter{}, &fakeStoreRepository{}, &fakeStoreRepository{})
		require.NoError(t, err)
		require.NotNil(t, got)
	})
	t.Run("nil-writer", func(t *testing.T) {
		t.Parallel()
		_, err := credential.NewStoreService(ctx, nil, &fakeStoreRepository{}, &fakeStoreRepository{})
		require.Error(t, err)
	})
	t.Run("nil-interface-writer", func(t *testing.T) {
		t.Parallel()
		_, err := credential.NewStoreService(ctx, (*fakeWriter)(nil), &fakeStoreRepository{}, &fakeStoreRepository{})
		require.Error(t, err)
	})
	t.Run("nil-vault-repo", func(t *testing.T) {
		t.Parallel()
		_, err := credential.NewStoreService(ctx, &fakeWriter{}, nil, &fakeStoreRepository{})
		require.Error(t, err)
	})
	t.Run("nil-vault-interface-repo", func(t *testing.T) {
		t.Parallel()
		_, err := credential.NewStoreService(ctx, &fakeWriter{}, (*fakeStoreRepository)(nil), &fakeStoreRepository{})
		require.Error(t, err)
	})
	t.Run("nil-static-repo", func(t *testing.T) {
		t.Parallel()
		_, err := credential.NewStoreService(ctx, &fakeWriter{}, &fakeStoreRepository{}, nil)
		require.Error(t, err)
	})
	t.Run("nil-static-interface-repo", func(t *testing.T) {
		t.Parallel()
		_, err := credential.NewStoreService(ctx, &fakeWriter{}, &fakeStoreRepository{}, (*fakeStoreRepository)(nil))
		require.Error(t, err)
	})
}
