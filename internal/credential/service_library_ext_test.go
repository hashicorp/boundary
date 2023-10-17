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
	credential.VaultLibraryRepository
}

type fakeWriter struct {
	db.Writer
}

func TestNewLibraryService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		got, err := credential.NewLibraryService(ctx, &fakeWriter{}, &fakeVaultLibraryRepository{})
		require.NoError(t, err)
		require.NotNil(t, got)
	})
	t.Run("nil-writer", func(t *testing.T) {
		t.Parallel()
		_, err := credential.NewLibraryService(ctx, nil, &fakeVaultLibraryRepository{})
		require.Error(t, err)
	})
	t.Run("nil-interface-writer", func(t *testing.T) {
		t.Parallel()
		_, err := credential.NewLibraryService(ctx, (*fakeWriter)(nil), &fakeVaultLibraryRepository{})
		require.Error(t, err)
	})
	t.Run("nil-repo", func(t *testing.T) {
		t.Parallel()
		_, err := credential.NewLibraryService(ctx, &fakeWriter{}, nil)
		require.Error(t, err)
	})
	t.Run("nil-interface-repo", func(t *testing.T) {
		t.Parallel()
		_, err := credential.NewLibraryService(ctx, &fakeWriter{}, (*fakeVaultLibraryRepository)(nil))
		require.Error(t, err)
	})
}
