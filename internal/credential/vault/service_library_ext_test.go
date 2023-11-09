// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/require"
)

type fakeWriter struct {
	db.Writer
}

func TestNewLibraryListingService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		got, err := vault.NewLibraryListingService(ctx, &fakeWriter{}, &vault.Repository{})
		require.NoError(t, err)
		require.NotNil(t, got)
	})
	t.Run("nil-writer", func(t *testing.T) {
		t.Parallel()
		_, err := vault.NewLibraryListingService(ctx, nil, &vault.Repository{})
		require.Error(t, err)
	})
	t.Run("nil-interface-writer", func(t *testing.T) {
		t.Parallel()
		_, err := vault.NewLibraryListingService(ctx, (*fakeWriter)(nil), &vault.Repository{})
		require.Error(t, err)
	})
	t.Run("nil-repo", func(t *testing.T) {
		t.Parallel()
		_, err := vault.NewLibraryListingService(ctx, &fakeWriter{}, nil)
		require.Error(t, err)
	})
}
