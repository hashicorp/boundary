// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeCredentialStoreRepository struct {
	EsimatedStoreCountFn            func(context.Context) (int, error)
	ListDeletedCredentialStoreIdsFn func(context.Context, time.Time, ...credential.Option) ([]string, error)
}

func (f *fakeCredentialStoreRepository) EsimatedStoreCount(ctx context.Context) (int, error) {
	return f.EsimatedStoreCountFn(ctx)
}

func (f *fakeCredentialStoreRepository) ListDeletedCredentialStoreIds(ctx context.Context, since time.Time, opt ...credential.Option) ([]string, error) {
	return f.ListDeletedCredentialStoreIdsFn(ctx, since, opt...)
}

func TestNewCredentialStoreService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		got, err := credential.NewCredentialStoreService(ctx, &fakeWriter{}, &fakeCredentialStoreRepository{})
		require.NoError(t, err)
		require.NotNil(t, got)
	})
	t.Run("nil-writer", func(t *testing.T) {
		t.Parallel()
		_, err := credential.NewCredentialStoreService(ctx, nil, &fakeCredentialStoreRepository{})
		require.Error(t, err)
	})
	t.Run("nil-interface-writer", func(t *testing.T) {
		t.Parallel()
		_, err := credential.NewCredentialStoreService(ctx, (*fakeWriter)(nil), &fakeCredentialStoreRepository{})
		require.Error(t, err)
	})
	t.Run("repos", func(t *testing.T) {
		t.Parallel()
		_, err := credential.NewCredentialStoreService(ctx, &fakeWriter{})
		require.Error(t, err)
	})
	t.Run("nil-repo", func(t *testing.T) {
		t.Parallel()
		_, err := credential.NewCredentialStoreService(ctx, &fakeWriter{}, nil)
		require.Error(t, err)
	})
	t.Run("nil-interface-repo", func(t *testing.T) {
		t.Parallel()
		_, err := credential.NewCredentialStoreService(ctx, &fakeWriter{}, (*fakeCredentialStoreRepository)(nil))
		require.Error(t, err)
	})
}

func TestCredentialStoreService_EstimatedCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		repo := &fakeCredentialStoreRepository{
			EsimatedStoreCountFn: func(ctx context.Context) (int, error) {
				return 5, nil
			},
		}
		service, err := credential.NewCredentialStoreService(ctx, &fakeWriter{}, repo)
		require.NoError(t, err)
		num, err := service.EstimatedCount(ctx)
		require.NoError(t, err)
		assert.Equal(t, 5, num)
	})
	t.Run("error-in-get-fn", func(t *testing.T) {
		t.Parallel()
		repo := &fakeCredentialStoreRepository{
			EsimatedStoreCountFn: func(ctx context.Context) (int, error) {
				return 0, errors.New("some error")
			},
		}
		service, err := credential.NewCredentialStoreService(ctx, &fakeWriter{}, repo)
		require.NoError(t, err)
		_, err = service.EstimatedCount(ctx)
		require.ErrorContains(t, err, "some error")
	})
}

func TestCredentialStoreService_ListDeletedIds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		timeSince := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
		repo := &fakeCredentialStoreRepository{
			ListDeletedCredentialStoreIdsFn: func(ctx context.Context, since time.Time, opt ...credential.Option) ([]string, error) {
				assert.True(t, since.Equal(timeSince))
				opts, err := credential.GetOpts(opt...)
				require.NoError(t, err)
				assert.NotNil(t, opts.WithReader)
				return []string{"a", "b"}, nil
			},
		}
		writer := &fakeWriter{
			DoTxFn: func(ctx context.Context, retries uint, backoff db.Backoff, handler db.TxHandler) (db.RetryInfo, error) {
				err := handler(&fakeReader{}, &fakeWriter{})
				return db.RetryInfo{}, err
			},
		}
		service, err := credential.NewCredentialStoreService(ctx, writer, repo)
		require.NoError(t, err)
		ids, err := service.ListDeletedIds(ctx, timeSince)
		require.NoError(t, err)
		assert.Empty(
			t,
			cmp.Diff([]string{"a", "b"},
				ids,
				cmpopts.SortSlices(func(i, j string) bool { return i < j })),
		)
	})
	t.Run("tx-error", func(t *testing.T) {
		t.Parallel()
		timeSince := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
		repo := &fakeCredentialStoreRepository{
			ListDeletedCredentialStoreIdsFn: func(ctx context.Context, since time.Time, opt ...credential.Option) ([]string, error) {
				assert.True(t, since.Equal(timeSince))
				opts, err := credential.GetOpts(opt...)
				require.NoError(t, err)
				assert.NotNil(t, opts.WithReader)
				return []string{"a", "b"}, nil
			},
		}
		writer := &fakeWriter{
			DoTxFn: func(ctx context.Context, retries uint, backoff db.Backoff, handler db.TxHandler) (db.RetryInfo, error) {
				return db.RetryInfo{}, errors.New("some error")
			},
		}
		service, err := credential.NewCredentialStoreService(ctx, writer, repo)
		require.NoError(t, err)
		_, err = service.ListDeletedIds(ctx, timeSince)
		require.ErrorContains(t, err, "some error")
	})
	t.Run("list-fails", func(t *testing.T) {
		t.Parallel()
		timeSince := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
		repo := &fakeCredentialStoreRepository{
			ListDeletedCredentialStoreIdsFn: func(ctx context.Context, since time.Time, opt ...credential.Option) ([]string, error) {
				return nil, errors.New("some error")
			},
		}
		writer := &fakeWriter{
			DoTxFn: func(ctx context.Context, retries uint, backoff db.Backoff, handler db.TxHandler) (db.RetryInfo, error) {
				err := handler(&fakeReader{}, &fakeWriter{})
				return db.RetryInfo{}, err
			},
		}
		service, err := credential.NewCredentialStoreService(ctx, writer, repo)
		require.NoError(t, err)
		_, err = service.ListDeletedIds(ctx, timeSince)
		require.ErrorContains(t, err, "some error")
	})
}
