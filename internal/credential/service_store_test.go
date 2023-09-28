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

type fakeStoreRepository struct {
	EstimatedStoreCountFn func(context.Context) (int, error)
	ListDeletedStoreIdsFn func(context.Context, time.Time, ...credential.Option) ([]string, error)
}

func (f *fakeStoreRepository) EstimatedStoreCount(ctx context.Context) (int, error) {
	return f.EstimatedStoreCountFn(ctx)
}

func (f *fakeStoreRepository) ListDeletedStoreIds(ctx context.Context, since time.Time, opt ...credential.Option) ([]string, error) {
	return f.ListDeletedStoreIdsFn(ctx, since, opt...)
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

func TestStoreService_EstimatedCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		repo := &fakeStoreRepository{
			EstimatedStoreCountFn: func(ctx context.Context) (int, error) {
				return 5, nil
			},
		}
		service, err := credential.NewStoreService(ctx, &fakeWriter{}, repo, repo)
		require.NoError(t, err)
		num, err := service.EstimatedCount(ctx)
		require.NoError(t, err)
		assert.Equal(t, 10, num)
	})
	t.Run("error-in-get-fn", func(t *testing.T) {
		t.Parallel()
		repo := &fakeStoreRepository{
			EstimatedStoreCountFn: func(ctx context.Context) (int, error) {
				return 0, errors.New("some error")
			},
		}
		service, err := credential.NewStoreService(ctx, &fakeWriter{}, repo, repo)
		require.NoError(t, err)
		_, err = service.EstimatedCount(ctx)
		require.ErrorContains(t, err, "some error")
	})
}

func TestStoreService_ListDeletedIds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		timeSince := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
		repo := &fakeStoreRepository{
			ListDeletedStoreIdsFn: func(ctx context.Context, since time.Time, opt ...credential.Option) ([]string, error) {
				assert.True(t, since.Equal(timeSince))
				opts, err := credential.GetOpts(opt...)
				require.NoError(t, err)
				assert.NotNil(t, opts.WithReader)
				return []string{"a", "b"}, nil
			},
		}
		writer := &fakeWriter{
			DoTxFn: func(ctx context.Context, retries uint, backoff db.Backoff, handler db.TxHandler) (db.RetryInfo, error) {
				r := &fakeReader{
					NowFn: func(ctx context.Context) (time.Time, error) {
						return time.Now(), nil
					},
				}
				err := handler(r, &fakeWriter{})
				return db.RetryInfo{}, err
			},
		}
		service, err := credential.NewStoreService(ctx, writer, repo, repo)
		require.NoError(t, err)
		ids, ttime, err := service.ListDeletedIds(ctx, timeSince)
		require.NoError(t, err)
		assert.Empty(
			t,
			cmp.Diff([]string{"a", "b", "a", "b"},
				ids,
				cmpopts.SortSlices(func(i, j string) bool { return i < j })),
		)
		// Transaction time should be within ~10 seconds of now
		now := time.Now()
		assert.True(t, ttime.Add(-10*time.Second).Before(now))
		assert.True(t, ttime.Add(10*time.Second).After(now))
	})
	t.Run("tx-error", func(t *testing.T) {
		t.Parallel()
		timeSince := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
		repo := &fakeStoreRepository{
			ListDeletedStoreIdsFn: func(ctx context.Context, since time.Time, opt ...credential.Option) ([]string, error) {
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
		service, err := credential.NewStoreService(ctx, writer, repo, repo)
		require.NoError(t, err)
		_, _, err = service.ListDeletedIds(ctx, timeSince)
		require.ErrorContains(t, err, "some error")
	})
	t.Run("list-fails", func(t *testing.T) {
		t.Parallel()
		timeSince := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
		repo := &fakeStoreRepository{
			ListDeletedStoreIdsFn: func(ctx context.Context, since time.Time, opt ...credential.Option) ([]string, error) {
				return nil, errors.New("some error")
			},
		}
		writer := &fakeWriter{
			DoTxFn: func(ctx context.Context, retries uint, backoff db.Backoff, handler db.TxHandler) (db.RetryInfo, error) {
				r := &fakeReader{
					NowFn: func(ctx context.Context) (time.Time, error) {
						return time.Now(), nil
					},
				}
				err := handler(r, &fakeWriter{})
				return db.RetryInfo{}, err
			},
		}
		service, err := credential.NewStoreService(ctx, writer, repo, repo)
		require.NoError(t, err)
		_, _, err = service.ListDeletedIds(ctx, timeSince)
		require.ErrorContains(t, err, "some error")
	})
}
