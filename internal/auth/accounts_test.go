// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeAccountRepository struct {
	GetTotalAccountsFn      func(context.Context) (int, error)
	ListDeletedAccountIdsFn func(context.Context, time.Time, ...auth.Option) ([]string, error)
}

func (f *fakeAccountRepository) GetTotalAccounts(ctx context.Context) (int, error) {
	return f.GetTotalAccountsFn(ctx)
}

func (f *fakeAccountRepository) ListDeletedAccountIds(ctx context.Context, since time.Time, opt ...auth.Option) ([]string, error) {
	return f.ListDeletedAccountIdsFn(ctx, since, opt...)
}

type fakeWriter struct {
	// Embed interface so we don't need to implement the functions we don't care about
	db.Writer
	DoTxFn func(ctx context.Context, retries uint, backOff db.Backoff, Handler db.TxHandler) (db.RetryInfo, error)
}

func (f *fakeWriter) DoTx(ctx context.Context, retries uint, backOff db.Backoff, handler db.TxHandler) (db.RetryInfo, error) {
	return f.DoTxFn(ctx, retries, backOff, handler)
}

type fakeReader struct {
	db.Reader
}

func TestNewAccountService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		got, err := auth.NewAccountService(ctx, &fakeWriter{}, &fakeAccountRepository{}, &fakeAccountRepository{}, &fakeAccountRepository{})
		require.NoError(t, err)
		require.NotNil(t, got)
	})
	t.Run("nil-writer", func(t *testing.T) {
		t.Parallel()
		_, err := auth.NewAccountService(ctx, nil, &fakeAccountRepository{}, &fakeAccountRepository{}, &fakeAccountRepository{})
		require.Error(t, err)
	})
	t.Run("nil-interface-writer", func(t *testing.T) {
		t.Parallel()
		_, err := auth.NewAccountService(ctx, (*fakeWriter)(nil), &fakeAccountRepository{}, &fakeAccountRepository{}, &fakeAccountRepository{})
		require.Error(t, err)
	})
	t.Run("nil-ldap-repo", func(t *testing.T) {
		t.Parallel()
		_, err := auth.NewAccountService(ctx, &fakeWriter{}, nil, &fakeAccountRepository{}, &fakeAccountRepository{})
		require.Error(t, err)
	})
	t.Run("nil-ldap-interface-repo", func(t *testing.T) {
		t.Parallel()
		_, err := auth.NewAccountService(ctx, &fakeWriter{}, (*fakeAccountRepository)(nil), &fakeAccountRepository{}, &fakeAccountRepository{})
		require.Error(t, err)
	})
	t.Run("nil-oidc-repo", func(t *testing.T) {
		t.Parallel()
		_, err := auth.NewAccountService(ctx, &fakeWriter{}, &fakeAccountRepository{}, nil, &fakeAccountRepository{})
		require.Error(t, err)
	})
	t.Run("nil-oidc-interface-repo", func(t *testing.T) {
		t.Parallel()
		_, err := auth.NewAccountService(ctx, &fakeWriter{}, &fakeAccountRepository{}, (*fakeAccountRepository)(nil), &fakeAccountRepository{})
		require.Error(t, err)
	})
	t.Run("nil-pw-repo", func(t *testing.T) {
		t.Parallel()
		_, err := auth.NewAccountService(ctx, &fakeWriter{}, &fakeAccountRepository{}, &fakeAccountRepository{}, nil)
		require.Error(t, err)
	})
	t.Run("nil-pw-interface-repo", func(t *testing.T) {
		t.Parallel()
		_, err := auth.NewAccountService(ctx, &fakeWriter{}, &fakeAccountRepository{}, &fakeAccountRepository{}, (*fakeAccountRepository)(nil))
		require.Error(t, err)
	})
}

func TestAccountService_GetTotalItems(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		repo := &fakeAccountRepository{
			GetTotalAccountsFn: func(ctx context.Context) (int, error) {
				return 5, nil
			},
		}
		service, err := auth.NewAccountService(ctx, &fakeWriter{}, repo, repo, repo)
		require.NoError(t, err)
		num, err := service.GetTotalItems(ctx)
		require.NoError(t, err)
		assert.Equal(t, 15, num)
	})
	t.Run("error-in-get-fn", func(t *testing.T) {
		t.Parallel()
		repo := &fakeAccountRepository{
			GetTotalAccountsFn: func(ctx context.Context) (int, error) {
				return 0, errors.New("some error")
			},
		}
		service, err := auth.NewAccountService(ctx, &fakeWriter{}, repo, repo, repo)
		require.NoError(t, err)
		_, err = service.GetTotalItems(ctx)
		require.ErrorContains(t, err, "some error")
	})
}

func TestAccountService_ListDeletedIds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		timeSince := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
		repo := &fakeAccountRepository{
			ListDeletedAccountIdsFn: func(ctx context.Context, since time.Time, opt ...auth.Option) ([]string, error) {
				assert.True(t, since.Equal(timeSince))
				opts, err := auth.GetOpts(opt...)
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
		service, err := auth.NewAccountService(ctx, writer, repo, repo, repo)
		require.NoError(t, err)
		ids, err := service.ListDeletedIds(ctx, timeSince)
		require.NoError(t, err)
		assert.Empty(
			t,
			cmp.Diff([]string{"a", "b", "a", "b", "a", "b"},
				ids,
				cmpopts.SortSlices(func(i, j string) bool { return i < j })),
		)
	})
	t.Run("tx-error", func(t *testing.T) {
		t.Parallel()
		timeSince := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
		repo := &fakeAccountRepository{
			ListDeletedAccountIdsFn: func(ctx context.Context, since time.Time, opt ...auth.Option) ([]string, error) {
				assert.True(t, since.Equal(timeSince))
				opts, err := auth.GetOpts(opt...)
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
		service, err := auth.NewAccountService(ctx, writer, repo, repo, repo)
		require.NoError(t, err)
		_, err = service.ListDeletedIds(ctx, timeSince)
		require.ErrorContains(t, err, "some error")
	})
	t.Run("list-fails", func(t *testing.T) {
		t.Parallel()
		timeSince := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
		repo := &fakeAccountRepository{
			ListDeletedAccountIdsFn: func(ctx context.Context, since time.Time, opt ...auth.Option) ([]string, error) {
				return nil, errors.New("some error")
			},
		}
		writer := &fakeWriter{
			DoTxFn: func(ctx context.Context, retries uint, backoff db.Backoff, handler db.TxHandler) (db.RetryInfo, error) {
				err := handler(&fakeReader{}, &fakeWriter{})
				return db.RetryInfo{}, err
			},
		}
		service, err := auth.NewAccountService(ctx, writer, repo, repo, repo)
		require.NoError(t, err)
		_, err = service.ListDeletedIds(ctx, timeSince)
		require.ErrorContains(t, err, "some error")
	})
}
