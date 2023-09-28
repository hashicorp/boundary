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

type fakeVaultLibraryRepository struct {
	EstimatedLibraryCountFn               func(context.Context) (int, error)
	EstimatedSSHCertificateLibraryCountFn func(context.Context) (int, error)
	ListDeletedLibraryIdsFn               func(context.Context, time.Time, ...credential.Option) ([]string, error)
	ListDeletedSSHCertificateLibraryIdsFn func(context.Context, time.Time, ...credential.Option) ([]string, error)
}

func (f *fakeVaultLibraryRepository) EstimatedLibraryCount(ctx context.Context) (int, error) {
	return f.EstimatedLibraryCountFn(ctx)
}

func (f *fakeVaultLibraryRepository) EstimatedSSHCertificateLibraryCount(ctx context.Context) (int, error) {
	return f.EstimatedSSHCertificateLibraryCountFn(ctx)
}

func (f *fakeVaultLibraryRepository) ListDeletedLibraryIds(ctx context.Context, since time.Time, opt ...credential.Option) ([]string, error) {
	return f.ListDeletedLibraryIdsFn(ctx, since, opt...)
}

func (f *fakeVaultLibraryRepository) ListDeletedSSHCertificateLibraryIds(ctx context.Context, since time.Time, opt ...credential.Option) ([]string, error) {
	return f.ListDeletedSSHCertificateLibraryIdsFn(ctx, since, opt...)
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
	NowFn func(context.Context) (time.Time, error)
}

func (f *fakeReader) Now(ctx context.Context) (time.Time, error) {
	return f.NowFn(ctx)
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

func TestCredentialLibraryService_EstimatedCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		repo := &fakeVaultLibraryRepository{
			EstimatedLibraryCountFn: func(ctx context.Context) (int, error) {
				return 5, nil
			},
			EstimatedSSHCertificateLibraryCountFn: func(ctx context.Context) (int, error) {
				return 3, nil
			},
		}
		service, err := credential.NewLibraryService(ctx, &fakeWriter{}, repo)
		require.NoError(t, err)
		num, err := service.EstimatedCount(ctx)
		require.NoError(t, err)
		assert.Equal(t, 8, num)
	})
	t.Run("error-in-generic-libs-fn", func(t *testing.T) {
		t.Parallel()
		repo := &fakeVaultLibraryRepository{
			EstimatedLibraryCountFn: func(ctx context.Context) (int, error) {
				return 0, errors.New("some error")
			},
			EstimatedSSHCertificateLibraryCountFn: func(ctx context.Context) (int, error) {
				return 3, nil
			},
		}
		service, err := credential.NewLibraryService(ctx, &fakeWriter{}, repo)
		require.NoError(t, err)
		_, err = service.EstimatedCount(ctx)
		require.ErrorContains(t, err, "some error")
	})
	t.Run("error-in-ssh-cert-libs-fn", func(t *testing.T) {
		t.Parallel()
		repo := &fakeVaultLibraryRepository{
			EstimatedLibraryCountFn: func(ctx context.Context) (int, error) {
				return 5, nil
			},
			EstimatedSSHCertificateLibraryCountFn: func(ctx context.Context) (int, error) {
				return 0, errors.New("some error")
			},
		}
		service, err := credential.NewLibraryService(ctx, &fakeWriter{}, repo)
		require.NoError(t, err)
		_, err = service.EstimatedCount(ctx)
		require.ErrorContains(t, err, "some error")
	})
}

func TestLibraryService_ListDeletedIds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		timeSince := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
		repo := &fakeVaultLibraryRepository{
			ListDeletedLibraryIdsFn: func(ctx context.Context, since time.Time, opt ...credential.Option) ([]string, error) {
				assert.True(t, since.Equal(timeSince))
				opts, err := credential.GetOpts(opt...)
				require.NoError(t, err)
				assert.NotNil(t, opts.WithReader)
				return []string{"a", "b"}, nil
			},
			ListDeletedSSHCertificateLibraryIdsFn: func(ctx context.Context, since time.Time, opt ...credential.Option) ([]string, error) {
				assert.True(t, since.Equal(timeSince))
				opts, err := credential.GetOpts(opt...)
				require.NoError(t, err)
				assert.NotNil(t, opts.WithReader)
				return []string{"c", "d"}, nil
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
		service, err := credential.NewLibraryService(ctx, writer, repo)
		require.NoError(t, err)
		ids, ttime, err := service.ListDeletedIds(ctx, timeSince)
		require.NoError(t, err)
		assert.Empty(
			t,
			cmp.Diff([]string{"a", "b", "c", "d"},
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
		repo := &fakeVaultLibraryRepository{
			ListDeletedLibraryIdsFn: func(ctx context.Context, since time.Time, opt ...credential.Option) ([]string, error) {
				assert.True(t, since.Equal(timeSince))
				opts, err := credential.GetOpts(opt...)
				require.NoError(t, err)
				assert.NotNil(t, opts.WithReader)
				return []string{"a", "b"}, nil
			},
			ListDeletedSSHCertificateLibraryIdsFn: func(ctx context.Context, since time.Time, opt ...credential.Option) ([]string, error) {
				assert.True(t, since.Equal(timeSince))
				opts, err := credential.GetOpts(opt...)
				require.NoError(t, err)
				assert.NotNil(t, opts.WithReader)
				return []string{"c", "d"}, nil
			},
		}
		writer := &fakeWriter{
			DoTxFn: func(ctx context.Context, retries uint, backoff db.Backoff, handler db.TxHandler) (db.RetryInfo, error) {
				return db.RetryInfo{}, errors.New("some error")
			},
		}
		service, err := credential.NewLibraryService(ctx, writer, repo)
		require.NoError(t, err)
		_, _, err = service.ListDeletedIds(ctx, timeSince)
		require.ErrorContains(t, err, "some error")
	})
	t.Run("first-list-fails", func(t *testing.T) {
		t.Parallel()
		timeSince := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
		repo := &fakeVaultLibraryRepository{
			ListDeletedLibraryIdsFn: func(ctx context.Context, since time.Time, opt ...credential.Option) ([]string, error) {
				return nil, errors.New("some error")
			},
			ListDeletedSSHCertificateLibraryIdsFn: func(ctx context.Context, since time.Time, opt ...credential.Option) ([]string, error) {
				assert.True(t, since.Equal(timeSince))
				opts, err := credential.GetOpts(opt...)
				require.NoError(t, err)
				assert.NotNil(t, opts.WithReader)
				return []string{"c", "d"}, nil
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
		service, err := credential.NewLibraryService(ctx, writer, repo)
		require.NoError(t, err)
		_, _, err = service.ListDeletedIds(ctx, timeSince)
		require.ErrorContains(t, err, "some error")
	})
	t.Run("second-list-fails", func(t *testing.T) {
		t.Parallel()
		timeSince := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
		repo := &fakeVaultLibraryRepository{
			ListDeletedLibraryIdsFn: func(ctx context.Context, since time.Time, opt ...credential.Option) ([]string, error) {
				assert.True(t, since.Equal(timeSince))
				opts, err := credential.GetOpts(opt...)
				require.NoError(t, err)
				assert.NotNil(t, opts.WithReader)
				return []string{"a", "b"}, nil
			},
			ListDeletedSSHCertificateLibraryIdsFn: func(ctx context.Context, since time.Time, opt ...credential.Option) ([]string, error) {
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
		service, err := credential.NewLibraryService(ctx, writer, repo)
		require.NoError(t, err)
		_, _, err = service.ListDeletedIds(ctx, timeSince)
		require.ErrorContains(t, err, "some error")
	})
}
