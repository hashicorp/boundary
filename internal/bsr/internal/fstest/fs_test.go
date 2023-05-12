// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package fstest_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
	"github.com/hashicorp/boundary/internal/storage"
	"github.com/stretchr/testify/require"
)

// Test options that only MemFS supports
func TestMemFSNew(t *testing.T) {
	ctx := context.Background()

	errCustom := errors.New("custom error from new")

	cases := []struct {
		name    string
		m       *fstest.MemFS
		n       string
		wantErr error
	}{
		{
			"read-only",
			fstest.NewMemFS(fstest.WithReadOnly(true)),
			"test",
			fstest.ErrReadOnly,
		},
		{
			"custom-new-func",
			fstest.NewMemFS(fstest.WithNewFunc(func(_ context.Context, _ string) (storage.Container, error) {
				return nil, errCustom
			})),
			"test",
			errCustom,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := tc.m.New(ctx, tc.n)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, c)
		})
	}
}

func TestFSNew(t *testing.T) {
	ctx := context.Background()

	fsCases := []struct {
		name  string
		newFs func(t *testing.T) storage.FS
	}{
		{
			"MemFS",
			func(t *testing.T) storage.FS { return fstest.NewMemFS() },
		},
		{
			"LocalFS",
			func(t *testing.T) storage.FS {
				d, err := os.MkdirTemp("", "localfs")
				require.NoError(t, err)
				t.Cleanup(func() {
					os.RemoveAll(d)
				})
				return fstest.NewLocalFS(ctx, d)
			},
		},
	}
	cases := []struct {
		name    string
		n       string
		setupFn func(t *testing.T, fs storage.FS)
		wantErr error
	}{
		{
			"default",
			"test",
			nil,
			nil,
		},
		{
			"already-exists",
			"test",
			func(t *testing.T, fs storage.FS) {
				_, err := fs.New(ctx, "test")
				require.NoError(t, err)
			},
			fstest.ErrAlreadyExists,
		},
	}

	for _, tfs := range fsCases {
		t.Run(tfs.name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					f := tfs.newFs(t)
					if tc.setupFn != nil {
						tc.setupFn(t, f)
					}
					c, err := f.New(ctx, tc.n)
					if tc.wantErr != nil {
						require.ErrorIs(t, err, tc.wantErr)
						return
					}
					require.NoError(t, err)
					require.NotNil(t, c)
				})
			}
		})
	}
}

func TestFSOpen(t *testing.T) {
	ctx := context.Background()

	fsCases := []struct {
		name  string
		newFs func(t *testing.T) storage.FS
	}{
		{
			"MemFS",
			func(t *testing.T) storage.FS { return fstest.NewMemFS() },
		},
		{
			"LocalFS",
			func(t *testing.T) storage.FS {
				d, err := os.MkdirTemp("", "localfs")
				require.NoError(t, err)
				t.Cleanup(func() {
					os.RemoveAll(d)
				})
				return fstest.NewLocalFS(ctx, d)
			},
		},
	}
	cases := []struct {
		name    string
		setupFn func(t *testing.T, fs storage.FS)
		n       string
		wantErr error
	}{
		{
			"exists",
			func(t *testing.T, fs storage.FS) {
				_, err := fs.New(ctx, "test")
				require.NoError(t, err)
			},
			"test",
			nil,
		},
		{
			"does-not-exist",
			nil,
			"test",
			fstest.ErrDoesNotExist,
		},
	}
	for _, tfs := range fsCases {
		t.Run(tfs.name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					f := tfs.newFs(t)
					if tc.setupFn != nil {
						tc.setupFn(t, f)
					}
					c, err := f.Open(ctx, tc.n)
					if tc.wantErr != nil {
						require.ErrorIs(t, err, tc.wantErr)
						return
					}
					require.NoError(t, err)
					require.NotNil(t, c)
				})
			}
		})
	}
}

func TestContainerOpenFile(t *testing.T) {
	ctx := context.Background()

	fsCases := []struct {
		name  string
		newFs func(t *testing.T) storage.FS
	}{
		{
			"MemFS",
			func(t *testing.T) storage.FS { return fstest.NewMemFS() },
		},
		{
			"LocalFS",
			func(t *testing.T) storage.FS {
				d, err := os.MkdirTemp("", "localfs")
				require.NoError(t, err)
				t.Cleanup(func() {
					os.RemoveAll(d)
				})
				return fstest.NewLocalFS(ctx, d)
			},
		},
	}

	cases := []struct {
		name    string
		setupFn func(t *testing.T, f storage.FS) storage.Container
		n       string
		opts    []storage.Option
		wantErr error
	}{
		{
			"create",
			func(t *testing.T, f storage.FS) storage.Container {
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				return c
			},
			"test",
			[]storage.Option{storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite)},
			nil,
		},
		{
			"create-already-exists",
			func(t *testing.T, f storage.FS) storage.Container {
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				_, err = c.OpenFile(ctx, "test", storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite))
				require.NoError(t, err)
				return c
			},
			"test",
			[]storage.Option{storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite)},
			nil,
		},
		{
			"create-read-only",
			func(t *testing.T, f storage.FS) storage.Container {
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				return c
			},
			"test",
			[]storage.Option{storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadOnly)},
			fstest.ErrReadOnly,
		},
		{
			"read-only-does-not-exist",
			func(t *testing.T, f storage.FS) storage.Container {
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				return c
			},
			"test",
			[]storage.Option{storage.WithFileAccessMode(storage.ReadOnly)},
			fstest.ErrDoesNotExist,
		},
		{
			"read-only-exist",
			func(t *testing.T, f storage.FS) storage.Container {
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				_, err = c.OpenFile(ctx, "test", storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite))
				require.NoError(t, err)
				return c
			},
			"test",
			[]storage.Option{storage.WithFileAccessMode(storage.ReadOnly)},
			nil,
		},
	}
	for _, tfs := range fsCases {
		t.Run(tfs.name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					fs := tfs.newFs(t)
					c := tc.setupFn(t, fs)
					f, err := c.OpenFile(ctx, tc.n, tc.opts...)
					if tc.wantErr != nil {
						require.ErrorIs(t, err, tc.wantErr)
						return
					}
					require.NoError(t, err)
					require.NotNil(t, f)
				})
			}
		})
	}
}

func TestContainerCreate(t *testing.T) {
	ctx := context.Background()

	fsCases := []struct {
		name  string
		newFs func(t *testing.T) storage.FS
	}{
		{
			"MemFS",
			func(t *testing.T) storage.FS { return fstest.NewMemFS() },
		},
		{
			"LocalFS",
			func(t *testing.T) storage.FS {
				d, err := os.MkdirTemp("", "localfs")
				require.NoError(t, err)
				t.Cleanup(func() {
					os.RemoveAll(d)
				})
				return fstest.NewLocalFS(ctx, d)
			},
		},
	}

	cases := []struct {
		name    string
		setupFn func(t *testing.T, f storage.FS) storage.Container
		n       string
		wantErr error
	}{
		{
			"create",
			func(t *testing.T, f storage.FS) storage.Container {
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				return c
			},
			"test",
			nil,
		},
		{
			"create-already-exists",
			func(t *testing.T, f storage.FS) storage.Container {
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				_, err = c.OpenFile(ctx, "test", storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite))
				require.NoError(t, err)
				return c
			},
			"test",
			nil,
		},
	}
	for _, tfs := range fsCases {
		t.Run(tfs.name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					fs := tfs.newFs(t)
					c := tc.setupFn(t, fs)
					f, err := c.Create(ctx, tc.n)
					if tc.wantErr != nil {
						require.ErrorIs(t, err, tc.wantErr)
						return
					}
					require.NoError(t, err)
					require.NotNil(t, f)
				})
			}
		})
	}
}

func TestMemContainerSubContainer(t *testing.T) {
	ctx := context.Background()

	fsCases := []struct {
		name  string
		newFs func(t *testing.T) storage.FS
	}{
		{
			"MemFS",
			func(t *testing.T) storage.FS { return fstest.NewMemFS() },
		},
		{
			"LocalFS",
			func(t *testing.T) storage.FS {
				d, err := os.MkdirTemp("", "localfs")
				require.NoError(t, err)
				t.Cleanup(func() {
					os.RemoveAll(d)
				})
				return fstest.NewLocalFS(ctx, d)
			},
		},
	}
	cases := []struct {
		name    string
		setupFn func(t *testing.T, f storage.FS) storage.Container
		n       string
		opts    []storage.Option
		wantErr error
	}{
		{
			"create",
			func(t *testing.T, f storage.FS) storage.Container {
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				return c
			},
			"test",
			[]storage.Option{storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite)},
			nil,
		},
		{
			"create-already-exists",
			func(t *testing.T, f storage.FS) storage.Container {
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				_, err = c.SubContainer(ctx, "test", storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite))
				require.NoError(t, err)
				return c
			},
			"test",
			[]storage.Option{storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite)},
			fstest.ErrAlreadyExists,
		},
		{
			"create-read-only",
			func(t *testing.T, f storage.FS) storage.Container {
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				return c
			},
			"test",
			[]storage.Option{storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadOnly)},
			fstest.ErrReadOnly,
		},
		{
			"read-only-does-not-exist",
			func(t *testing.T, f storage.FS) storage.Container {
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				return c
			},
			"test",
			[]storage.Option{storage.WithFileAccessMode(storage.ReadOnly)},
			fstest.ErrDoesNotExist,
		},
		{
			"read-only-exist",
			func(t *testing.T, f storage.FS) storage.Container {
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				_, err = c.SubContainer(ctx, "test", storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite))
				require.NoError(t, err)
				return c
			},
			"test",
			[]storage.Option{storage.WithFileAccessMode(storage.ReadOnly)},
			nil,
		},
	}
	for _, tfs := range fsCases {
		t.Run(tfs.name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					fs := tfs.newFs(t)
					c := tc.setupFn(t, fs)
					sc, err := c.SubContainer(ctx, tc.n, tc.opts...)
					if tc.wantErr != nil {
						require.ErrorIs(t, err, tc.wantErr)
						return
					}
					require.NoError(t, err)
					require.NotNil(t, sc)
				})
			}
		})
	}
}
