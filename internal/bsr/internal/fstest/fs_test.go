// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package fstest_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
	"github.com/hashicorp/boundary/internal/storage"
	"github.com/stretchr/testify/assert"
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
		{
			"LimitedSpaceFS",
			func(t *testing.T) storage.FS { return fstest.NewLimitedSpaceFS() },
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
		{
			"LimitedSpaceFS",
			func(t *testing.T) storage.FS { return fstest.NewLimitedSpaceFS() },
		},
	}

	cases := []struct {
		name     string
		setupFn  func(t *testing.T, f storage.FS) storage.Container
		n        string
		opts     []storage.Option
		wantErr  error
		wantData string
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
			"",
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
			"",
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
			"",
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
			"",
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
			"",
		},
		{
			"open-twice",
			func(t *testing.T, f storage.FS) storage.Container {
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				w, err := c.OpenFile(ctx, "test", storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite))
				require.NoError(t, err)
				n, err := w.WriteString("hello world")
				require.NoError(t, err)
				require.Equal(t, len("hello world"), n)
				r, err := c.OpenFile(ctx, "test", storage.WithFileAccessMode(storage.ReadOnly))
				require.NoError(t, err)
				data := make([]byte, len("hello world"))
				n, err = r.Read(data)
				require.NoError(t, err)
				require.Equal(t, len("hello world"), n)
				return c
			},
			"test",
			[]storage.Option{storage.WithFileAccessMode(storage.ReadOnly)},
			nil,
			"hello world",
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
					if tc.wantData != "" {
						data := make([]byte, len(tc.wantData))
						n, err := f.Read(data)
						require.NoError(t, err)
						require.Equal(t, len(tc.wantData), n)
						require.Equal(t, tc.wantData, string(data))
					}
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
		{
			"LimitedSpaceFS",
			func(t *testing.T) storage.FS { return fstest.NewLimitedSpaceFS() },
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
		{
			"LimitedSpaceFS",
			func(t *testing.T) storage.FS { return fstest.NewLimitedSpaceFS() },
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

func TestOpeningFileTwice(t *testing.T) {
	ctx := context.Background()
	f := fstest.NewMemFS()
	c, err := f.New(ctx, "test")
	require.NoError(t, err)

	expectedData := "hello world"

	// Create File
	w, err := c.OpenFile(ctx, "test", storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite))
	require.NoError(t, err)
	n, err := w.WriteString(expectedData)
	require.NoError(t, err)
	require.Equal(t, len(expectedData), n)

	r1, err := c.OpenFile(ctx, "test", storage.WithFileAccessMode(storage.ReadOnly))
	require.NoError(t, err)
	r2, err := c.OpenFile(ctx, "test", storage.WithFileAccessMode(storage.ReadOnly))
	require.NoError(t, err)

	// reader 1 works independently from reader 2
	actualData := make([]byte, len(expectedData))
	n, err = r1.Read(actualData)
	require.NoError(t, err)
	require.Equal(t, len(expectedData), n)
	require.Equal(t, expectedData, string(actualData))

	// reader 2 works independently from reader 1
	actualData = make([]byte, len(expectedData))
	n, err = r2.Read(actualData)
	require.NoError(t, err)
	require.Equal(t, len(expectedData), n)
	require.Equal(t, expectedData, string(actualData))
}

func TestOutOfSpace(t *testing.T) {
	ctx := context.Background()

	line := []byte("foo")

	fs := fstest.NewLimitedSpaceFS()

	// Create some containers, subcontains and files.
	r, err := fs.New(ctx, "root")
	require.NoError(t, err)

	sub, err := r.SubContainer(ctx, "sub", storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite))
	require.NoError(t, err)

	f1, err := r.Create(ctx, "f1")
	require.NoError(t, err)
	c, err := f1.Write(line)
	require.NoError(t, err)
	assert.Equal(t, c, len(line))

	f2, err := sub.Create(ctx, "f2")
	require.NoError(t, err)
	c, err = f2.Write(line)
	require.NoError(t, err)
	assert.Equal(t, c, len(line))

	// Now mark out of space
	fs.SetOutOfSpace(true)

	// eixsing files can no longer write
	c, err = f1.Write(line)
	require.ErrorIs(t, err, fstest.ErrOutOfSpace)
	assert.Equal(t, 0, c)

	c, err = f2.Write(line)
	require.ErrorIs(t, err, fstest.ErrOutOfSpace)
	assert.Equal(t, 0, c)

	// existing containers cannot create new files
	f3, err := r.Create(ctx, "f3")
	require.ErrorIs(t, err, fstest.ErrOutOfSpace)
	assert.Nil(t, f3)

	f4, err := sub.Create(ctx, "f4")
	require.ErrorIs(t, err, fstest.ErrOutOfSpace)
	assert.Nil(t, f4)

	// existing containers cannot create sub containers
	sub2, err := r.SubContainer(ctx, "sub2", storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite))
	require.ErrorIs(t, err, fstest.ErrOutOfSpace)
	assert.Nil(t, sub2)

	sub3, err := sub.SubContainer(ctx, "sub3", storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite))
	require.ErrorIs(t, err, fstest.ErrOutOfSpace)
	assert.Nil(t, sub3)

	// fs cannot make a new container
	r2, err := fs.New(ctx, "root2")
	require.ErrorIs(t, err, fstest.ErrOutOfSpace)
	assert.Nil(t, r2)
}

func TestMemFile_WriteAndClose(t *testing.T) {
	mf := fstest.NewMemFile(
		"test-write-and-close-file",
		0o644,
		fstest.WithStorageOptions([]storage.Option{
			storage.WithFileAccessMode(storage.ReadWrite),
		}))
	require.False(t, mf.Closed, "MemFile is closed")

	str1 := "Input 1"
	n, err := mf.Write([]byte(str1))
	require.NoError(t, err)
	assert.NotNil(t, n)

	str2 := "Input 2"
	n, err = mf.WriteAndClose([]byte(str2))
	require.NoError(t, err)
	assert.NotNil(t, n)

	expectedString := "Input 1Input 2"
	assert.Equal(t, expectedString, mf.Buf.String())

	require.True(t, mf.Closed, "MemFile is not closed")
}
