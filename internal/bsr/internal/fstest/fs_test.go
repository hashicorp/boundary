// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package fstest_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
	"github.com/hashicorp/boundary/internal/storage"
	"github.com/stretchr/testify/require"
)

func TestMemFSNew(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name    string
		m       *fstest.MemFS
		n       string
		wantErr error
	}{
		{
			"default",
			fstest.NewMemFS(),
			"test",
			nil,
		},
		{
			"read-only",
			fstest.NewMemFS(fstest.WithReadOnly(true)),
			"test",
			errors.New("cannot create new container from read-only fs"),
		},
		{
			"custom-new-func",
			fstest.NewMemFS(fstest.WithNewFunc(func(_ context.Context, _ string) (storage.Container, error) {
				return nil, fmt.Errorf("custom error from new")
			})),
			"test",
			errors.New("custom error from new"),
		},
		{
			"already-exists",
			func() *fstest.MemFS {
				f := fstest.NewMemFS()
				_, err := f.New(ctx, "test")
				require.NoError(t, err)
				return f
			}(),
			"test",
			errors.New("container test already exists"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := tc.m.New(ctx, tc.n)
			if tc.wantErr != nil {
				require.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
			require.NotNil(t, c)
		})
	}
}

func TestMemFSOpen(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name    string
		m       *fstest.MemFS
		n       string
		wantErr error
	}{
		{
			"exists",
			func() *fstest.MemFS {
				f := fstest.NewMemFS()
				_, err := f.New(ctx, "test")
				require.NoError(t, err)
				return f
			}(),
			"test",
			nil,
		},
		{
			"does-not-exist",
			fstest.NewMemFS(),
			"test",
			errors.New("container test not found"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := tc.m.Open(ctx, tc.n)
			if tc.wantErr != nil {
				require.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
			require.NotNil(t, c)
		})
	}
}

func TestMemContainerOpenFile(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name    string
		c       *fstest.MemContainer
		n       string
		opts    []storage.Option
		wantErr error
	}{
		{
			"create",
			func() *fstest.MemContainer {
				f := fstest.NewMemFS()
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				cc := c.(*fstest.MemContainer)
				return cc
			}(),
			"test",
			[]storage.Option{storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite)},
			nil,
		},
		{
			"create-already-exists",
			func() *fstest.MemContainer {
				f := fstest.NewMemFS()
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				cc := c.(*fstest.MemContainer)
				_, err = cc.OpenFile(ctx, "test", storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite))
				require.NoError(t, err)
				return cc
			}(),
			"test",
			[]storage.Option{storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite)},
			nil,
		},
		{
			"create-read-only",
			func() *fstest.MemContainer {
				f := fstest.NewMemFS()
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				cc := c.(*fstest.MemContainer)
				return cc
			}(),
			"test",
			[]storage.Option{storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadOnly)},
			errors.New("cannot create file in read-only mode"),
		},
		{
			"read-only-does-not-exist",
			func() *fstest.MemContainer {
				f := fstest.NewMemFS()
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				cc := c.(*fstest.MemContainer)
				return cc
			}(),
			"test",
			[]storage.Option{storage.WithFileAccessMode(storage.ReadOnly)},
			errors.New("file test does not exist"),
		},
		{
			"read-only-exist",
			func() *fstest.MemContainer {
				f := fstest.NewMemFS()
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				cc := c.(*fstest.MemContainer)
				_, err = cc.OpenFile(ctx, "test", storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite))
				require.NoError(t, err)
				return cc
			}(),
			"test",
			[]storage.Option{storage.WithFileAccessMode(storage.ReadOnly)},
			nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := tc.c.OpenFile(ctx, tc.n, tc.opts...)
			if tc.wantErr != nil {
				require.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
			require.NotNil(t, c)
		})
	}
}

func TestMemContainerCreate(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name    string
		c       *fstest.MemContainer
		n       string
		wantErr error
	}{
		{
			"create",
			func() *fstest.MemContainer {
				f := fstest.NewMemFS()
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				cc := c.(*fstest.MemContainer)
				return cc
			}(),
			"test",
			nil,
		},
		{
			"create-already-exists",
			func() *fstest.MemContainer {
				f := fstest.NewMemFS()
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				cc := c.(*fstest.MemContainer)
				_, err = cc.OpenFile(ctx, "test", storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite))
				require.NoError(t, err)
				return cc
			}(),
			"test",
			nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := tc.c.Create(ctx, tc.n)
			if tc.wantErr != nil {
				require.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
			require.NotNil(t, c)
		})
	}
}

func TestMemContainerSubContainer(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name    string
		c       *fstest.MemContainer
		n       string
		opts    []storage.Option
		wantErr error
	}{
		{
			"create",
			func() *fstest.MemContainer {
				f := fstest.NewMemFS()
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				cc := c.(*fstest.MemContainer)
				return cc
			}(),
			"test",
			[]storage.Option{storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite)},
			nil,
		},
		{
			"create-already-exists",
			func() *fstest.MemContainer {
				f := fstest.NewMemFS()
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				cc := c.(*fstest.MemContainer)
				_, err = cc.SubContainer(ctx, "test", storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite))
				require.NoError(t, err)
				return cc
			}(),
			"test",
			[]storage.Option{storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite)},
			errors.New("container test already exists"),
		},
		{
			"create-read-only",
			func() *fstest.MemContainer {
				f := fstest.NewMemFS()
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				cc := c.(*fstest.MemContainer)
				return cc
			}(),
			"test",
			[]storage.Option{storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadOnly)},
			errors.New("cannot create container in read-only mode"),
		},
		{
			"read-only-does-not-exist",
			func() *fstest.MemContainer {
				f := fstest.NewMemFS()
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				cc := c.(*fstest.MemContainer)
				return cc
			}(),
			"test",
			[]storage.Option{storage.WithFileAccessMode(storage.ReadOnly)},
			errors.New("container test does not exist"),
		},
		{
			"read-only-exist",
			func() *fstest.MemContainer {
				f := fstest.NewMemFS()
				c, err := f.New(ctx, "test")
				require.NoError(t, err)
				cc := c.(*fstest.MemContainer)
				_, err = cc.SubContainer(ctx, "test", storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite))
				require.NoError(t, err)
				return cc
			}(),
			"test",
			[]storage.Option{storage.WithFileAccessMode(storage.ReadOnly)},
			nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := tc.c.SubContainer(ctx, tc.n, tc.opts...)
			if tc.wantErr != nil {
				require.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
			require.NotNil(t, c)
		})
	}
}
