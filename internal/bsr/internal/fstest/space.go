// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package fstest provides test implementations of the fs interfaces.
package fstest

import (
	"context"
	"errors"
	"fmt"
	sfs "io/fs"
	"sync"

	"github.com/hashicorp/boundary/internal/storage"
)

// ErrOutOfSpace is used when the FS is out of space.
var ErrOutOfSpace = errors.New("no space left on device")

// LimitedSpaceFS is a test FS that can simulate running out of disk space.
type LimitedSpaceFS struct {
	*MemFS

	outOfSpace bool
	sync.RWMutex
}

// SetOutOfSpace is a helper to mark the file system as being out of space.
func (l *LimitedSpaceFS) SetOutOfSpace(b bool) {
	l.Lock()
	defer l.Unlock()
	l.outOfSpace = b
}

// OutOfSpace is used to check if the filesystem is out of space in a concurrent safe way.
func (l *LimitedSpaceFS) OutOfSpace() bool {
	l.RLock()
	defer l.RUnlock()
	return l.outOfSpace
}

// NewLimitedSpaceFS creates a LimitedSpaceFS. It supports WithNewFunc, WithReadOnly.
func NewLimitedSpaceFS(options ...Option) *LimitedSpaceFS {
	return &LimitedSpaceFS{
		MemFS: NewMemFS(options...),
	}
}

// New creates a storage.Container in the LimitedSpaceFS.
func (l *LimitedSpaceFS) New(ctx context.Context, n string) (storage.Container, error) {
	if l.OutOfSpace() {
		return nil, ErrOutOfSpace
	}
	c, err := l.MemFS.New(ctx, n)
	if err != nil {
		return nil, err
	}

	cc := c.(*MemContainer)
	return &LimitedSpaceContainer{
		MemContainer: cc,
		fs:           l,
	}, nil
}

// Open opens an existing a storage.Container from the LimitedSpaceFS.
func (l *LimitedSpaceFS) Open(ctx context.Context, n string) (storage.Container, error) {
	return l.MemFS.Open(ctx, n)
}

// LimitedSpaceContainer is a storage.Container that resides in memory.
type LimitedSpaceContainer struct {
	*MemContainer

	fs *LimitedSpaceFS
}

// Close closes the container.
func (l *LimitedSpaceContainer) Close() error {
	return l.MemContainer.Close()
}

// Create makes a new storage.File in the container.
func (l *LimitedSpaceContainer) Create(ctx context.Context, n string) (storage.File, error) {
	if l.fs.OutOfSpace() {
		return nil, ErrOutOfSpace
	}
	f, err := l.MemContainer.Create(ctx, n)
	if err != nil {
		return nil, err
	}
	ff := f.(*MemFile)
	return &LimitedSpaceFile{
		MemFile: ff,
		fs:      l.fs,
	}, nil
}

// OpenFile creates a storage.File in the container using the provided options
// It supports WithCloseSyncMode.
func (l *LimitedSpaceContainer) OpenFile(ctx context.Context, n string, option ...storage.Option) (storage.File, error) {
	if l.fs.OutOfSpace() {
		return nil, ErrOutOfSpace
	}
	f, err := l.MemContainer.OpenFile(ctx, n, option...)
	if err != nil {
		return nil, err
	}
	ff := f.(*MemFile)
	return &LimitedSpaceFile{
		MemFile: ff,
		fs:      l.fs,
	}, nil
}

// SubContainer creates a new storage.Container in the container.
func (l *LimitedSpaceContainer) SubContainer(ctx context.Context, n string, option ...storage.Option) (storage.Container, error) {
	if l.fs.OutOfSpace() {
		return nil, ErrOutOfSpace
	}
	c, err := l.MemContainer.SubContainer(ctx, n, option...)
	if err != nil {
		return nil, err
	}

	cc := c.(*MemContainer)
	return &LimitedSpaceContainer{
		MemContainer: cc,
		fs:           l.fs,
	}, nil
}

// LimitedSpaceFile is a storage.File that resides in memory.
type LimitedSpaceFile struct {
	*MemFile

	fs *LimitedSpaceFS
}

// Stat returns the FileInfo for the file.
func (l *LimitedSpaceFile) Stat() (sfs.FileInfo, error) {
	return l.MemFile.Stat()
}

func (l *LimitedSpaceFile) Read(p []byte) (int, error) {
	return l.MemFile.Read(p)
}

// Close closes the file.
func (l *LimitedSpaceFile) Close() error {
	return l.MemFile.Close()
}

// WriteString implements io.StringWriter.
func (l *LimitedSpaceFile) WriteString(s string) (n int, err error) {
	return l.Write([]byte(s))
}

func (l *LimitedSpaceFile) Write(p []byte) (n int, err error) {
	if l.fs.OutOfSpace() {
		return 0, fmt.Errorf("%s %w", l.MemFile.name, ErrOutOfSpace)
	}
	return l.MemFile.Write(p)
}

func (l *LimitedSpaceFile) WriteAndClose(p []byte) (n int, err error) {
	if l.fs.OutOfSpace() {
		return 0, fmt.Errorf("%s %w", l.MemFile.name, ErrOutOfSpace)
	}
	n, err = l.MemFile.Write(p)
	if err != nil {
		return n, err
	}
	return n, l.MemFile.Close()
}
