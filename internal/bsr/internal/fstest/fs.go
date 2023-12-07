// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


// Package fstest provides test implementations of the fs interfaces.
package fstest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	sfs "io/fs"

	"github.com/hashicorp/boundary/internal/storage"
)

// Common erorrs
var (
	ErrClosed        = errors.New("closed")
	ErrAlreadyExists = errors.New("already exists")
	ErrDoesNotExist  = errors.New("does not exist")
	ErrReadOnly      = errors.New("read-only")
)

const (
	defaultContainerPerm = 0o775
	defaultFilePerm      = 0o644
)

// MemFS is a storage.FS that only resides in memory.
type MemFS struct {
	Containers map[string]*MemContainer

	newFunc  NewFunc
	readOnly bool
}

// NewMemFS creates a MemFS. It supports WithNewFunc, WithReadOnly.
func NewMemFS(options ...Option) *MemFS {
	opts := getOpts(options...)

	return &MemFS{
		Containers: make(map[string]*MemContainer),
		newFunc:    opts.withNewFunc,
		readOnly:   opts.withReadOnly,
	}
}

// New creates a storage.Container in the MemFS.
func (m *MemFS) New(ctx context.Context, n string) (storage.Container, error) {
	if m.newFunc != nil {
		return m.newFunc(ctx, n)
	}

	if m.readOnly {
		return nil, fmt.Errorf("cannot create new container from read-only fs: %w", ErrReadOnly)
	}

	if m.Containers == nil {
		m.Containers = make(map[string]*MemContainer)
	}
	if _, exists := m.Containers[n]; exists {
		return nil, fmt.Errorf("container %s already exists: %w", n, ErrAlreadyExists)
	}

	c := &MemContainer{
		Name:       n,
		Sub:        make(map[string]*MemContainer),
		Files:      make(map[string]*MemFile),
		mode:       defaultContainerPerm,
		accessMode: storage.ReadWrite,
	}
	m.Containers[n] = c
	return c, nil
}

// Open opens an existing a storage.Container from the MemFS.
func (m *MemFS) Open(_ context.Context, n string) (storage.Container, error) {
	if m.Containers == nil {
		return nil, fmt.Errorf("container %s not found: %w", n, ErrDoesNotExist)
	}

	c, ok := m.Containers[n]
	if !ok {
		return nil, fmt.Errorf("container %s not found: %w", n, ErrDoesNotExist)
	}
	c.Closed = false
	return c, nil
}

// MemContainer is a storage.Container that resides in memory.
type MemContainer struct {
	Name string

	Sub   map[string]*MemContainer
	Files map[string]*MemFile

	Closed bool

	accessMode storage.AccessMode
	mode       sfs.FileMode

	sync.RWMutex
}

// Close closes the container.
func (m *MemContainer) Close() error {
	m.Lock()
	defer m.Unlock()
	m.Closed = true
	return nil
}

// Create makes a new storage.File in the container.
func (m *MemContainer) Create(ctx context.Context, n string) (storage.File, error) {
	if m.Closed {
		return nil, fmt.Errorf("create on closed container: %w", ErrClosed)
	}
	return m.OpenFile(ctx, n, storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite))
}

// OpenFile creates a storage.File in the container using the provided options
// It supports WithCloseSyncMode.
func (m *MemContainer) OpenFile(_ context.Context, n string, option ...storage.Option) (storage.File, error) {
	m.Lock()
	defer m.Unlock()

	if m.Closed {
		return nil, fmt.Errorf("create on closed container: %w", ErrClosed)
	}
	opts := storage.GetOpts(option...)

	if m.accessMode == storage.ReadOnly && opts.WithFileAccessMode != storage.ReadOnly {
		return nil, fmt.Errorf("cannot create writeable file in readonly container: %w", ErrReadOnly)
	}

	if opts.WithCreateFile && opts.WithFileAccessMode == storage.ReadOnly {
		return nil, fmt.Errorf("cannot create file in read-only mode: %w", ErrReadOnly)
	}

	var f *MemFile

	if opts.WithCreateFile {
		// create or truncate just like os.Create
		f = &MemFile{
			Buf: bytes.NewBuffer([]byte{}),
		}
	} else {
		var ok bool
		f, ok = m.Files[n]
		if !ok {
			return nil, fmt.Errorf("file %s does not exist: %w", n, ErrDoesNotExist)
		}
	}

	f.name = n
	f.syncMode = opts.WithCloseSyncMode
	f.accessMode = opts.WithFileAccessMode
	f.mode = defaultFilePerm
	f.Closed = false
	m.Files[n] = f
	return f, nil
}

// SubContainer creates a new storage.Container in the container.
func (m *MemContainer) SubContainer(_ context.Context, n string, option ...storage.Option) (storage.Container, error) {
	m.Lock()
	defer m.Unlock()
	if m.Closed {
		return nil, fmt.Errorf("subcontainer on closed container: %w", ErrClosed)
	}
	opts := storage.GetOpts(option...)

	c, exists := m.Sub[n]

	if opts.WithCreateFile && opts.WithFileAccessMode == storage.ReadOnly {
		return nil, fmt.Errorf("cannot create container in read-only mode: %w", ErrReadOnly)
	}

	if opts.WithCreateFile {
		if exists {
			return nil, fmt.Errorf("container %s already exists: %w", n, ErrAlreadyExists)
		}
		c = &MemContainer{
			Name:  n,
			Sub:   make(map[string]*MemContainer),
			Files: make(map[string]*MemFile),
		}
	} else {
		if !exists {
			return nil, fmt.Errorf("container %s does not exist: %w", n, ErrDoesNotExist)
		}
	}
	c.accessMode = opts.WithFileAccessMode
	c.Closed = false
	m.Sub[n] = c
	return c, nil
}

// memFileInfo implements storage.FileInfo
type memFileInfo struct {
	name string
	size int64
	mode sfs.FileMode
	mod  time.Time
}

func (m *memFileInfo) Name() string       { return m.name }
func (m *memFileInfo) Size() int64        { return m.size }
func (m *memFileInfo) Mode() sfs.FileMode { return m.mode }
func (m *memFileInfo) ModTime() time.Time { return m.mod }
func (m *memFileInfo) IsDir() bool        { return false }
func (m *memFileInfo) Sys() any           { return nil }

// MemFile is a storage.File that resides in memory.
type MemFile struct {
	name    string
	Buf     *bytes.Buffer
	mode    sfs.FileMode
	modtime time.Time

	statFunc  StatFunc
	closeFunc CloseFunc

	Closed     bool
	OutOfSpace bool

	syncMode   storage.SyncMode
	accessMode storage.AccessMode

	sync.RWMutex
}

// NewMemFile creates a MemFile. It supports WithCloseFunc and WithStatFunc
// to customize the behavior of Close and Stat.
func NewMemFile(n string, mode sfs.FileMode, options ...Option) *MemFile {
	opts := getOpts(options...)

	storageOpts := storage.GetOpts(opts.withStorageOptions...)

	return &MemFile{
		name:       n,
		Buf:        bytes.NewBuffer([]byte{}),
		mode:       mode,
		accessMode: storageOpts.WithFileAccessMode,
		syncMode:   storageOpts.WithCloseSyncMode,
		statFunc:   opts.withStatFunc,
		closeFunc:  opts.withCloseFunc,
	}
}

// NewWritableMemFile is a convinence function to create a MemFile with the
// WriteOnly storage access mode.
func NewWritableMemFile(n string, options ...Option) *MemFile {
	opts := getOpts(options...)

	return &MemFile{
		name:       n,
		Buf:        bytes.NewBuffer([]byte{}),
		mode:       0o664,
		accessMode: storage.WriteOnly,
		syncMode:   storage.Asynchronous,
		statFunc:   opts.withStatFunc,
		closeFunc:  opts.withCloseFunc,
	}
}

// Stat returns the FileInfo for the file.
func (m *MemFile) Stat() (sfs.FileInfo, error) {
	m.RLock()
	defer m.RUnlock()

	if m.Closed {
		return nil, fmt.Errorf("stat on closed file")
	}

	if m.statFunc != nil {
		return m.statFunc()
	}
	return &memFileInfo{
		name: m.name,
		size: int64(m.Buf.Len()),
		mode: m.mode,
		mod:  m.modtime,
	}, nil
}

func (m *MemFile) Read(p []byte) (int, error) {
	m.RLock()
	defer m.RUnlock()

	if m.accessMode == storage.WriteOnly {
		return 0, fmt.Errorf("read on write-only file")
	}

	if m.Closed {
		return 0, fmt.Errorf("read on closed file")
	}
	return m.Buf.Read(p)
}

// Close closes the file.
func (m *MemFile) Close() error {
	m.Lock()
	defer m.Unlock()

	if m.Closed {
		return fmt.Errorf("close on closed file")
	}

	if m.closeFunc != nil {
		return m.closeFunc()
	}
	m.Closed = true
	return nil
}

// WriteString implements io.StringWriter.
func (m *MemFile) WriteString(s string) (n int, err error) {
	return m.Write([]byte(s))
}

func (m *MemFile) Write(p []byte) (n int, err error) {
	m.Lock()
	defer m.Unlock()

	if m.Closed {
		return 0, fmt.Errorf("write on closed file")
	}

	if m.accessMode == storage.ReadOnly {
		return 0, fmt.Errorf("write on read-only file")
	}

	if m.OutOfSpace {
		return 0, fmt.Errorf("write failed, no space left on device")
	}
	defer func() {
		m.modtime = time.Now()
	}()
	return m.Buf.Write(p)
}

// TempFile implements storage.TempFile
type TempFile struct {
	*os.File
}

// NewTempFile creates a TempFile.
func NewTempFile(n string) (*TempFile, error) {
	f, err := os.CreateTemp("", n)
	if err != nil {
		return nil, err
	}
	return &TempFile{
		File: f,
	}, nil
}

// Close will close and remove the TempFile
func (t *TempFile) Close() error {
	fname, err := t.File.Stat()
	if err != nil {
		return err
	}
	if err := t.File.Close(); err != nil {
		return err
	}
	return os.Remove(fname.Name())
}
