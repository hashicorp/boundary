// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package fstest provides test implementations of a the fs interfaces.
package fstest

import (
	"bytes"
	"context"
	"fmt"
	"time"

	sfs "io/fs"

	"github.com/hashicorp/boundary/internal/storage"
)

// MemFS is a storage.FS that only resides in memory.
type MemFS struct {
	Containers map[string]*MemContainer

	newFunc NewFunc
}

// NewMemFS creates a MemFS. It supports WithNewFunc.
func NewMemFS(options ...Option) *MemFS {
	opts := getOpts(options...)

	return &MemFS{
		Containers: make(map[string]*MemContainer),
		newFunc:    opts.withNewFunc,
	}
}

// New creates a storage.Container in the MemFS.
func (m *MemFS) New(ctx context.Context, n string) (storage.Container, error) {
	if m.newFunc != nil {
		return m.newFunc(ctx, n)
	}
	if m.Containers == nil {
		m.Containers = make(map[string]*MemContainer)
	}
	if _, exists := m.Containers[n]; exists {
		return nil, fmt.Errorf("container %s already exists", n)
	}
	c := &MemContainer{
		Name:  n,
		Sub:   make(map[string]*MemContainer),
		Files: make(map[string]*MemFile),
	}
	m.Containers[n] = c
	return c, nil
}

// MemContainer is a storage.Container that resides in memory.
type MemContainer struct {
	Name string

	Sub   map[string]*MemContainer
	Files map[string]*MemFile

	Closed bool
}

// Close closes the container.
func (m *MemContainer) Close() error {
	m.Closed = true
	return nil
}

// Create makes a new storage.File in the container.
func (m *MemContainer) Create(_ context.Context, n string) (storage.File, error) {
	if m.Closed {
		return nil, fmt.Errorf("create on closed container")
	}
	if _, exists := m.Files[n]; exists {
		return nil, fmt.Errorf("file %s already exists", n)
	}
	f := &MemFile{
		name: n,
		Buf:  bytes.NewBuffer([]byte{}),
		mode: sfs.ModeAppend,
	}
	m.Files[n] = f
	return f, nil
}

// OpenFile creates a storage.File in the container using the provided options
// It supports WithCloseSyncMode.
func (m *MemContainer) OpenFile(_ context.Context, n string, option ...storage.Option) (storage.File, error) {
	opts := storage.GetOpts(option...)
	if m.Closed {
		return nil, fmt.Errorf("create on closed container")
	}
	if _, exists := m.Files[n]; exists {
		return nil, fmt.Errorf("file %s already exists", n)
	}

	var mode sfs.FileMode

	switch opts.WithCloseSyncMode {
	case storage.NoSync:
		mode = sfs.ModeAppend | sfs.ModeTemporary
	default:
		mode = sfs.ModeAppend
	}

	f := &MemFile{
		name: n,
		Buf:  bytes.NewBuffer([]byte{}),
		mode: mode,
	}
	m.Files[n] = f
	return f, nil
}

// SubContainer creates a new storage.Container in the container.
func (m *MemContainer) SubContainer(_ context.Context, n string, _ ...storage.Option) (storage.Container, error) {
	if _, exists := m.Sub[n]; exists {
		return nil, fmt.Errorf("container %s already exists", n)
	}
	c := &MemContainer{
		Name:  n,
		Sub:   make(map[string]*MemContainer),
		Files: make(map[string]*MemFile),
	}
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

	Closed bool
}

// NewMemFile creates a MemFile. It supports WithCloseFunc and WithStatFunc
// to customize the behavior of Close and Stat.
func NewMemFile(n string, mode sfs.FileMode, options ...Option) *MemFile {
	opts := getOpts(options...)

	return &MemFile{
		name:      n,
		Buf:       bytes.NewBuffer([]byte{}),
		mode:      mode,
		statFunc:  opts.withStatFunc,
		closeFunc: opts.withCloseFunc,
	}
}

// Stat returns the FileInfo for the file.
func (m *MemFile) Stat() (sfs.FileInfo, error) {
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
	return m.Buf.Read(p)
}

// Close closes the file.
func (m *MemFile) Close() error {
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
	if m.Closed {
		return 0, fmt.Errorf("write on closed file")
	}

	defer func() {
		m.modtime = time.Now()
	}()
	return m.Buf.Write(p)
}
