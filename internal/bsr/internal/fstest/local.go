// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package fstest

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hashicorp/boundary/internal/storage"
)

// LocalFS is a test filesystem that creates files in the provided directory.
type LocalFS struct {
	Path string
}

// NewLocalFS creates a LocalFS.
func NewLocalFS(_ context.Context, p string) *LocalFS {
	return &LocalFS{
		Path: p,
	}
}

// New creates the named root container within the local FS.
// Calls to New make use of the os.Mkdir locking and error handling
// to ensure that the directory being made is a valid directory and does not
// exist.
func (fs *LocalFS) New(_ context.Context, name string) (storage.Container, error) {
	const op = "fstest.(LocalFS).New"
	if name == "" {
		return nil, fmt.Errorf("%s: missing name", op)
	}
	path, err := joinPath(fs.Path, name)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if err := os.Mkdir(path, defaultContainerPerm); err != nil {
		return nil, fmt.Errorf("%s: %w: %w", op, err, ErrAlreadyExists)
	}

	return &LocalContainer{
		Path:   path,
		IsRoot: true,
	}, nil
}

// Open opens an existing root container.
func (fs *LocalFS) Open(_ context.Context, name string) (storage.Container, error) {
	const op = "fstest.(LocalFS).Open"
	path, err := joinPath(fs.Path, name)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", op, err, ErrDoesNotExist)
	}
	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", op, err, ErrDoesNotExist)
	}

	if !stat.IsDir() {
		return nil, fmt.Errorf("%s not a dir: %w", name, ErrDoesNotExist)
	}

	return &LocalContainer{
		Path:   path,
		IsRoot: true,
	}, nil
}

// joinPath joins a parent path with the single name child container or file.
// The name cannot contain any path seperators.
// The name cannot contain `..`
// The subpath returned will be a child of the parent.
func joinPath(parentPath, name string) (string, error) {
	// Check if name has any OS path separator and fail if it does
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return "", fmt.Errorf("name contains path separator")
	}

	subPath := filepath.Join(parentPath, name)
	if len(parentPath) >= len(subPath) {
		return "", fmt.Errorf("new path must be longer than parent")
	}

	rel, err := filepath.Rel(parentPath, subPath)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("subpath must be within current container")
	}

	return subPath, nil
}

// LocalContainer is a storage.Container backed by a os.File that is a directory.
type LocalContainer struct {
	Path   string
	closed bool
	IsRoot bool

	sync.RWMutex
}

// Sub returns a map of subcontainers in this container where the key is the name
// of the container.
func (c *LocalContainer) Sub(ctx context.Context) (map[string]*LocalContainer, error) {
	sub := make(map[string]*LocalContainer, 0)

	err := filepath.WalkDir(c.Path, func(path string, d fs.DirEntry, _ error) error {
		if !d.IsDir() {
			// continue to next file if not a directory
			return nil
		}

		// If the root, continue the walk
		if path == c.Path {
			return nil
		}
		bn := filepath.Base(path)
		cc, err := c.SubContainer(ctx, bn, storage.WithFileAccessMode(storage.ReadWrite))
		if err != nil {
			return err
		}
		sub[bn] = cc.(*LocalContainer)
		// Only do one level, don't walk down into each directory.
		return filepath.SkipDir
	})
	return sub, err
}

// Close closes the container.
func (c *LocalContainer) Close() error {
	const op = "fstest.(LocalContainer).Close"
	c.Lock()
	defer c.Unlock()
	c.closed = true

	return nil
}

// Create creates a new storage.File in the container.
func (c *LocalContainer) Create(ctx context.Context, name string) (storage.File, error) {
	const op = "fstest.(LocalContainer).Create"
	file, err := c.OpenFile(ctx, name, storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return file, nil
}

// OpenFile opens a file in the container.
// Supports the following options:
// - WithCloseSyncMode: This is ignored by stored on the LocalContainer for test assertions.
// - WithFileAccessMode: Sets the access mode for the file. If opened with Write, it will also be append.
// - WithCreateFile: Creates the file if it does not exist. If the file does exists, it is truncated.
func (c *LocalContainer) OpenFile(ctx context.Context, name string, options ...storage.Option) (storage.File, error) {
	const op = "fstest.(LocalContainer).OpenFile"
	c.Lock()
	defer c.Unlock()
	if c.closed {
		return nil, fmt.Errorf("%s: container closed: %w", op, ErrClosed)
	}
	if name == "" {
		return nil, fmt.Errorf("%s: missing name", op)
	}
	path, err := joinPath(c.Path, name)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	opts := storage.GetOpts(options...)

	if opts.WithCreateFile && opts.WithFileAccessMode == storage.ReadOnly {
		return nil, fmt.Errorf("cannot create file in read-only mode: %w", ErrReadOnly)
	}

	var fileFlag int
	switch opts.WithFileAccessMode {
	case storage.WriteOnly:
		fileFlag = os.O_WRONLY
	case storage.ReadWrite:
		fileFlag = os.O_RDWR
	default:
		fileFlag = os.O_RDONLY
	}

	switch {
	case opts.WithCreateFile:
		fileFlag |= os.O_CREATE | os.O_TRUNC
	default:
		fileFlag |= os.O_APPEND
	}

	file, err := os.OpenFile(path, fileFlag, defaultFilePerm)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", op, err, ErrDoesNotExist)
	}

	fi, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("%s: file is a directory", op)
	}

	return &LocalFile{
		ctx:        ctx,
		File:       file,
		Path:       path,
		SyncMode:   opts.WithCloseSyncMode,
		AccessMode: opts.WithFileAccessMode,
	}, nil
}

// SubContainer creates or opens a container in this container.
func (c *LocalContainer) SubContainer(_ context.Context, name string, options ...storage.Option) (storage.Container, error) {
	const op = "fstest.(LocalContainer).SubContainer"
	c.Lock()
	defer c.Unlock()
	if c.closed {
		return nil, fmt.Errorf("%s: container closed: %w", op, ErrClosed)
	}
	if name == "" {
		return nil, fmt.Errorf("%s: missing name", op)
	}
	opts := storage.GetOpts(options...)
	if opts.WithCreateFile && opts.WithFileAccessMode == storage.ReadOnly {
		return nil, fmt.Errorf("%s: cannot create container in read-only mode: %w", op, ErrReadOnly)
	}

	path, err := joinPath(c.Path, name)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if opts.WithCreateFile {
		if err := os.Mkdir(path, defaultContainerPerm); err != nil {
			return nil, fmt.Errorf("%s: %w: %w", op, err, ErrAlreadyExists)
		}
	} else {
		stat, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w: %w", op, err, ErrDoesNotExist)
		}

		if !stat.IsDir() {
			return nil, fmt.Errorf("%s: %w: %w", op, err, ErrDoesNotExist)
		}
	}

	return &LocalContainer{
		Path: path,
	}, nil
}

// LocalFile is a storage.File backed by a os.File.
type LocalFile struct {
	ctx context.Context

	Path       string
	File       *os.File
	SyncMode   storage.SyncMode
	AccessMode storage.AccessMode
	closed     bool

	sync.RWMutex
}

// Stat returns the FileInfo structure describing file.
func (f *LocalFile) Stat() (fs.FileInfo, error) {
	const op = "fstest.(LocalFile).Stat"
	f.RLock()
	defer f.RUnlock()
	if f.closed {
		return nil, fmt.Errorf("%s: file is closed", op)
	}

	fi, err := f.File.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return fi, nil
}

func (f *LocalFile) Read(b []byte) (int, error) {
	const op = "fstest.(localFile).Read"
	f.RLock()
	defer f.RUnlock()
	if f.closed {
		return 0, fmt.Errorf("%s: file is closed", op)
	}
	if f.AccessMode == storage.WriteOnly {
		return 0, fmt.Errorf("%s: file is write-only", op)
	}

	n, err := f.File.Read(b)
	if err != nil {
		if err == io.EOF {
			return n, err
		}
		return n, fmt.Errorf("%s: %w", op, err)
	}
	return n, nil
}

// Close closes the file preventing reads or writes.
func (f *LocalFile) Close() error {
	f.Lock()
	defer f.Unlock()

	return f.close()
}

func (f *LocalFile) close() error {
	const op = "fstest.(LocalFile).close"

	if f.closed {
		return nil
	}

	if err := f.File.Close(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	f.closed = true
	return nil
}

func (f *LocalFile) Write(b []byte) (int, error) {
	f.Lock()
	defer f.Unlock()

	return f.write(b)
}

func (f *LocalFile) write(b []byte) (int, error) {
	const op = "fstest.(localFile).write"

	if f.closed {
		return 0, fmt.Errorf("%s: file is closed", op)
	}
	if f.AccessMode == storage.ReadOnly {
		return 0, fmt.Errorf("%s: file is read-only", op)
	}

	n, err := f.File.Write(b)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	return n, nil
}

// WriteString writes a string to the file.
func (f *LocalFile) WriteString(s string) (int, error) {
	const op = "storage.(localFile).WriteString"
	return f.Write([]byte(s))
}

// WriteAndClose writes and closes the file.
func (f *LocalFile) WriteAndClose(b []byte) (int, error) {
	f.Lock()
	defer f.Unlock()

	n, err := f.write(b)
	if err != nil {
		return n, fmt.Errorf("write failed: %w", err)
	}

	err = f.close()
	if err != nil {
		return n, fmt.Errorf("close failed: %w", err)
	}

	return n, nil
}
