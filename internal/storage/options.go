// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package storage

// SyncMode is used to determine how a file is synced when closed.
type SyncMode uint8

const (
	// Asynchronous mode will trigger a file to sync to the storage
	// bucket on a recurring interval once it has been closed. It will continue
	// retrying until the root container is closed.
	// Asynchronous is the default sync mode.
	Asynchronous SyncMode = iota

	// Synchronous mode will cause a file closed call to block until the file
	// has been synced to the storage bucket. Any error while syncing the file
	// will be returned to the caller of Close.
	Synchronous

	// NoSync mode will result in Close not syncing the file to the storage
	// bucket.
	NoSync
)

// AccessMode is use to determine the access mode a file is opened with.
type AccessMode uint8

const (
	// ReadOnly mode will open a file as read only.
	// ReadOnly is the default access mode.
	ReadOnly AccessMode = iota

	// WriteOnly mode will open a file for writing only.
	WriteOnly

	// ReadWrite mode will open a file for reading and writing.
	ReadWrite
)

// GetOpts - iterate the inbound Options and return a struct.
func GetOpts(opt ...Option) Options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

func getDefaultOptions() Options {
	return Options{
		WithCloseSyncMode:  Asynchronous,
		WithFileAccessMode: ReadOnly,
		WithCreateFile:     false,
		WithBuffer:         0,
		WithMinimumBuffer:  0,
	}
}

// Options are storage options.
type Options struct {
	WithCloseSyncMode  SyncMode
	WithFileAccessMode AccessMode
	WithCreateFile     bool
	WithBuffer         uint64
	WithMinimumBuffer  uint64
}

// Option is a storage option.
type Option func(*Options)

// WithCloseSyncMode sets how a file is synced when closed.
func WithCloseSyncMode(m SyncMode) Option {
	return func(o *Options) {
		o.WithCloseSyncMode = m
	}
}

// WithCreateFile indicates a file should be created when opening.
func WithCreateFile() Option {
	return func(o *Options) {
		o.WithCreateFile = true
	}
}

// WithFileAccessMode sets the access mode when a file is opened.
func WithFileAccessMode(m AccessMode) Option {
	return func(o *Options) {
		o.WithFileAccessMode = m
	}
}

// WithBuffer sets the buffer size.
// The value must be a factorial of 4KiB.
func WithBuffer(b uint64) Option {
	return func(o *Options) {
		o.WithBuffer = b
	}
}

// WithMinimumBuffer sets the threshold to enforce when the
// buffer expands back to its original size.
func WithMinimumBuffer(m uint64) Option {
	return func(o *Options) {
		o.WithMinimumBuffer = m
	}
}
