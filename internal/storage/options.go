// Copyright IBM Corp. 2020, 2025
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

	// minimumAvailableDiskSpace represents the minimum amount of available disk
	// space a worker needs in the path defined by RecordingStoragePath for processing
	// sessions with recording enabled.
	minimumAvailableDiskSpace
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
		WithCloseSyncMode:             Asynchronous,
		WithFileAccessMode:            ReadOnly,
		WithCreateFile:                false,
		WithBuffer:                    0,
		WithMinimumAvailableDiskSpace: DefaultMinimumAvailableDiskSpace,
	}
}

// Options are storage options.
type Options struct {
	WithCloseSyncMode             SyncMode
	WithFileAccessMode            AccessMode
	WithCreateFile                bool
	WithBuffer                    uint64
	WithMinimumAvailableDiskSpace uint64
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

// WithBuffer sets the buffer size. If the buffer size is not
// a factorial of 4KiB, the input will be used as a minimum
// buffer threshold used to determine the minimum number of
// empty bytes allowed in the buffer before having the buffer
// expand. In this case, the buffer size will be rounded up
// to the nearest 4KiB factorial.
func WithBuffer(b uint64) Option {
	return func(o *Options) {
		o.WithBuffer = b
	}
}

// WithMinimumAvailableDiskSpace sets the minimum amount of
// available disk space a worker needs in the local path defined for
// processing sessions with recording enabled.
func WithMinimumAvailableDiskSpace(m uint64) Option {
	return func(o *Options) {
		o.WithMinimumAvailableDiskSpace = m
	}
}
