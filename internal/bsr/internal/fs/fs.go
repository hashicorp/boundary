// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package fs defines the interfaces bsr needs with a storage system.
package fs

import (
	"context"
	"io"
	"io/fs"
)

// FS is a filesystem for creating or reading BSRs.
type FS interface {
	New(context.Context, string) (Container, error)
}

// SyncMode is use to determine how a file is synced when closed.
type SyncMode uint8

// Valid sync modes.
const (
	Asynchronous SyncMode = iota
	Synchronous
	NoSync
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
		WithCloseSyncMode: Asynchronous,
	}
}

// Options are fs options.
type Options struct {
	WithCloseSyncMode SyncMode
}

// Option is an fs option.
type Option func(*Options)

// WithCloseSyncMode sets how a file is synced when closed.
func WithCloseSyncMode(m SyncMode) Option {
	return func(o *Options) {
		o.WithCloseSyncMode = m
	}
}

// A Container is a filesystem abstraction that can create files or other containers.
type Container interface {
	io.Closer
	Create(context.Context, string) (WriterFile, error)
	OpenFile(context.Context, string, ...Option) (WriterFile, error)
	SubContainer(context.Context, string) (Container, error)
}

// WriterFile is a file that can be written to.
type WriterFile interface {
	fs.File
	io.Writer
	io.StringWriter
}
