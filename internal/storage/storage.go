// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"context"
	"io"
	"io/fs"

	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

// RecordingStorage can be used to create a FS usable for session recording.
type RecordingStorage interface {
	NewLocalFS(ctx context.Context, bucket Bucket, _ ...Option) (FS, error)
	NewRemoteFS(ctx context.Context, bucket Bucket, _ ...Option) (FS, error)
	PluginClients() map[string]plgpb.StoragePluginServiceClient
}

// Bucket is a resource that represents a bucket in an external object store
type Bucket interface {
	GetBucketName() string
	GetBucketPrefix() string
}

// FS is a filesystem for creating or reading files and containers.
type FS interface {
	New(ctx context.Context, name string) (Container, error)
}

// A Container is a filesystem abstraction that can create files or other containers.
type Container interface {
	io.Closer
	Create(context.Context, string) (File, error)
	OpenFile(context.Context, string, ...Option) (File, error)
	SubContainer(context.Context, string, ...Option) (Container, error)
}

// File represents a storage File.
type File interface {
	fs.File
	io.Writer
	io.StringWriter
}
