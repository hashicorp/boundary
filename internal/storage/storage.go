// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package storage

import (
	"context"
	"io"
	"io/fs"

	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/storage/bucket"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

// DefaultMinimumAvailableDiskSpace is the default value a Boundary worker will use
// if the user does not configure the worker with a RecordingStorageMinimumAvailableCapacity
// value. This value is equivalent to 500MiB. This value is used to determine the worker's
// local storage state.
const DefaultMinimumAvailableDiskSpace = 500 * 1024 * 1024

// RecordingStorage can be used to create an FS usable for session recording.
type RecordingStorage interface {
	// NewSyncingFS returns an FS that will use local storage as a cache and sync files when they are closed.
	NewSyncingFS(ctx context.Context, bucket bucket.StorageBucketSingleton, _ ...Option) (FS, error)

	// NewRemoteFS returns a ReadOnly FS that can be used to retrieve files from a storage bucket.
	NewRemoteFS(ctx context.Context, bucket bucket.StorageBucketSingleton, _ ...Option) (FS, error)

	// PluginClients returns a map of storage plugin clients keyed on the plugin name.
	PluginClients() map[string]plgpb.StoragePluginServiceClient

	// CreateTemp creates a temporary file that is cleaned up when closed. All temp files
	// are also removed when storage is initialized.
	CreateTemp(ctx context.Context, p string) (TempFile, error)

	// GetLocalStorageState returns the current local storage state of the storage instance.
	GetLocalStorageState(ctx context.Context) server.LocalStorageState

	// GetStorageBucketCredentialStates returns a map of the current storage bucket credential states.
	// The key is the public id of the storage bucket and the value is the storage bucket credential state.
	GetStorageBucketCredentialStates() map[string]*plgpb.StorageBucketCredentialState

	// UpsertStorageBucket wiil compare the given storage bucket against the same storage bucket
	// that is currently being managed and will return the storage bucket that has the latest version.
	// If the given storage bucket has the latest version, then the managed storage bucket will be updated.
	UpsertStorageBucket(ctx context.Context, newBucket *storagebuckets.StorageBucket) (bucket.StorageBucketSingleton, error)

	// AddDependant starts tracking the given resource as a dependant.
	AddDependant(ctx context.Context, storageBucketId string, dependantId string) error

	// RemoveDependant stops tracking the given resource as an dependant.
	RemoveDependant(ctx context.Context, storageBucketId string, dependantId string) error
}

// Bucket is a resource that represents a bucket in an external object store
type Bucket interface {
	boundary.Resource
	GetScopeId() string
	GetBucketName() string
	GetBucketPrefix() string
	GetWorkerFilter() string
}

// FS is a filesystem for creating or reading files and containers.
type FS interface {
	New(ctx context.Context, name string) (Container, error)
	Open(ctx context.Context, name string) (Container, error)
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
	io.StringWriter
	Writer
}

// TempFile is a temporary File. It will get removed when Closed.
type TempFile interface {
	File
	io.Seeker
}

// Writer is an interface that extends the io.Writer interface with an additional
// WriteAndClose method. WriteAndClose writes a byte slice and closes the file in
// a single call.
type Writer interface {
	io.Writer
	WriteAndClose([]byte) (int, error)
}
