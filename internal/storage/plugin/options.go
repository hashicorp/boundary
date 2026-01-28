// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"github.com/hashicorp/boundary/internal/pagination"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	// DefaultChunkSize is the default chunk size for streaming
	DefaultChunkSize = 65536 // 64KiB
)

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments.
type Option func(*options)

// options = how options are represented
type options struct {
	withChunkSize          uint32
	withName               string
	withDescription        string
	withAttributes         *structpb.Struct
	withSecrets            *structpb.Struct
	withWorkerFilter       string
	withBucketPrefix       string
	withLimit              int
	withVersion            uint32
	withStartPageAfterItem pagination.Item
}

func getDefaultOptions() options {
	return options{
		withChunkSize:  DefaultChunkSize,
		withAttributes: &structpb.Struct{},
	}
}

// WithChunkSize provides an optional chunkSize to associate
// with a StorageClient. ChunkSize is the number of bytes to
// send to the plugin in a single request. If not provided,
// the default is 64KiB. The recommended chunk size for
// GRPC streamed messages is 16KiB to 64KiB.
func WithChunkSize(chunkSize uint32) Option {
	return func(o *options) {
		o.withChunkSize = chunkSize
	}
}

// WithDescription provides an optional description.
func WithDescription(desc string) Option {
	return func(o *options) {
		o.withDescription = desc
	}
}

// WithName provides an optional name.
func WithName(name string) Option {
	return func(o *options) {
		o.withName = name
	}
}

// WithAttributes provides an optional attributes field.
func WithAttributes(attrs *structpb.Struct) Option {
	return func(o *options) {
		o.withAttributes = attrs
	}
}

// WithSecrets provides an optional secrets field.
func WithSecrets(secrets *structpb.Struct) Option {
	return func(o *options) {
		o.withSecrets = secrets
	}
}

// WithBucketPrefix provides an optional bucket prefix.
func WithBucketPrefix(bp string) Option {
	return func(o *options) {
		o.withBucketPrefix = bp
	}
}

// WithWorkerFilter provides a worker filter that indicate which workers
// can support requests for this storage bucket.
func WithWorkerFilter(wf string) Option {
	return func(o *options) {
		o.withWorkerFilter = wf
	}
}

// WithLimit provides an option to provide a limit. Intentionally allowing
// negative integers. If WithLimit < 0, then unlimited results are
// returned. If WithLimit == 0, then default limits are used for results.
func WithLimit(l int) Option {
	return func(o *options) {
		o.withLimit = l
	}
}

// WithVersion provides an optional version number
func WithVersion(v uint32) Option {
	return func(o *options) {
		o.withVersion = v
	}
}

// WithStartPageAfterItem is used to paginate over the results.
// The next page will start after the provided item.
func WithStartPageAfterItem(item pagination.Item) Option {
	return func(o *options) {
		o.withStartPageAfterItem = item
	}
}
