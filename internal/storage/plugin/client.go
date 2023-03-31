// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"context"

	wpbs "github.com/hashicorp/boundary/internal/gen/worker/servers/services"
)

// StorageProxyClient provides a storage related functions that will be sent from a controller
// to a worker through a CommandClientProducer to a corresponding storage plugin.
type StorageProxyClient interface {
	// OnCreateStorageBucket is a hook that runs when a storage bucket is created.
	OnCreateStorageBucket(context.Context, *wpbs.OnCreateStorageBucketRequest) (*wpbs.OnCreateStorageBucketResponse, error)
	// OnUpdateStorageBucket is a hook that runs when a storage bucket is updated.
	OnUpdateStorageBucket(context.Context, *wpbs.OnUpdateStorageBucketRequest) (*wpbs.OnUpdateStorageBucketResponse, error)
	// OnDeleteStorageBucket is a hook that runs when a storage bucket is deleted.
	OnDeleteStorageBucket(context.Context, *wpbs.OnDeleteStorageBucketRequest) (*wpbs.OnDeleteStorageBucketResponse, error)
}
