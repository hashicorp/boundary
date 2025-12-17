// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bucket

import (
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

// StorageBucketSingleton ensures safe and easy access to a storage bucket and
// its storage bucket credential state.
type StorageBucketSingleton interface {
	GetState() *plgpb.StorageBucketCredentialState
	GetBucket() *storagebuckets.StorageBucket
	SetState(*plgpb.StorageBucketCredentialState) error
	SetBucket(*storagebuckets.StorageBucket) error
	HasWriteAccess() bool
	HasReadAccess() bool
	AddDependant(name string)
	RemoveDependant(name string)
	HasDependants() bool
}
