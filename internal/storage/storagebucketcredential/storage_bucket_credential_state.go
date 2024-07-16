// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package storagebucketcredential

import (
	"github.com/hashicorp/boundary/internal/server/store"
)

// NewWorkerStorageBucketCredentialState returns a new WorkerStorageBucketCredentialState.
func NewWorkerStorageBucketCredentialState() *WorkerStorageBucketCredentialState {
	return &WorkerStorageBucketCredentialState{
		WorkerStorageBucketCredentialState: &store.WorkerStorageBucketCredentialState{},
	}
}

type WorkerStorageBucketCredentialState struct {
	*store.WorkerStorageBucketCredentialState
	tableName string `gorm:"-"`
}

// TableName returns the table name.
func (sbc *WorkerStorageBucketCredentialState) TableName() string {
	if sbc.tableName != "" {
		return sbc.tableName
	}
	return "worker_storage_bucket_credential_state"
}

// SetTableName sets the table name.
func (sbc *WorkerStorageBucketCredentialState) SetTableName(n string) {
	sbc.tableName = n
}
