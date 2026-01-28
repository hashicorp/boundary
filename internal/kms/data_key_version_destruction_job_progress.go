// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package kms

import (
	"github.com/hashicorp/boundary/internal/kms/store"
	"google.golang.org/protobuf/proto"
)

// DataKeyVersionDestructionJobProgress is used to read
// data key version destruction job progress from the DB.
type DataKeyVersionDestructionJobProgress struct {
	*store.DataKeyVersionDestructionJobProgress
}

func (k *DataKeyVersionDestructionJobProgress) TableName() string {
	return "kms_data_key_version_destruction_job_progress"
}

// allocDataKeyVersionDestructionJobProgress makes an empty one in memory.
func allocDataKeyVersionDestructionJobProgress() DataKeyVersionDestructionJobProgress {
	return DataKeyVersionDestructionJobProgress{
		DataKeyVersionDestructionJobProgress: &store.DataKeyVersionDestructionJobProgress{},
	}
}

// Clone an DataKeyVersionDestructionJob
func (k *DataKeyVersionDestructionJobProgress) Clone() *DataKeyVersionDestructionJobProgress {
	cp := proto.Clone(k.DataKeyVersionDestructionJobProgress)
	return &DataKeyVersionDestructionJobProgress{
		DataKeyVersionDestructionJobProgress: cp.(*store.DataKeyVersionDestructionJobProgress),
	}
}
