// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package kms

import (
	"github.com/hashicorp/boundary/internal/kms/store"
	"google.golang.org/protobuf/proto"
)

// DataKeyVersionDestructionJobRun is used to read and write
// data key version destruction job runs in the DB.
type DataKeyVersionDestructionJobRun struct {
	*store.DataKeyVersionDestructionJobRun
}

func (k *DataKeyVersionDestructionJobRun) TableName() string {
	return "kms_data_key_version_destruction_job_run"
}

// allocDataKeyVersionDestructionJobRun makes an empty one in memory.
func allocDataKeyVersionDestructionJobRun() DataKeyVersionDestructionJobRun {
	return DataKeyVersionDestructionJobRun{
		DataKeyVersionDestructionJobRun: &store.DataKeyVersionDestructionJobRun{},
	}
}

// Clone a DataKeyVersionDestructionJobRun
func (k *DataKeyVersionDestructionJobRun) Clone() *DataKeyVersionDestructionJobRun {
	cp := proto.Clone(k.DataKeyVersionDestructionJobRun)
	return &DataKeyVersionDestructionJobRun{
		DataKeyVersionDestructionJobRun: cp.(*store.DataKeyVersionDestructionJobRun),
	}
}
