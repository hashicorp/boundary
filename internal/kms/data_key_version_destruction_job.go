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

// allocDataKeyVersionDestructionJob makes an empty one in memory.
func allocDataKeyVersionDestructionJob() DataKeyVersionDestructionJobProgress {
	return DataKeyVersionDestructionJobProgress{
		DataKeyVersionDestructionJobProgress: &store.DataKeyVersionDestructionJobProgress{},
	}
}

// Clone an DataKeyVersionDestructionJob
func (c *DataKeyVersionDestructionJobProgress) Clone() *DataKeyVersionDestructionJobProgress {
	cp := proto.Clone(c.DataKeyVersionDestructionJobProgress)
	return &DataKeyVersionDestructionJobProgress{
		DataKeyVersionDestructionJobProgress: cp.(*store.DataKeyVersionDestructionJobProgress),
	}
}
