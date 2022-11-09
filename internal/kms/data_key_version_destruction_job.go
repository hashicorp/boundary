package kms

import (
	"github.com/hashicorp/boundary/internal/kms/store"
	"google.golang.org/protobuf/proto"
)

// DataKeyVersionDestructionJob is used to read and write
// data key version destruction jobs in the DB.
type DataKeyVersionDestructionJob struct {
	*store.DataKeyVersionDestructionJob
}

func (k *DataKeyVersionDestructionJob) TableName() string {
	return "kms_data_key_version_destruction_job"
}

// allocDataKeyVersionDestructionJob makes an empty one in memory.
func allocDataKeyVersionDestructionJob() DataKeyVersionDestructionJob {
	return DataKeyVersionDestructionJob{
		DataKeyVersionDestructionJob: &store.DataKeyVersionDestructionJob{},
	}
}

// Clone a DataKeyVersionDestructionJob
func (c *DataKeyVersionDestructionJob) Clone() *DataKeyVersionDestructionJob {
	cp := proto.Clone(c.DataKeyVersionDestructionJob)
	return &DataKeyVersionDestructionJob{
		DataKeyVersionDestructionJob: cp.(*store.DataKeyVersionDestructionJob),
	}
}
