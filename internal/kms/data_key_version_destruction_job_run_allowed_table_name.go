package kms

import (
	"github.com/hashicorp/boundary/internal/kms/store"
	"google.golang.org/protobuf/proto"
)

// DataKeyVersionDestructionJobRunAllowedTableName is used to read
// the names of tables that reference the data key version.
type DataKeyVersionDestructionJobRunAllowedTableName struct {
	*store.DataKeyVersionDestructionJobRunAllowedTableName
}

func (k *DataKeyVersionDestructionJobRunAllowedTableName) TableName() string {
	return "kms_data_key_version_destruction_job_run_allowed_table_name"
}

// allocDataKeyVersionDestructionJobRunAllowedTableName makes an empty one in memory.
func allocDataKeyVersionDestructionJobRunAllowedTableName() DataKeyVersionDestructionJobRunAllowedTableName {
	return DataKeyVersionDestructionJobRunAllowedTableName{
		DataKeyVersionDestructionJobRunAllowedTableName: &store.DataKeyVersionDestructionJobRunAllowedTableName{},
	}
}

// Clone an DataKeyVersionDestructionJob
func (c *DataKeyVersionDestructionJobRunAllowedTableName) Clone() *DataKeyVersionDestructionJobRunAllowedTableName {
	cp := proto.Clone(c.DataKeyVersionDestructionJobRunAllowedTableName)
	return &DataKeyVersionDestructionJobRunAllowedTableName{
		DataKeyVersionDestructionJobRunAllowedTableName: cp.(*store.DataKeyVersionDestructionJobRunAllowedTableName),
	}
}
