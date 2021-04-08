package job

import (
	"github.com/hashicorp/boundary/internal/job/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// Run represents an instance of a job that is either actively running or has already completed.
type Run struct {
	*store.JobRun
	tableName string `gorm:"-"`
}

func (j *Run) clone() *Run {
	cp := proto.Clone(j.JobRun)
	return &Run{
		JobRun:    cp.(*store.JobRun),
		tableName: j.tableName,
	}
}

func allocRun() *Run {
	return &Run{
		JobRun: &store.JobRun{},
	}
}

// TableName returns the table name for the job run.
func (j *Run) TableName() string {
	if j.tableName != "" {
		return j.tableName
	}
	return "job_run"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name "job_run".
func (j *Run) SetTableName(n string) {
	j.tableName = n
}

func (j *Run) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-private-id": []string{j.PrivateId},
		"resource-type":       []string{"job-run"},
		"op-type":             []string{op.String()},
	}
	return metadata
}
