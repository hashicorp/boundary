// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package job

import (
	"github.com/hashicorp/boundary/internal/scheduler/job/store"
	"google.golang.org/protobuf/proto"
)

// Run represents an instance of a job that is either actively running or has failed in some way.
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
