// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package job

import (
	"github.com/hashicorp/boundary/internal/scheduler/job/store"
	"google.golang.org/protobuf/proto"
)

// Job represents work that should be run at a predetermined time and needs to be synchronized
// across servers to ensure that one and only one instance of a job is running at any given time.
type Job struct {
	*store.Job
	tableName string `gorm:"-"`
}

func (j *Job) clone() *Job {
	cp := proto.Clone(j.Job)
	return &Job{
		Job:       cp.(*store.Job),
		tableName: j.tableName,
	}
}

func allocJob() *Job {
	return &Job{
		Job: &store.Job{},
	}
}

// TableName returns the table name for the job.
func (j *Job) TableName() string {
	if j.tableName != "" {
		return j.tableName
	}
	return "job"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name "job".
func (j *Job) SetTableName(n string) {
	j.tableName = n
}
