package job

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/job/store"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultJobRunTableName = "job_run"
)

type JobRun struct {
	*store.JobRun
	tableName string `gorm:"-"`
}

// NewJobRun creates a new in memory JobRun.
// jobId is the private_id of the job to run.
// serverId is the private_id of the server running the job.
//
// WithJobRunStatus() is the only valid option, if not provided
// the run defaults to a status of running.
func NewJobRun(jobId, serverId string, opt ...Option) (*JobRun, error) {
	const op = "job.NewJobRun"
	if jobId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing job id")
	}
	if serverId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing server id")
	}

	opts := getOpts(opt...)
	runStatus := opts.withJobRunStatus
	if !isValidRunStatus(runStatus) {
		return nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("invalid run status: %v", runStatus))
	}

	run := &JobRun{
		JobRun: &store.JobRun{
			JobId:    jobId,
			ServerId: serverId,
			Status:   runStatus,
		},
	}
	return run, nil
}

func (j *JobRun) clone() *JobRun {
	cp := proto.Clone(j.JobRun)
	return &JobRun{
		JobRun:    cp.(*store.JobRun),
		tableName: j.tableName,
	}
}

func allocJobRun() *JobRun {
	return &JobRun{
		JobRun: &store.JobRun{},
	}
}

// TableName returns the table name for the job run.
func (j *JobRun) TableName() string {
	if j.tableName != "" {
		return j.tableName
	}
	return DefaultJobRunTableName
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (j *JobRun) SetTableName(n string) {
	j.tableName = n
}
