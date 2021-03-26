package job

import (
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/job/store"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultJobTableName = "job"
)

type Job struct {
	*store.Job
	tableName string `gorm:"-"`
}

// NewJob creates a new in memory Job.
//
// * Name is the human-friendly name of the job.
//
// * Code is not user facing and should be used to distinguish unique jobs of the same
// type that can run in parallel.
//
// * Description is the human-friendly description of the job.
//
// WithNextScheduledRun() is the only valid option.  If this option is not provided the
// NextScheduledRun will default to zero time, and be scheduled to run immediately.
func NewJob(name, code, description string, opt ...Option) (*Job, error) {
	const op = "job.NewJob"
	if name == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing name")
	}
	if code == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing code")
	}
	if description == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing description")
	}

	opts := getOpts(opt...)
	job := &Job{
		Job: &store.Job{
			Name:             name,
			Description:      description,
			Code:             code,
			NextScheduledRun: opts.withNextScheduledRun,
		},
	}
	return job, nil
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
	return DefaultJobTableName
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (j *Job) SetTableName(n string) {
	j.tableName = n
}
