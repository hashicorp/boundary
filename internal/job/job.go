package job

import (
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/job/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// DefaultJobTableName is the default name of the database table that is used to persist a Job
	DefaultJobTableName = "job"
)

// Job represents work that should be run at a predetermined time and needs to be synchronized
// across servers to ensure that one and only one instance of a job is running at any given time.
type Job struct {
	*store.Job
	tableName string `gorm:"-"`
}

// NewJob creates a new in memory Job.
//
// • Name is the human-friendly name of the job.
//
// • Code is not user facing and should be used to distinguish unique jobs of
// the same type that can run in parallel.
//
// • Description is the human-friendly description of the job.
//
// WithNextScheduledRun() is the only valid option.  If this option is not
// provided the NextScheduledRun of the job will default to zero time, and be available
// to run immediately.
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
			NextScheduledRun: &timestamp.Timestamp{Timestamp: timestamppb.New(opts.withNextScheduledRun)},
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

func (j *Job) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-private-id": []string{j.PrivateId},
		"resource-type":       []string{"job"},
		"op-type":             []string{op.String()},
	}
	return metadata
}
