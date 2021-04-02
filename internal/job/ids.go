package job

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

const (
	// JobPrefix is the prefix of all generated Job private ids
	JobPrefix = "job"

	// JobRunPrefix is the prefix of all generated JobRun private ids
	JobRunPrefix = "jobrun"
)

func newJobId(name, code string) (string, error) {
	const op = "job.newJobId"
	if name == "" {
		return "", errors.New(errors.InvalidParameter, op, "missing name")
	}
	if code == "" {
		return "", errors.New(errors.InvalidParameter, op, "missing code")
	}

	id, err := db.NewPrivateId(JobPrefix, db.WithPrngValues([]string{name, code}))
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	return id, nil
}

func newJobRunId() (string, error) {
	const op = "job.newJobRunId"
	id, err := db.NewPrivateId(JobRunPrefix)
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	return id, nil
}
