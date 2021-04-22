package job

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

const (
	// jobPrefix is the prefix of all generated Job private ids
	jobPrefix = "job"
)

// NewJobId generates a pseudo random id seeded on the name and code parameters.
// The id is prefixed with "job_".
func NewJobId(name, code string) (string, error) {
	const op = "job.NewJobId"
	if name == "" {
		return "", errors.New(errors.InvalidParameter, op, "missing name")
	}
	if code == "" {
		return "", errors.New(errors.InvalidParameter, op, "missing code")
	}

	id, err := db.NewPrivateId(jobPrefix, db.WithPrngValues([]string{name, code}))
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	return id, nil
}
