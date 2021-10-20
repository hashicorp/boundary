package host

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

// A Repository stores and retrieves the persistent types in the static
// package. It is not safe to use a repository concurrently.
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
}

// NewRepository creates a new Repository. The returned repository should
// only be used for one transaction and it is not safe for concurrent go
// routines to access it.
func NewRepository(r db.Reader, w db.Writer, kms *kms.Kms, _ ...Option) (*Repository, error) {
	const op = "host.NewRepository"
	switch {
	case r == nil:
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "db.Reader")
	case w == nil:
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "db.Writer")
	case kms == nil:
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "kms")
	}

	return &Repository{
		reader: r,
		writer: w,
		kms:    kms,
	}, nil
}
