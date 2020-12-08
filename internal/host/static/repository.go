package static

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
	// defaultLimit provides a default for limiting the number of results
	// returned from the repo
	defaultLimit int
}

// NewRepository creates a new Repository. The returned repository should
// only be used for one transaction and it is not safe for concurrent go
// routines to access it. WithLimit option is used as a repo wide default
// limit applied to all ListX methods.
// routines to access it.
func NewRepository(r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*Repository, error) {
	const op = "static.NewRepository"
	switch {
	case r == nil:
		return nil, errors.New(errors.InvalidParameter, op, "db.Reader")
	case w == nil:
		return nil, errors.New(errors.InvalidParameter, op, "db.Writer")
	case kms == nil:
		return nil, errors.New(errors.InvalidParameter, op, "kms")
	}

	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = db.DefaultLimit
	}

	return &Repository{
		reader:       r,
		writer:       w,
		kms:          kms,
		defaultLimit: opts.withLimit,
	}, nil
}
