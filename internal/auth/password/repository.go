package password

import (
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/db"
)

// A Repository stores and retrieves the persistent types in the password
// package. It is not safe to use a repository concurrently.
type Repository struct {
	reader  db.Reader
	writer  db.Writer
	wrapper wrapping.Wrapper
	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int
}

// NewRepository creates a new Repository. The returned repository should
// only be used for one transaction and it is not safe for concurrent go
// routines to access it.  WithLimit option is used as a repo wide default
// limit applied to all ListX methods.
func NewRepository(r db.Reader, w db.Writer, wrapper wrapping.Wrapper, opt ...Option) (*Repository, error) {
	switch {
	case r == nil:
		return nil, fmt.Errorf("db.Reader: %w", db.ErrNilParameter)
	case w == nil:
		return nil, fmt.Errorf("db.Writer: %w", db.ErrNilParameter)
	case wrapper == nil:
		return nil, fmt.Errorf("wrapping.Wrapper: %w", db.ErrNilParameter)
	}

	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the watchtower defaults should be used.
		opts.withLimit = db.DefaultLimit
	}

	return &Repository{
		reader:       r,
		writer:       w,
		wrapper:      wrapper,
		defaultLimit: opts.withLimit,
	}, nil
}
