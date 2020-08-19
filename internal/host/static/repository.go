package static

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
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
func NewRepository(r db.Reader, w db.Writer, kms *kms.Kms) (*Repository, error) {
	switch {
	case r == nil:
		return nil, fmt.Errorf("db.Reader: %w", db.ErrNilParameter)
	case w == nil:
		return nil, fmt.Errorf("db.Writer: %w", db.ErrNilParameter)
	case kms == nil:
		return nil, fmt.Errorf("kms: %w", db.ErrNilParameter)
	}

	return &Repository{
		reader: r,
		writer: w,
		kms:    kms,
	}, nil
}
