package static

import (
	"errors"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/db"
)

// A Repository stores and retrieves the persistent types in the static
// package.
type Repository struct {
	reader  db.Reader
	writer  db.Writer
	wrapper wrapping.Wrapper
}

// NewRepository creates a new Repository.
func NewRepository(r db.Reader, w db.Writer, wrapper wrapping.Wrapper) (*Repository, error) {
	if r == nil {
		return nil, errors.New("error creating db repository with nil reader")
	}
	if w == nil {
		return nil, errors.New("error creating db repository with nil writer")
	}
	if wrapper == nil {
		return nil, errors.New("error creating db repository with nil wrapper")
	}
	return &Repository{
		reader:  r,
		writer:  w,
		wrapper: wrapper,
	}, nil
}
