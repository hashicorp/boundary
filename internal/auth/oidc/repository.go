package oidc

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

// Repository is the oidc repository
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms

	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int
}

// NewRepository creates a new oidc Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewRepository(r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*Repository, error) {
	const op = "oidc.NewRepository"
	if r == nil {
		return nil, errors.New(errors.InvalidParameter, op, "reader is nil")
	}
	if w == nil {
		return nil, errors.New(errors.InvalidParameter, op, "writer is nil")
	}
	if kms == nil {
		return nil, errors.New(errors.InvalidParameter, op, "kms is nil")
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

// getAuthMethods allows the caller to either lookup a specific AuthMethod via
// its id or search for a set AuthMethods within a set of scopes.  Passing both
// scopeIds and a authMethodId is an error.   The WithVersion option is
// supported when an authMethodId is specified.  All other options are ignored.
func (r *Repository) getAuthMethods(ctx context.Context, authMethodId string, scopeIds []string, opt ...Option) ([]*AuthMethod, error) {
	panic("to-do")
}
