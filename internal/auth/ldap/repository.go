// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/util"
)

// RepoFactory is a factory function that returns a repository and any error
type RepoFactory func() (*Repository, error)

// Repository is the ldap repository
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    kms.GetWrapperer

	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int
}

// NewRepository creates a new ldap Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewRepository(ctx context.Context, r db.Reader, w db.Writer, kms kms.GetWrapperer, opt ...Option) (*Repository, error) {
	const op = "ldap.NewRepository"
	if r == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "reader is nil")
	}
	if w == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "writer is nil")
	}
	if util.IsNil(kms) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "kms is nil")
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
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
