// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/util"
)

// A Repository stores and retrieves the persistent types in the host
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
func NewRepository(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*Repository, error) {
	const op = "static.NewRepository"
	switch {
	case util.IsNil(r):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil db.Reader")
	case util.IsNil(w):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil db.Writer")
	case util.IsNil(kms):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil kms")
	}

	opts := GetOpts(opt...)
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
