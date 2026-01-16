// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"io"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
)

// A Repository stores and retrieves the persistent types in the vault
// package. It is not safe to use a repository concurrently.
type Repository struct {
	reader    db.Reader
	writer    db.Writer
	kms       *kms.Kms
	scheduler *scheduler.Scheduler
	// defaultLimit provides a default for limiting the number of results
	// returned from the repo
	defaultLimit int
	randomReader io.Reader
}

// NewRepository creates a new Repository. The returned repository should
// only be used for one transaction and it is not safe for concurrent go
// routines to access it. WithLimit option is used as a repo wide default
// limit applied to all ListX methods.
func NewRepository(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, scheduler *scheduler.Scheduler, opt ...Option) (*Repository, error) {
	const op = "vault.NewRepository"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "db.Reader")
	case w == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "db.Writer")
	case kms == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "kms")
	case scheduler == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "scheduler")
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
		scheduler:    scheduler,
		defaultLimit: opts.withLimit,
		randomReader: opts.withRandomReader,
	}, nil
}
