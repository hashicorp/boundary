// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package alias

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

// A Repository stores and retrieves the persistent types in the alias
// package. It is not safe to use a repository concurrently.
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
}

// NewRepository creates a new Repository. The returned repository should
// only be used for one transaction and it is not safe for concurrent go
// routines to access it.
func NewRepository(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms) (*Repository, error) {
	const op = "alias.NewRepository"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "db.Reader")
	case w == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "db.Writer")
	case kms == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "kms")
	}

	return &Repository{
		reader: r,
		writer: w,
		kms:    kms,
	}, nil
}
