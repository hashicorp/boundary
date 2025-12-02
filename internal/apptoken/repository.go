// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

var ErrMetadataScopeNotFound = errors.New(context.Background(), errors.RecordNotFound, "iam", "scope not found for metadata", errors.WithoutEvent())

// Repository is the iam database repository
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms

	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int
}

// NewRepository creates a new iam Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewRepository(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*Repository, error) {
	const op = "iam.NewRepository"
	if r == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil reader")
	}
	if w == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil writer")
	}
	if kms == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil kms")
	}

	return &Repository{
		reader: r,
		writer: w,
		kms:    kms,
	}, nil
}
