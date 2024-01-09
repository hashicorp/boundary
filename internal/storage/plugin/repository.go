// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
}

// NewRepository creates a new Repository. The returned repository is not
// safe for concurrent go routines to access it
func NewRepository(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms) (*Repository, error) {
	const op = "plugin.NewRepository"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil db.Reader")
	case w == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil db.Writer")
	case kms == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil kms")
	}

	return &Repository{
		reader: r,
		writer: w,
		kms:    kms,
	}, nil
}
