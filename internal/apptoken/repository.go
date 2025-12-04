// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

// Repository is the iam database repository
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
}

// NewRepository creates a new apptoken Repository
func NewRepository(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*Repository, error) {
	const op = "apptoken.NewRepository"
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

// TODO: Implement additional fields in AppToken and complete this method
// getAppTokenById retrieves an AppToken by its public ID
func (r *Repository) getAppTokenById(ctx context.Context, id string) (*AppToken, error) {
	const op = "apptoken.(Repository).getAppTokenById"
	if id == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing id")
	}

	query := `
	select public_id, scope_id
	  from app_token_global
	 where public_id = $1
	union all
	select public_id, scope_id
	  from app_token_org
	 where public_id = $1
	union all
	select public_id, scope_id
	  from app_token_project
	 where public_id = $1
	`

	rows, err := r.reader.Query(ctx, query, []any{id})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	var at AppToken
	if rows.Next() {
		if err := rows.Scan(&at.PublicId, &at.ScopeId); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if at.PublicId == "" {
		return nil, nil // Token not found
	}
	return &at, nil
}
