// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

// Repository is the apptoken database repository
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
	limit  int
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

	rows, err := r.reader.Query(ctx, getAppTokenByIdQuery, []any{id})
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
		return nil, errors.New(ctx, errors.NotFound, op, "app token not found")
	}
	return &at, nil
}

// listAppTokens lists tokens across all three token subtypes (global, org, proj).
// Cipher information and permissions are not included when listing a token.
func (r *Repository) listAppTokens(ctx context.Context, withScopeIds []string, opt ...Option) ([]*AppToken, time.Time, error) {
	const op = "apptoken.(Repository).listAppTokens"
	if len(withScopeIds) == 0 {
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	opts := getOpts(opt...)

	limit := r.limit
	if opts.withLimit != 0 {
		limit = opts.withLimit
	}

	args := []any{sql.Named("scope_ids", withScopeIds)}
	whereClause := "scope_id in @scope_ids"
	if opts.withStartPageAfterItem != nil {
		whereClause = fmt.Sprintf("(create_time, public_id) < (@last_item_create_time, @last_item_id) and %s", whereClause)
		args = append(args,
			sql.Named("last_item_create_time", opts.withStartPageAfterItem.GetCreateTime()),
			sql.Named("last_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
	}

	dbOpts := []db.Option{db.WithLimit(limit), db.WithOrder("create_time desc, public_id desc")}

	return r.queryAppTokens(ctx, whereClause, args, dbOpts...)
}

func (r *Repository) queryAppTokens(ctx context.Context, whereClause string, args []any, opt ...db.Option) ([]*AppToken, time.Time, error) {
	const op = "apptoken.(Repository).queryAppTokens"

	var transactionTimestamp time.Time
	var appTokens []*AppToken
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(rd db.Reader, w db.Writer) error {
		var atvs []*appTokenView
		err := rd.SearchWhere(ctx, &atvs, whereClause, args, opt...)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		appTokens = make([]*AppToken, 0, len(atvs))
		for _, atv := range atvs {
			appTokens = append(appTokens, atv.toAppToken())
		}
		transactionTimestamp, err = rd.Now(ctx)
		return err
	}); err != nil {
		return nil, time.Time{}, err
	}
	return appTokens, transactionTimestamp, nil
}

// TODO: Implement proper estimated count logic
func (r *Repository) estimatedCount(ctx context.Context) (int, error) {
	const op = "apptoken.(Repository).estimatedCount"
	return 10, nil
}
