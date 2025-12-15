// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
)

// listAliases lists aliases in the given scopes and supports WithLimit option.
func (r *Repository) listAliases(ctx context.Context, withScopeIds []string, opt ...Option) ([]*Alias, time.Time, error) {
	const op = "target.(Repository).listAliases"
	if len(withScopeIds) == 0 {
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, time.Time{}, errors.Wrap(ctx, err, op)
	}

	limit := r.defaultLimit
	switch {
	case opts.withLimit > 0:
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	case opts.withLimit < 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "limit must be non-negative")
	}

	var args []any
	whereClause := "scope_id in @scope_ids"
	args = append(args, sql.Named("scope_ids", withScopeIds))

	if opts.withStartPageAfterItem != nil {
		whereClause = fmt.Sprintf("(create_time, public_id) < (@last_item_create_time, @last_item_id) and %s", whereClause)
		args = append(args,
			sql.Named("last_item_create_time", opts.withStartPageAfterItem.GetCreateTime()),
			sql.Named("last_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
	}
	dbOpts := []db.Option{db.WithLimit(limit), db.WithOrder("create_time desc, public_id desc")}
	return r.queryAliases(ctx, whereClause, args, dbOpts...)
}

// listAliasesRefresh lists aliases limited by the list
// permissions of the repository.
// Supported options:
//   - withTerminated
//   - withLimit
//   - withStartPageAfterItem
func (r *Repository) listAliasesRefresh(ctx context.Context, updatedAfter time.Time, withScopeIds []string, opt ...Option) ([]*Alias, time.Time, error) {
	const op = "target.(Repository).listAliasesRefresh"

	switch {
	case updatedAfter.IsZero():
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing updated after time")

	case len(withScopeIds) == 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, time.Time{}, errors.Wrap(ctx, err, op)
	}

	limit := r.defaultLimit
	switch {
	case opts.withLimit > 0:
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	case opts.withLimit < 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "limit must be non-negative")
	}

	var args []any
	whereClause := "update_time > @updated_after_time and scope_id in @scope_ids"
	args = append(args,
		sql.Named("updated_after_time", timestamp.New(updatedAfter)),
		sql.Named("scope_ids", withScopeIds),
	)
	if opts.withStartPageAfterItem != nil {
		whereClause = fmt.Sprintf("(update_time, public_id) < (@last_item_update_time, @last_item_id) and %s", whereClause)
		args = append(args,
			sql.Named("last_item_update_time", opts.withStartPageAfterItem.GetUpdateTime()),
			sql.Named("last_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
	}

	dbOpts := []db.Option{db.WithLimit(limit), db.WithOrder("update_time desc, public_id desc")}
	return r.queryAliases(ctx, whereClause, args, dbOpts...)
}

func (r *Repository) queryAliases(ctx context.Context, whereClause string, args []any, opt ...db.Option) ([]*Alias, time.Time, error) {
	const op = "target.(Repository).queryAliases"

	var ret []*Alias
	var transactionTimestamp time.Time
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(rd db.Reader, w db.Writer) error {
		var inRet []*Alias
		if err := rd.SearchWhere(ctx, &inRet, whereClause, args, opt...); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		ret = inRet
		var err error
		transactionTimestamp, err = rd.Now(ctx)
		return err
	}); err != nil {
		return nil, time.Time{}, err
	}
	return ret, transactionTimestamp, nil
}

// listDeletedIds lists the public IDs of any aliases deleted since the timestamp provided.
func (r *Repository) listDeletedIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	const op = "target.(Repository).listDeletedIds"
	var deletedAliases []*deletedAlias
	var transactionTimestamp time.Time
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, _ db.Writer) error {
		if err := r.SearchWhere(ctx, &deletedAliases, "delete_time >= ?", []any{since}); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted aliases"))
		}
		var err error
		transactionTimestamp, err = r.Now(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to get transaction timestamp"))
		}
		return nil
	}); err != nil {
		return nil, time.Time{}, err
	}
	var aliasIds []string
	for _, sess := range deletedAliases {
		aliasIds = append(aliasIds, sess.PublicId)
	}
	return aliasIds, transactionTimestamp, nil
}

// estimatedCount returns an estimate of the total number of items in the alias table.
func (r *Repository) estimatedCount(ctx context.Context) (int, error) {
	const op = "target.(Repository).estimatedCount"
	rows, err := r.reader.Query(ctx, estimateCount, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total aliases"))
	}
	var count int
	for rows.Next() {
		if err := r.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total aliases"))
		}
	}
	return count, nil
}
