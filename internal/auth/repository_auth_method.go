// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/util"
)

// AuthMethodRepository coordinates calls across different subtype services
// to gather information about all auth methods.
type AuthMethodRepository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
}

// NewAuthMethodRepository returns a new auth method repository.
func NewAuthMethodRepository(ctx context.Context, reader db.Reader, writer db.Writer, kms *kms.Kms) (*AuthMethodRepository, error) {
	const op = "auth.NewAuthMethodRepository"
	switch {
	case util.IsNil(reader):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing DB reader")
	case util.IsNil(writer):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing DB writer")
	case util.IsNil(kms):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing kms")
	}
	return &AuthMethodRepository{
		reader: reader,
		writer: writer,
		kms:    kms,
	}, nil
}

// List lists auth methods across all subtypes.
func (amr *AuthMethodRepository) List(ctx context.Context, scopeIds []string, afterItem pagination.Item, opt ...Option) ([]AuthMethod, time.Time, error) {
	const op = "auth.(*AuthMethodRepository).list"

	opts, err := GetOpts(opt...)
	if err != nil {
		return nil, time.Time{}, errors.Wrap(ctx, err, op)
	}

	limit := opts.WithLimit

	switch {
	case len(scopeIds) == 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing scope ids")
	case limit < 1:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing limit")
	}

	whereClause := "scope_id in @scope_ids"
	args := []any{sql.Named("scope_ids", scopeIds)}

	if opts.WithUnauthenticatedUser {
		whereClause += " and is_active_public_state = true"
	}

	query := fmt.Sprintf(listAuthMethodsTemplate, whereClause, limit)
	if afterItem != nil {
		query = fmt.Sprintf(listAuthMethodsPageTemplate, whereClause, limit)
		args = append(args,
			sql.Named("last_item_create_time", afterItem.GetCreateTime()),
			sql.Named("last_item_id", afterItem.GetPublicId()),
		)
	}

	return amr.queryAuthMethods(ctx, query, args)
}

// ListRefresh lists auth methods across all subtypes.
func (amr *AuthMethodRepository) ListRefresh(ctx context.Context, scopeIds []string, updatedAfter time.Time, afterItem pagination.Item, opt ...Option) ([]AuthMethod, time.Time, error) {
	const op = "auth.(*AuthMethodRepository).list"

	opts, err := GetOpts(opt...)
	if err != nil {
		return nil, time.Time{}, errors.Wrap(ctx, err, op)
	}

	limit := opts.WithLimit

	switch {
	case len(scopeIds) == 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing scope ids")
	case updatedAfter.IsZero():
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing updated after time")
	case limit < 1:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing limit")
	}

	whereClause := "scope_id in @scope_ids"
	args := []any{sql.Named("scope_ids", scopeIds)}

	if opts.WithUnauthenticatedUser {
		whereClause += " and is_active_public_state = true"
	}

	query := fmt.Sprintf(listAuthMethodsRefreshTemplate, whereClause, limit)
	args = append(args,
		sql.Named("updated_after_time", timestamp.New(updatedAfter)),
	)
	if afterItem != nil {
		query = fmt.Sprintf(listAuthMethodsRefreshPageTemplate, whereClause, limit)
		args = append(args,
			sql.Named("last_item_update_time", afterItem.GetUpdateTime()),
			sql.Named("last_item_id", afterItem.GetPublicId()),
		)
	}

	return amr.queryAuthMethods(ctx, query, args)
}

// EstimatedCount estimates the total number of auth methods.
func (amr *AuthMethodRepository) EstimatedCount(ctx context.Context) (int, error) {
	const op = "auth.(*AuthMethodRepository).EstimatedCount"
	rows, err := amr.reader.Query(ctx, estimateCountAuthMethodsQuery, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total auth methods"))
	}
	var count int
	for rows.Next() {
		if err := amr.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total auth methods"))
		}
	}
	if err := rows.Err(); err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total auth methods"))
	}
	return count, nil
}

// ListDeletedIds lists the deleted IDs of all auth methods since the time specified.
func (amr *AuthMethodRepository) ListDeletedIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	const op = "auth.(*AuthMethodRepository).ListDeletedIds"
	var deletedAuthMethodIDs []string
	var transactionTimestamp time.Time
	if _, err := amr.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		rows, err := w.Query(ctx, listDeletedIdsQuery, []any{sql.Named("since", since)})
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		defer rows.Close()
		for rows.Next() {
			if err := r.ScanRows(ctx, rows, &deletedAuthMethodIDs); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}
		if err := rows.Err(); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		transactionTimestamp, err = r.Now(ctx)
		return err
	}); err != nil {
		return nil, time.Time{}, err
	}
	return deletedAuthMethodIDs, transactionTimestamp, nil
}

func (amr *AuthMethodRepository) queryAuthMethods(ctx context.Context, query string, args []any) ([]AuthMethod, time.Time, error) {
	const op = "auth.(*AuthMethodRepository).queryAuthMethods"

	var authmethods []AuthMethod
	var transactionTimestamp time.Time
	if _, err := amr.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		rows, err := r.Query(ctx, query, args)
		if err != nil {
			return err
		}
		defer rows.Close()
		var foundAuthMethods []*AuthMethodListQueryResult
		for rows.Next() {
			if err := r.ScanRows(ctx, rows, &foundAuthMethods); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, am := range foundAuthMethods {
			authmethod, err := am.toAuthMethod(ctx)
			if err != nil {
				return err
			}
			authmethods = append(authmethods, authmethod)
		}
		transactionTimestamp, err = r.Now(ctx)
		return err
	}); err != nil {
		return nil, time.Time{}, errors.Wrap(ctx, err, op)
	}

	return authmethods, transactionTimestamp, nil
}
