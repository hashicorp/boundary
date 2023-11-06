// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-dbw"
)

// CreateManagedGroup inserts an ManagedGroup, mg, into the repository and
// returns a new ManagedGroup containing its PublicId. mg is not changed. mg
// must contain a valid AuthMethodId. mg must not contain a PublicId. The
// PublicId is generated and assigned by this method.
//
// Both mg.Name and mg.Description are optional. If mg.Name is set, it must be
// unique within mg.AuthMethodId.
func (r *Repository) CreateManagedGroup(ctx context.Context, scopeId string, mg *ManagedGroup, opt ...Option) (*ManagedGroup, error) {
	const op = "oidc.(Repository).CreateManagedGroup"
	if mg == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing ManagedGroup")
	}
	if mg.ManagedGroup == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing embedded ManagedGroup")
	}
	if mg.AuthMethodId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	}
	if mg.Filter == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter")
	}
	if mg.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id must be empty")
	}
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}

	mg = mg.Clone()

	id, err := newManagedGroupId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	mg.PublicId = id

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"), errors.WithCode(errors.Encrypt))
	}

	var newManagedGroup *ManagedGroup
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newManagedGroup = mg.Clone()
			if err := w.Create(ctx, newManagedGroup, db.WithOplog(oplogWrapper, mg.oplog(oplog.OpType_OP_TYPE_CREATE, scopeId))); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf(
				"in auth method %s: name %q already exists",
				mg.AuthMethodId, mg.Name))
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(mg.AuthMethodId))
	}
	return newManagedGroup, nil
}

// LookupManagedGroup will look up a managed group in the repository. If the managed group is not
// found, it will return nil, nil. All options are ignored.
func (r *Repository) LookupManagedGroup(ctx context.Context, withPublicId string, opt ...Option) (*ManagedGroup, error) {
	const op = "oidc.(Repository).LookupManagedGroup"
	if withPublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	a := AllocManagedGroup()
	a.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, a); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", withPublicId)))
	}
	return a, nil
}

// ListManagedGroups in an auth method and supports the following options:
//   - WithLimit
//   - WithStartPageAfterItem
func (r *Repository) ListManagedGroups(ctx context.Context, withAuthMethodId string, opt ...Option) ([]*ManagedGroup, error) {
	const op = "oidc.(Repository).ListManagedGroups"
	if withAuthMethodId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}

	var args []any
	args = append(args, sql.Named("with_auth_method_id", withAuthMethodId))
	whereClause := "auth_method_id = @with_auth_method_id"

	// Ordering and pagination are tightly coupled.
	// We order by update_time ascending so that new
	// and updated items appear at the end of the pagination.
	// We need to further order by public_id to distinguish items
	// with identical update times.
	withOrder := "update_time asc, public_id asc"
	if opts.withStartPageAfterItem != nil {
		// Now that the order is defined, we can use a simple where
		// clause to only include items updated since the specified
		// start of the page. We use greater than or equal for the update
		// time as there may be items with identical update_times. We
		// then use PublicId as a tiebreaker.
		args = append(args,
			sql.Named("after_item_update_time", opts.withStartPageAfterItem.GetUpdateTime()),
			sql.Named("after_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
		whereClause = "(" + whereClause + ") and (update_time > @after_item_update_time or (update_time = @after_item_update_time and public_id > @after_item_id))"
	}
	var mgs []*ManagedGroup
	err := r.reader.SearchWhere(ctx, &mgs, whereClause, args, db.WithLimit(limit), db.WithOrder(withOrder))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return mgs, nil
}

// DeleteManagedGroup deletes the managed group for the provided id from the
// repository returning a count of the number of records deleted. All options
// are ignored.
func (r *Repository) DeleteManagedGroup(ctx context.Context, scopeId, withPublicId string, opt ...Option) (int, error) {
	const op = "oidc.(Repository).DeleteManagedGroup"
	if withPublicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	if scopeId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	mg := AllocManagedGroup()
	mg.PublicId = withPublicId

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			metadata := mg.oplog(oplog.OpType_OP_TYPE_DELETE, scopeId)
			dMg := mg.Clone()
			rowsDeleted, err = w.Delete(ctx, dMg, db.WithOplog(oplogWrapper, metadata))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsDeleted > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been deleted")
			}
			return nil
		},
	)

	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(withPublicId))
	}

	return rowsDeleted, nil
}

// UpdateManagedGroup updates the repository entry for mg.PublicId with the
// values in mg for the fields listed in fieldMaskPaths. It returns a new
// ManagedGroup containing the updated values and a count of the number of
// records updated. mg is not changed.
//
// mg must contain a valid PublicId. Only mg.Name, mg.Description, and mg.Filter
// can be updated. If mg.Name is set to a non-empty string, it must be unique
// within mg.AuthMethodId.
//
// An attribute of a will be set to NULL in the database if the attribute in a
// is the zero value and it is included in fieldMaskPaths.
func (r *Repository) UpdateManagedGroup(ctx context.Context, scopeId string, mg *ManagedGroup, version uint32, fieldMaskPaths []string, opt ...Option) (*ManagedGroup, int, error) {
	const op = "oidc.(Repository).UpdateManagedGroup"
	if mg == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing ManagedGroup")
	}
	if mg.ManagedGroup == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing embedded ManagedGroup")
	}
	if mg.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	if version == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if scopeId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}

	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold(NameField, f):
		case strings.EqualFold(DescriptionField, f):
		case strings.EqualFold(FilterField, f):
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, f)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbw.BuildUpdatePaths(
		map[string]any{
			NameField:        mg.Name,
			DescriptionField: mg.Description,
			FilterField:      mg.Filter,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "missing field mask")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt),
			errors.WithMsg(("unable to get oplog wrapper")))
	}

	mg = mg.Clone()

	metadata := mg.oplog(oplog.OpType_OP_TYPE_UPDATE, scopeId)

	// TODO/FIXME: if the filter is updated, remove all account/mg associations

	var rowsUpdated int
	var returnedManagedGroup *ManagedGroup
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedManagedGroup = mg.Clone()
			var err error
			rowsUpdated, err = w.Update(ctx, returnedManagedGroup, dbMask, nullFields, db.WithOplog(oplogWrapper, metadata), db.WithVersion(&version))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsUpdated > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been updated")
			}
			return nil
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, db.NoRowsAffected, errors.New(ctx, errors.NotUnique, op,
				fmt.Sprintf("name %s already exists: %s", mg.Name, mg.PublicId))
		}
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(mg.PublicId))
	}

	return returnedManagedGroup, rowsUpdated, nil
}

// listDeletedManagedGroupIds lists the public IDs of any managed groups deleted since the timestamp provided.
func (r *Repository) listDeletedManagedGroupIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	const op = "oidc.(Repository).listDeletedManagedGroupIds"
	var deletedManagedGroups []*deletedManagedGroup
	var transactionTimestamp time.Time
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		if err := r.SearchWhere(ctx, &deletedManagedGroups, "delete_time >= ?", []any{since}); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted managed groups"))
		}
		var err error
		transactionTimestamp, err = r.Now(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query transaction timestamp"))
		}
		return nil
	}); err != nil {
		return nil, time.Time{}, err
	}
	var mgIds []string
	for _, mg := range deletedManagedGroups {
		mgIds = append(mgIds, mg.PublicId)
	}
	return mgIds, transactionTimestamp, nil
}

// estimatedManagedGroupCount returns and estimate of the total number of items in the managed groups table.
func (r *Repository) estimatedManagedGroupCount(ctx context.Context) (int, error) {
	const op = "oidc.(Repository).estimatedManagedGroupCount"
	rows, err := r.reader.Query(ctx, estimateCountOidcManagedGroups, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total managed groups"))
	}
	var count int
	for rows.Next() {
		if err := r.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total managed groups"))
		}
	}
	return count, nil
}
