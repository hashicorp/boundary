// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/perms"
)

// targetAndScopeIdsForDestinations returns the target ids for which there is
// at least one permission. If all targets in a specific scope are granted
// permission for an action, then the scope id is in the returned scope id slice.
func targetAndScopeIdsForDestinations(perms []perms.Permission) ([]string, []string) {
	var targetIds, scopeIds []string
	for _, perm := range perms {
		switch {
		case perm.All:
			scopeIds = append(scopeIds, perm.ScopeId)
		case len(perm.ResourceIds) > 0:
			targetIds = append(targetIds, perm.ResourceIds...)
		}
	}
	return targetIds, scopeIds
}

// listResolvableAliases lists aliases which have a destination id set to that
// of a target for which there is permission in the provided slice of permissions.
// Only WithLimit and WithStartPageAfterItem options are supported.
func (r *Repository) listResolvableAliases(ctx context.Context, permissions []perms.Permission, opt ...Option) ([]*Alias, time.Time, error) {
	const op = "target.(Repository).listResolvableAliases"
	switch {
	case len(permissions) == 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing permissions")
	}
	toTargetIds, toTargetsInScopeIds := targetAndScopeIdsForDestinations(permissions)

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
	var destinationIdClauses []string
	if len(toTargetIds) > 0 {
		destinationIdClauses = append(destinationIdClauses, "destination_id in @target_ids")
		args = append(args, sql.Named("target_ids", toTargetIds))
	}
	if len(toTargetsInScopeIds) > 0 {
		destinationIdClauses = append(destinationIdClauses, "destination_id in (select public_id from target where project_id in @target_scope_ids)")
		args = append(args, sql.Named("target_scope_ids", toTargetsInScopeIds))
	}
	if len(destinationIdClauses) == 0 {
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "no target ids or scope ids provided")
	}

	whereClause := fmt.Sprintf("destination_id is not null and (%s)", strings.Join(destinationIdClauses, " or "))

	if opts.withStartPageAfterItem != nil {
		whereClause = fmt.Sprintf("(create_time, public_id) < (@last_item_create_time, @last_item_id) and %s", whereClause)
		args = append(args,
			sql.Named("last_item_create_time", opts.withStartPageAfterItem.GetCreateTime()),
			sql.Named("last_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
	}
	dbOpts := []db.Option{db.WithLimit(limit), db.WithOrder("create_time desc, public_id desc"), db.WithDebug(true)}
	return r.queryAliases(ctx, whereClause, args, dbOpts...)
}

// listResolvableAliasesRefresh lists aliases limited by the list
// permissions of the repository.
// Supported options:
//   - withLimit
//   - withStartPageAfterItem
func (r *Repository) listResolvableAliasesRefresh(ctx context.Context, updatedAfter time.Time, permissions []perms.Permission, opt ...Option) ([]*Alias, time.Time, error) {
	const op = "target.(Repository).listResolvableAliasesRefresh"

	switch {
	case updatedAfter.IsZero():
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing updated after time")
	case len(permissions) == 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing permissions")
	}
	toTargetIds, toTargetsInScopeIds := targetAndScopeIdsForDestinations(permissions)

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
	var destinationIdClauses []string
	if len(toTargetIds) > 0 {
		destinationIdClauses = append(destinationIdClauses, "destination_id in @target_ids")
		args = append(args, sql.Named("target_ids", toTargetIds))
	}
	if len(toTargetsInScopeIds) > 0 {
		destinationIdClauses = append(destinationIdClauses, "destination_id in (select public_id from target where project_id in @target_scope_ids)")
		args = append(args, sql.Named("target_scope_ids", toTargetsInScopeIds))
	}
	if len(destinationIdClauses) == 0 {
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "no target ids or scope ids provided")
	}

	whereClause := fmt.Sprintf("update_time > @updated_after_time and destination_id is not null and (%s)",
		strings.Join(destinationIdClauses, " or "))
	args = append(args,
		sql.Named("updated_after_time", timestamp.New(updatedAfter)),
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

// listRemovedResolvableIds lists the public IDs of any aliases deleted since
// the timestamp provided or which have been updated since the timestamp provided
// and do not have a destination id set to the id of a target for which there
// are permissions in the provided slice of permissions.
func (r *Repository) listRemovedResolvableAliasIds(ctx context.Context, since time.Time, permissions []perms.Permission) ([]string, time.Time, error) {
	const op = "target.(Repository).listRemovedResolvableIds"
	switch {
	case len(permissions) == 0:
		// while a lack of permissions is one way for targets to not be included
		// in the list of resolvable aliases, if permissions were always empty
		// then no aliases would have been returned in the first place and so
		// no ids would need to be removed. If permissions were changed to
		// become empty, then the list token would be invalidated and we shouldnt
		// have made it here, so it is an error for an empty slice of permissions
		// to be provided.
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing permissions")
	}
	toTargetIds, toTargetsInScopeIds := targetAndScopeIdsForDestinations(permissions)

	var args []any
	var destinationIdClauses []string
	if len(toTargetIds) > 0 {
		destinationIdClauses = append(destinationIdClauses, "destination_id not in @target_ids")
		args = append(args, sql.Named("target_ids", toTargetIds))
	}
	if len(toTargetsInScopeIds) > 0 {
		destinationIdClauses = append(destinationIdClauses, "destination_id not in (select public_id from target where project_id in @target_scope_ids)")
		args = append(args, sql.Named("target_scope_ids", toTargetsInScopeIds))
	}
	if len(destinationIdClauses) == 0 {
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "no target ids or scope ids provided")
	}
	whereClause := fmt.Sprintf("update_time > @updated_after_time and (destination_id is null or (%s))",
		strings.Join(destinationIdClauses, " and "))
	args = append(args,
		sql.Named("updated_after_time", timestamp.New(since)),
	)

	// The calculating of the deleted aliases and the non matching alises
	// must happen in the same transaction to ensure consistency.
	var notMatchingAliases []*Alias
	var deletedAliases []*deletedAlias
	var transactionTimestamp time.Time
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, _ db.Writer) error {
		if err := r.SearchWhere(ctx, &deletedAliases, "delete_time >= ?", []any{since}); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted aliases"))
		}

		var inRet []*Alias
		if err := r.SearchWhere(ctx, &inRet, whereClause, args); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		notMatchingAliases = inRet

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
	for _, da := range deletedAliases {
		aliasIds = append(aliasIds, da.PublicId)
	}
	for _, na := range notMatchingAliases {
		aliasIds = append(aliasIds, na.PublicId)
	}
	return aliasIds, transactionTimestamp, nil
}
