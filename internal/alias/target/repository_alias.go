// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-dbw"
)

// CreateAlias inserts Alias a into the repository and returns a new
// Alias containing the alias's PublicId. a is not changed. a must
// contain a valid ScopeId. a must not contain a PublicId. The PublicId is
// generated and assigned by this method. opt is ignored.
//
// Description, DestinationId, and HostId are optional.
//
// Value must be globally unique.
func (r *Repository) CreateAlias(ctx context.Context, a *Alias, opt ...Option) (*Alias, error) {
	const op = "target.(Repository).CreateAlias"
	switch {
	case a == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil Alias")
	case a.Alias == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil embedded Alias")
	case a.Value == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no value")
	case a.ScopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	case a.PublicId != "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}
	a = a.Clone()

	id, err := newAliasId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	a.PublicId = id

	oplogWrapper, err := r.kms.GetWrapper(ctx, a.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	metadata := newAliasMetadata(a, oplog.OpType_OP_TYPE_CREATE)

	var newAlias *Alias
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newAlias = a.Clone()
			err := w.Create(
				ctx,
				newAlias,
				db.WithOplog(oplogWrapper, metadata),
			)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			switch {
			case strings.Contains(err.Error(), `"alias_value_uq"`):
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("alias value %q is already in use", a.Value)))
			case strings.Contains(err.Error(), `"alias_target_scope_id_name_uq"`):
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in scope %q, the name %q is already in use", a.ScopeId, a.Name)))
			}
		}
		if strings.Contains(err.Error(), `violates foreign key constraint "target_fkey"`) {
			return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.NotFound), errors.WithMsg("target with specified destination id %q was not found", a.GetDestinationId()))
		}
		if strings.Contains(err.Error(), `wt_target_alias_value_shape`) {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("alias value %q contains invalid characters", a.Value)))
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	return newAlias, nil
}

// UpdateAlias updates the repository entry for a.PublicId with the
// values in a for the fields listed in fieldMask. It returns a new
// Alias containing the updated values and a count of the number of
// records updated. a is not changed.
func (r *Repository) UpdateAlias(ctx context.Context, a *Alias, version uint32, fieldMask []string, opt ...Option) (*Alias, int, error) {
	const op = "target.(Repository).UpdateAlias"
	switch {
	case a == nil:
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "nil Alias")
	case a.Alias == nil:
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "nil embedded Alias")
	case a.PublicId == "":
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	case len(fieldMask) == 0:
		return nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "empty field mask")
	case version == 0:
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no version")
	}

	for _, f := range fieldMask {
		switch {
		case strings.EqualFold(valueField, f):
		case strings.EqualFold(nameField, f):
		case strings.EqualFold(descriptionField, f):
		case strings.EqualFold(destinationIdField, f):
		case strings.EqualFold(hostIdField, f):
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, fmt.Sprintf("invalid field mask: %s", f))
		}
	}

	dbMask, nullFields := dbw.BuildUpdatePaths(
		map[string]any{
			nameField:          a.Name,
			descriptionField:   a.Description,
			valueField:         a.Value,
			destinationIdField: a.DestinationId,
			hostIdField:        a.HostId,
		},
		fieldMask,
		nil,
	)
	if slices.Contains(nullFields, valueField) {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "value cannot be empty")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, a.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	a = a.Clone()

	metadata := newAliasMetadata(a, oplog.OpType_OP_TYPE_UPDATE)

	var rowsUpdated int
	var returnedAlias *Alias
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedAlias = a.Clone()
			var err error
			rowsUpdated, err = w.Update(
				ctx,
				returnedAlias,
				dbMask,
				nullFields,
				db.WithOplog(oplogWrapper, metadata),
				db.WithVersion(&version),
			)
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
			switch {
			case strings.Contains(err.Error(), `"alias_value_uq"`):
				return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for alias %s: alias value %q is already in use", a.PublicId, a.Value)))
			case strings.Contains(err.Error(), `"alias_target_scope_id_name_uq"`):
				return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in scope %s, the name %q is already in use", a.ScopeId, a.Name)))
			}
		}
		if strings.Contains(err.Error(), `violates foreign key constraint "target_fkey"`) {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithCode(errors.NotFound), errors.WithMsg("target with specified destination id %q was not found", a.GetDestinationId()))
		}
		if strings.Contains(err.Error(), `wt_target_alias_value_shape`) {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("alias value contains invalid characters"))
		}
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}

	return returnedAlias, rowsUpdated, nil
}

// LookupAlias returns the Alias for id. Returns nil, nil if no
// Alias is found for id.
func (r *Repository) LookupAlias(ctx context.Context, id string, opt ...Option) (*Alias, error) {
	const op = "target.(Repository).LookupAlias"
	if id == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	a := allocAlias()
	a.PublicId = id
	if err := r.reader.LookupByPublicId(ctx, a); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", id)))
	}
	return a, nil
}

// LookupAliasByValue returns the Alias for the provided value. Returns nil, nil
// if no Alias is found for the provided value.
func (r *Repository) LookupAliasByValue(ctx context.Context, value string, opt ...Option) (*Alias, error) {
	const op = "target.(Repository).LookupAliasByValue"
	if value == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "value is empty")
	}
	a := allocAlias()
	if err := r.reader.LookupWhere(ctx, a, "value = $1", []any{value}); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %q", value)))
	}
	return a, nil
}

// DeleteAlias deletes id from the repository returning a count of the
// number of records deleted.
func (r *Repository) DeleteAlias(ctx context.Context, id string, opt ...Option) (int, error) {
	const op = "target.(Repository).DeleteAlias"
	if id == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}

	a := allocAlias()
	a.PublicId = id
	if err := r.reader.LookupByPublicId(ctx, a); err != nil {
		if errors.IsNotFoundError(err) {
			return db.NoRowsAffected, nil
		}
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", id)))
	}
	if a.ScopeId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, a.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	metadata := newAliasMetadata(a, oplog.OpType_OP_TYPE_DELETE)

	var rowsDeleted int
	var deleteAlias *Alias
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			deleteAlias = a.Clone()
			var err error
			rowsDeleted, err = w.Delete(
				ctx,
				deleteAlias,
				db.WithOplog(oplogWrapper, metadata),
			)
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
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("delete failed for %s", a.PublicId)))
	}

	return rowsDeleted, nil
}
