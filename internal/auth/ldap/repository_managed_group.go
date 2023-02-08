// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ldap

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-dbw"
)

// CreateManagedGroup inserts an ManagedGroup, mg, into the repository and
// returns a new ManagedGroup containing its PublicId. mg is not changed. mg
// must contain a valid AuthMethodId. mg must not contain a PublicId. The
// PublicId is generated and assigned by this method. All options are ignored.
//
// Both mg.Name and mg.Description are optional. If mg.Name is set, it must be
// unique within mg.AuthMethodId.
func (r *Repository) CreateManagedGroup(ctx context.Context, scopeId string, mg *ManagedGroup, _ ...Option) (*ManagedGroup, error) {
	const op = "ldap.(Repository).CreateManagedGroup"
	switch {
	case mg == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing managed group")
	case mg.ManagedGroup == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing embedded managed group")
	case mg.AuthMethodId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	case len(mg.GroupNames) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing group names")
	case mg.PublicId != "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id must be empty")
	case scopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}

	mg = mg.clone()

	id, err := newManagedGroupId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	mg.PublicId = id

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"), errors.WithCode(errors.Encrypt))
	}

	oplogMetadata, err := mg.oplog(ctx, oplog.OpType_OP_TYPE_CREATE, scopeId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to generate managed group oplog metadata"))
	}

	var newManagedGroup *ManagedGroup
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newManagedGroup = mg.clone()
			if err := w.Create(ctx, newManagedGroup, db.WithOplog(oplogWrapper, oplogMetadata)); err != nil {
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
func (r *Repository) LookupManagedGroup(ctx context.Context, withPublicId string, _ ...Option) (*ManagedGroup, error) {
	const op = "ldap.(Repository).LookupManagedGroup"
	if withPublicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
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

// ListManagedGroups in an auth method and supports WithLimit option.
func (r *Repository) ListManagedGroups(ctx context.Context, withAuthMethodId string, opt ...Option) ([]*ManagedGroup, error) {
	const op = "ldap.(Repository).ListManagedGroups"
	if withAuthMethodId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var mgs []*ManagedGroup
	err = r.reader.SearchWhere(ctx, &mgs, "auth_method_id = ?", []any{withAuthMethodId}, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return mgs, nil
}

// DeleteManagedGroup deletes the managed group for the provided id from the
// repository returning a count of the number of records deleted. All options
// are ignored.
func (r *Repository) DeleteManagedGroup(ctx context.Context, scopeId, withPublicId string, opt ...Option) (int, error) {
	const op = "ldap.(Repository).DeleteManagedGroup"
	switch {
	case withPublicId == "":
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	case scopeId == "":
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	mg := AllocManagedGroup()
	mg.PublicId = withPublicId
	if err := r.reader.LookupById(ctx, mg); err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("managed group not found"))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("unable to get oplog wrapper"))
	}

	metadata, err := mg.oplog(ctx, oplog.OpType_OP_TYPE_DELETE, scopeId)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to generate oplog metadata"))
	}

	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			dMg := mg.clone()
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
// mg must contain a valid PublicId. Only mg.Name, mg.Description, and mg.GroupNames
// can be updated. If mg.Name is set to a non-empty string, it must be unique
// within mg.AuthMethodId.
//
// An attribute of a will be set to NULL in the database if the attribute in a
// is the zero value and it is included in fieldMaskPaths.
func (r *Repository) UpdateManagedGroup(ctx context.Context, scopeId string, mg *ManagedGroup, version uint32, fieldMaskPaths []string, opt ...Option) (*ManagedGroup, int, error) {
	const op = "ldap.(Repository).UpdateManagedGroup"
	switch {
	case mg == nil:
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing ManagedGroup")
	case mg.ManagedGroup == nil:
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing embedded ManagedGroup")
	case mg.PublicId == "":
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	case version == 0:
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	case scopeId == "":
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}

	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold(NameField, f):
		case strings.EqualFold(DescriptionField, f):
		case strings.EqualFold(GroupNamesField, f):
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, f)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbw.BuildUpdatePaths(
		map[string]any{
			NameField:        mg.Name,
			DescriptionField: mg.Description,
			GroupNamesField:  mg.GroupNames,
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

	foundMg := AllocManagedGroup()
	foundMg.PublicId = mg.PublicId
	if err := r.reader.LookupById(ctx, foundMg); err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("managed group not found"))
	}
	metadata, err := foundMg.oplog(ctx, oplog.OpType_OP_TYPE_UPDATE, scopeId)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to generate oplog metadata"))
	}
	var rowsUpdated int
	var returnedManagedGroup *ManagedGroup
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedManagedGroup = mg.clone()
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
