// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package static

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-dbw"
)

// CreateHost inserts h into the repository and returns a new Host
// containing the host's PublicId. h is not changed. h must contain a valid
// CatalogId. h must not contain a PublicId. The PublicId is generated and
// assigned by this method. opt is ignored.
//
// h must contain a valid Address.
//
// Both h.Name and h.Description are optional. If h.Name is set, it must be
// unique within h.CatalogId.
func (r *Repository) CreateHost(ctx context.Context, projectId string, h *Host, opt ...Option) (*Host, error) {
	const op = "static.(Repository).CreateHost"
	if h == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil Host")
	}
	if h.Host == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil embedded Host")
	}
	if h.CatalogId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no catalog id")
	}
	if h.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}
	if projectId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no project id")
	}
	h.Address = strings.TrimSpace(h.Address)
	if len(h.Address) < MinHostAddressLength || len(h.Address) > MaxHostAddressLength {
		return nil, errors.New(ctx, errors.InvalidAddress, op, "invalid address")
	}
	h = h.clone()

	opts := getOpts(opt...)

	if opts.withPublicId != "" {
		if !strings.HasPrefix(opts.withPublicId, globals.StaticHostPrefix+"_") {
			return nil, errors.New(ctx,
				errors.InvalidPublicId,
				op,
				fmt.Sprintf("passed-in public ID %q has wrong prefix, should be %q", opts.withPublicId, globals.StaticHostPrefix),
			)
		}
		h.PublicId = opts.withPublicId
	} else {
		id, err := newHostId(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		h.PublicId = id
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var newHost *Host
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newHost = h.clone()
			err := w.Create(ctx, newHost, db.WithOplog(oplogWrapper, h.oplog(oplog.OpType_OP_TYPE_CREATE)))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in catalog: %s: name %s already exists", h.CatalogId, h.Name)))
		}
		if errors.IsCheckConstraintError(err) || errors.IsNotNullError(err) {
			return nil, errors.New(ctx,
				errors.InvalidAddress,
				op,
				fmt.Sprintf("in catalog: %s: %q", h.CatalogId, h.Address),
				errors.WithWrap(err),
			)
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in catalog: %s", h.CatalogId)))
	}
	return newHost, nil
}

// UpdateHost updates the repository entry for h.PublicId with the values
// in h for the fields listed in fieldMaskPaths. It returns a new Host
// containing the updated values and a count of the number of records
// updated. h is not changed.
//
// h must contain a valid PublicId. Only h.Name, h.Description, and
// h.Address can be updated. If h.Name is set to a non-empty string, it
// must be unique within h.CatalogId. If h.Address is set, it must contain
// a valid address.
//
// An attribute of h will be set to NULL in the database if the attribute
// in h is the zero value and it is included in fieldMaskPaths.
func (r *Repository) UpdateHost(ctx context.Context, projectId string, h *Host, version uint32, fieldMaskPaths []string, opt ...Option) (*Host, int, error) {
	const op = "static.(Repository).UpdateHost"
	if h == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "nil Host")
	}
	if h.Host == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "nil embedded Host")
	}
	if h.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	if version == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no version")
	}
	if projectId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no project id")
	}

	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("Name", f):
		case strings.EqualFold("Description", f):
		case strings.EqualFold("Address", f):
			h.Address = strings.TrimSpace(h.Address)
			if len(h.Address) < MinHostAddressLength || len(h.Address) > MaxHostAddressLength {
				return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidAddress, op, "invalid address")
			}
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, fmt.Sprintf("invalid field mask: %s", f))
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbw.BuildUpdatePaths(
		map[string]any{
			"Name":        h.Name,
			"Description": h.Description,
			"Address":     h.Address,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "empty field mask")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsUpdated int
	var returnedHost *Host
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedHost = h.clone()
			var err error
			rowsUpdated, err = w.Update(ctx, returnedHost, dbMask, nullFields,
				db.WithOplog(oplogWrapper, h.oplog(oplog.OpType_OP_TYPE_UPDATE)),
				db.WithVersion(&version))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsUpdated > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been updated")
			}
			ha := &hostAgg{
				PublicId: h.PublicId,
			}
			if err := r.reader.LookupByPublicId(ctx, ha); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("failed to lookup host after update"))
			}
			returnedHost.SetIds = ha.getSetIds()
			return nil
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in %s: name %s already exists", h.PublicId, h.Name)))
		}
		if errors.IsCheckConstraintError(err) || errors.IsNotNullError(err) {
			return nil, db.NoRowsAffected, errors.New(ctx,
				errors.InvalidAddress,
				op,
				fmt.Sprintf("in %s: %q", h.PublicId, h.Address),
				errors.WithWrap(err),
			)
		}
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in %s", h.PublicId)))
	}

	return returnedHost, rowsUpdated, nil
}

// LookupHost will look up a host in the repository. If the host is not
// found, it will return nil, nil. All options are ignored.
func (r *Repository) LookupHost(ctx context.Context, publicId string, opt ...Option) (*Host, error) {
	const op = "static.(Repository).LookupHost"
	if publicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	ha := &hostAgg{
		PublicId: publicId,
	}
	if err := r.reader.LookupByPublicId(ctx, ha); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", publicId)))
	}
	return ha.toHost(), nil
}

// ListHosts returns a slice of Hosts for the catalogId.
// WithLimit is the only option supported.
func (r *Repository) ListHosts(ctx context.Context, catalogId string, opt ...Option) ([]*Host, error) {
	const op = "static.(Repository).ListHosts"
	if catalogId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no catalog id")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var aggs []*hostAgg
	err := r.reader.SearchWhere(ctx, &aggs, "catalog_id = ?", []any{catalogId}, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	hosts := make([]*Host, 0, len(aggs))
	for _, ha := range aggs {
		hosts = append(hosts, ha.toHost())
	}

	return hosts, nil
}

// DeleteHost deletes the host for the provided id from the repository
// returning a count of the number of records deleted. All options are
// ignored.
func (r *Repository) DeleteHost(ctx context.Context, projectId string, publicId string, opt ...Option) (int, error) {
	const op = "static.(Repository).DeleteHost"
	if publicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	h := allocHost()
	h.PublicId = publicId

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			dh := h.clone()
			rowsDeleted, err = w.Delete(ctx, dh, db.WithOplog(oplogWrapper, h.oplog(oplog.OpType_OP_TYPE_DELETE)))
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
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("delete failed for %s", publicId)))
	}

	return rowsDeleted, nil
}
