// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package static

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-dbw"
)

// CreateSet inserts s into the repository and returns a new HostSet
// containing the host set's PublicId. s is not changed. s must contain a
// valid CatalogId. s must not contain a PublicId. The PublicId is
// generated and assigned by this method. opt is ignored.
//
// Both s.Name and s.Description are optional. If s.Name is set, it must be
// unique within s.CatalogId.
func (r *Repository) CreateSet(ctx context.Context, projectId string, s *HostSet, opt ...Option) (*HostSet, error) {
	const op = "static.(Repository).CreateSet"
	if s == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil HostSet")
	}
	if s.HostSet == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil embedded HostSet")
	}
	if s.CatalogId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no catalog id")
	}
	if s.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}
	if projectId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no project id")
	}
	s = s.clone()

	opts := getOpts(opt...)

	if opts.withPublicId != "" {
		if !strings.HasPrefix(opts.withPublicId, globals.StaticHostSetPrefix+"_") {
			return nil, errors.New(ctx,
				errors.InvalidPublicId,
				op,
				fmt.Sprintf("passed-in public ID %q has wrong prefix, should be %q", opts.withPublicId, globals.StaticHostSetPrefix),
			)
		}
		s.PublicId = opts.withPublicId
	} else {
		id, err := newHostSetId(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		s.PublicId = id
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var newHostSet *HostSet
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newHostSet = s.clone()
			err := w.Create(ctx, newHostSet, db.WithOplog(oplogWrapper, s.oplog(oplog.OpType_OP_TYPE_CREATE)))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in catalog: %s: name %s already exists", s.CatalogId, s.Name)))
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in catalog: %s", s.CatalogId)))
	}
	return newHostSet, nil
}

// UpdateSet updates the repository entry for s.PublicId with the values in
// s for the fields listed in fieldMaskPaths. It returns a new HostSet
// containing the updated values, the hosts assigned to the host set, and a
// count of the number of records updated. s is not changed.
//
// s must contain a valid PublicId. Only s.Name and s.Description can be
// updated. If s.Name is set to a non-empty string, it must be unique
// within s.CatalogId.
//
// An attribute of s will be set to NULL in the database if the attribute
// in s is the zero value and it is included in fieldMaskPaths.
//
// The WithLimit option can be used to limit the number of hosts returned.
// All other options are ignored.
func (r *Repository) UpdateSet(ctx context.Context, projectId string, s *HostSet, version uint32, fieldMaskPaths []string, opt ...Option) (*HostSet, []*Host, int, error) {
	const op = "static.(Repository).UpdateSet"
	if s == nil {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "nil HostSet")
	}
	if s.HostSet == nil {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "nil embedded HostSet")
	}
	if s.PublicId == "" {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	if version == 0 {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no version")
	}
	if projectId == "" {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no project id")
	}

	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("Name", f):
		case strings.EqualFold("Description", f):
		default:
			return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, fmt.Sprintf("invalid field mask: %s", f))
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbw.BuildUpdatePaths(
		map[string]any{
			"Name":        s.Name,
			"Description": s.Description,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "empty field mask")
	}

	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsUpdated int
	var returnedHostSet *HostSet
	var hosts []*Host
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			returnedHostSet = s.clone()
			var err error
			rowsUpdated, err = w.Update(ctx, returnedHostSet, dbMask, nullFields,
				db.WithOplog(oplogWrapper, s.oplog(oplog.OpType_OP_TYPE_UPDATE)),
				db.WithVersion(&version))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsUpdated > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been updated")
			}
			hosts, err = getHosts(ctx, reader, s.PublicId, limit)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in %s: name %s already exists", s.PublicId, s.Name)))
		}
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in %s", s.PublicId)))
	}

	return returnedHostSet, hosts, rowsUpdated, nil
}

// Endpoints returns a slice of host.Endpoint for the provided set id.
// If there are no hosts in the provided set id the slice is empty.
// If the set does not exist an error is returned.
func (r *Repository) Endpoints(ctx context.Context, setId string) ([]*host.Endpoint, error) {
	const op = "static.(Repository).Endpoints"
	_, hs, err := r.lookupSet(ctx, setId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	var es []*host.Endpoint
	for _, h := range hs {
		es = append(es, &host.Endpoint{
			HostId:  h.GetPublicId(),
			SetId:   setId,
			Address: h.GetAddress(),
		})
	}
	return es, err
}

// LookupSet will look up a host set in the repository and return the host
// set and the hosts assigned to the host set. If the host set is not
// found, it will return nil, nil, nil. The WithLimit option can be used to
// limit the number of hosts returned. All other options are ignored.
func (r *Repository) LookupSet(ctx context.Context, publicId string, opt ...Option) (*HostSet, []*Host, error) {
	const op = "static.(Repository).LookupSet"
	if publicId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	return r.lookupSet(ctx, publicId, opt...)
}

func (r *Repository) lookupSet(ctx context.Context, publicId string, opt ...Option) (*HostSet, []*Host, error) {
	const op = "static.(Repository).lookupSet"
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}

	s := allocHostSet()
	s.PublicId = publicId

	if err := r.reader.LookupByPublicId(ctx, s); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil, nil
		}
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	var hosts []*Host
	var err error
	if hosts, err = getHosts(ctx, r.reader, s.PublicId, limit); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in %s", s.PublicId)))
	}
	return s, hosts, nil
}

// ListSets returns a slice of HostSets for the catalogId. WithLimit is the
// only option supported.
func (r *Repository) ListSets(ctx context.Context, catalogId string, opt ...Option) ([]*HostSet, error) {
	const op = "static.(Repository).ListSets"
	if catalogId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no catalog id")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var sets []*HostSet
	err := r.reader.SearchWhere(ctx, &sets, "catalog_id = ?", []any{catalogId}, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return sets, nil
}

// DeleteSet deletes the host set for the provided id from the repository
// returning a count of the number of records deleted. All options are
// ignored.
func (r *Repository) DeleteSet(ctx context.Context, projectId string, publicId string, opt ...Option) (int, error) {
	const op = "static.(Repository).DeleteSet"
	if publicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	if projectId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no project id")
	}
	s := allocHostSet()
	s.PublicId = publicId

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			ds := s.clone()
			rowsDeleted, err = w.Delete(ctx, ds, db.WithOplog(oplogWrapper, s.oplog(oplog.OpType_OP_TYPE_DELETE)))
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
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("delete failed for %s", s.PublicId)))
	}

	return rowsDeleted, nil
}
