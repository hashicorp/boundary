package static

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// CreateSet inserts s into the repository and returns a new HostSet
// containing the host set's PublicId. s is not changed. s must contain a
// valid CatalogId. s must not contain a PublicId. The PublicId is
// generated and assigned by this method. opt is ignored.
//
// Both s.Name and s.Description are optional. If s.Name is set, it must be
// unique within s.CatalogId.
func (r *Repository) CreateSet(ctx context.Context, scopeId string, s *HostSet, opt ...Option) (*HostSet, error) {
	if s == nil {
		return nil, fmt.Errorf("create: static host set: %w", db.ErrInvalidParameter)
	}
	if s.HostSet == nil {
		return nil, fmt.Errorf("create: static host set: embedded HostSet: %w", db.ErrInvalidParameter)
	}
	if s.CatalogId == "" {
		return nil, fmt.Errorf("create: static host set: no catalog id: %w", db.ErrInvalidParameter)
	}
	if s.PublicId != "" {
		return nil, fmt.Errorf("create: static host set: public id not empty: %w", db.ErrInvalidParameter)
	}
	if scopeId == "" {
		return nil, fmt.Errorf("create: static host set: no scopeId: %w", db.ErrInvalidParameter)
	}
	s = s.clone()

	opts := getOpts(opt...)

	if opts.withPublicId != "" {
		if !strings.HasPrefix(opts.withPublicId, HostSetPrefix+"_") {
			return nil, fmt.Errorf("create: static host set: passed-in public ID %q has wrong prefix, should be %q: %w", opts.withPublicId, HostSetPrefix, db.ErrInvalidPublicId)
		}
		s.PublicId = opts.withPublicId
	} else {
		id, err := newHostSetId()
		if err != nil {
			return nil, fmt.Errorf("create: static host set: %w", err)
		}
		s.PublicId = id
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, fmt.Errorf("create: static host set: unable to get oplog wrapper: %w", err)
	}

	var newHostSet *HostSet
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newHostSet = s.clone()
			return w.Create(ctx, newHostSet, db.WithOplog(oplogWrapper, s.oplog(oplog.OpType_OP_TYPE_CREATE)))
		},
	)

	if err != nil {
		if db.IsUniqueError(err) {
			return nil, fmt.Errorf("create: static host set: in catalog: %s: name %s already exists: %w",
				s.CatalogId, s.Name, db.ErrNotUnique)
		}
		return nil, fmt.Errorf("create: static host set: in catalog: %s: %w", s.CatalogId, err)
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
func (r *Repository) UpdateSet(ctx context.Context, scopeId string, s *HostSet, version uint32, fieldMaskPaths []string, opt ...Option) (*HostSet, []*Host, int, error) {
	if s == nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update: static host set: %w", db.ErrInvalidParameter)
	}
	if s.HostSet == nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update: static host set: embedded HostSet: %w", db.ErrInvalidParameter)
	}
	if s.PublicId == "" {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update: static host set: missing public id: %w", db.ErrInvalidParameter)
	}
	if version == 0 {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update: static host set: no version supplied: %w", db.ErrInvalidParameter)
	}
	if scopeId == "" {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update: static host set: no scopeId: %w", db.ErrInvalidParameter)
	}

	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("Name", f):
		case strings.EqualFold("Description", f):
		default:
			return nil, nil, db.NoRowsAffected, fmt.Errorf("update: static host set: field: %s: %w", f, db.ErrInvalidFieldMask)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"Name":        s.Name,
			"Description": s.Description,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update: static host set: %w", db.ErrEmptyFieldMask)
	}

	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update: static host set: unable to get oplog wrapper: %w", err)
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
			if err == nil && rowsUpdated > 1 {
				return db.ErrMultipleRecords
			}
			if err != nil {
				return err
			}
			hosts, err = getHosts(ctx, reader, s.PublicId, limit)
			return err
		},
	)

	if err != nil {
		if db.IsUniqueError(err) {
			return nil, nil, db.NoRowsAffected, fmt.Errorf("update: static host set: %s: name %s already exists: %w",
				s.PublicId, s.Name, db.ErrNotUnique)
		}
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update: static host set: %s: %w", s.PublicId, err)
	}

	return returnedHostSet, hosts, rowsUpdated, nil
}

// LookupSet will look up a host set in the repository and return the host
// set and the hosts assigned to the host set. If the host set is not
// found, it will return nil, nil, nil. The WithLimit option can be used to
// limit the number of hosts returned. All other options are ignored.
func (r *Repository) LookupSet(ctx context.Context, publicId string, opt ...Option) (*HostSet, []*Host, error) {
	if publicId == "" {
		return nil, nil, fmt.Errorf("lookup: static host set: missing public id %w", db.ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}

	s := allocHostSet()
	s.PublicId = publicId

	var hosts []*Host
	_, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, _ db.Writer) error {
		if err := reader.LookupByPublicId(ctx, s); err != nil {
			if errors.Is(err, db.ErrRecordNotFound) {
				s = nil
				return nil
			}
			return err
		}
		var err error
		hosts, err = getHosts(ctx, reader, s.PublicId, limit)
		return err
	})

	if err != nil {
		return nil, nil, fmt.Errorf("lookup: static host set: failed %w for %s", err, publicId)
	}

	return s, hosts, nil
}

// ListSets returns a slice of HostSets for the catalogId. WithLimit is the
// only option supported.
func (r *Repository) ListSets(ctx context.Context, catalogId string, opt ...Option) ([]*HostSet, error) {
	if catalogId == "" {
		return nil, fmt.Errorf("list: static host set: missing catalog id: %w", db.ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var sets []*HostSet
	err := r.reader.SearchWhere(ctx, &sets, "catalog_id = ?", []interface{}{catalogId}, db.WithLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("list: static host set: %w", err)
	}
	return sets, nil
}

// DeleteSet deletes the host set for the provided id from the repository
// returning a count of the number of records deleted. All options are
// ignored.
func (r *Repository) DeleteSet(ctx context.Context, scopeId string, publicId string, opt ...Option) (int, error) {
	if publicId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete: static host set: missing public id: %w", db.ErrInvalidParameter)
	}
	if scopeId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete: static host set: no scopeId: %w", db.ErrInvalidParameter)
	}
	s := allocHostSet()
	s.PublicId = publicId

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete: static host set: unable to get oplog wrapper: %w", err)
	}

	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			ds := s.clone()
			rowsDeleted, err = w.Delete(ctx, ds, db.WithOplog(oplogWrapper, s.oplog(oplog.OpType_OP_TYPE_DELETE)))
			if err == nil && rowsDeleted > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)

	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete: static host set: %s: %w", publicId, err)
	}

	return rowsDeleted, nil
}
