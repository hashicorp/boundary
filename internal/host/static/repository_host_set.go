package static

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/oplog"
)

// CreateSet inserts s into the repository and returns a new Set containing
// the host set's PublicId. s is not changed. s must contain a valid
// CatalogId. s must not contain a PublicId. The PublicId is generated and
// assigned by this method. opt is ignored.
//
// Both s.Name and s.Description are optional. If s.Name is set, it must be
// unique within s.CatalogId.
func (r *Repository) CreateSet(ctx context.Context, s *HostSet, opt ...Option) (*HostSet, error) {
	if s == nil {
		return nil, fmt.Errorf("create: static host set: %w", db.ErrNilParameter)
	}
	if s.HostSet == nil {
		return nil, fmt.Errorf("create: static host set: embedded Set: %w", db.ErrNilParameter)
	}
	if s.CatalogId == "" {
		return nil, fmt.Errorf("create: static host set: no catalog id: %w", db.ErrInvalidParameter)
	}
	if s.PublicId != "" {
		return nil, fmt.Errorf("create: static host set: public id not empty: %w", db.ErrInvalidParameter)
	}
	s = s.clone()

	id, err := newHostSetId()
	if err != nil {
		return nil, fmt.Errorf("create: static host set: %w", err)
	}
	s.PublicId = id

	var newSet *HostSet
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newSet = s.clone()
			return w.Create(ctx, newSet, db.WithOplog(r.wrapper, s.oplog(oplog.OpType_OP_TYPE_CREATE)))
		},
	)

	if err != nil {
		if db.IsUniqueError(err) {
			return nil, fmt.Errorf("create: static host set: in catalog: %s: name %s already exists: %w",
				s.CatalogId, s.Name, db.ErrNotUnique)
		}
		return nil, fmt.Errorf("create: static host set: in catalog: %s: %w", s.CatalogId, err)
	}
	return newSet, nil
}

// UpdateSet updates the repository entry for s.PublicId with the values in
// s for the fields listed in fieldMaskPaths. It returns a new HostSet
// containing the updated values and a count of the number of records
// updated. s is not changed.
//
// s must contain a valid PublicId. Only s.Name and s.Description can be
// updated. If s.Name is set to a non-empty string, it must be unique
// within s.CatalogId.
//
// An attribute of s will be set to NULL in the database if the attribute
// in s is the zero value and it is included in fieldMaskPaths.
func (r *Repository) UpdateSet(ctx context.Context, s *HostSet, version uint32, fieldMaskPaths []string, opt ...Option) (*HostSet, int, error) {
	if s == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host set: %w", db.ErrNilParameter)
	}
	if s.HostSet == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host set: embedded HostSet: %w", db.ErrNilParameter)
	}
	if s.PublicId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host set: missing public id: %w", db.ErrInvalidParameter)
	}
	if version == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host set: no version supplied: %w", db.ErrInvalidParameter)
	}

	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("Name", f):
		case strings.EqualFold("Description", f):
		default:
			return nil, db.NoRowsAffected, fmt.Errorf("update: static host set: field: %s: %w", f, db.ErrInvalidFieldMask)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"Name":        s.Name,
			"Description": s.Description,
		},
		fieldMaskPaths,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host set: %w", db.ErrEmptyFieldMask)
	}

	s = s.clone()

	var rowsUpdated int
	var returnedHostSet *HostSet
	_, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedHostSet = s.clone()
			var err error
			rowsUpdated, err = w.Update(ctx, returnedHostSet, dbMask, nullFields,
				db.WithOplog(r.wrapper, s.oplog(oplog.OpType_OP_TYPE_UPDATE)),
				db.WithVersion(&version))
			if err == nil && rowsUpdated > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)

	if err != nil {
		if db.IsUniqueError(err) {
			return nil, db.NoRowsAffected, fmt.Errorf("update: static host set: %s: name %s already exists: %w",
				s.PublicId, s.Name, db.ErrNotUnique)
		}
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host set: %s: %w", s.PublicId, err)
	}

	return returnedHostSet, rowsUpdated, nil
}
