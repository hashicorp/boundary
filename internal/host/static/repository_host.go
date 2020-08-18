package static

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/oplog"
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
func (r *Repository) CreateHost(ctx context.Context, h *Host, opt ...Option) (*Host, error) {
	if h == nil {
		return nil, fmt.Errorf("create: static host: %w", db.ErrNilParameter)
	}
	if h.Host == nil {
		return nil, fmt.Errorf("create: static host: embedded Host: %w", db.ErrNilParameter)
	}
	if h.CatalogId == "" {
		return nil, fmt.Errorf("create: static host: no catalog id: %w", db.ErrInvalidParameter)
	}
	if h.PublicId != "" {
		return nil, fmt.Errorf("create: static host: public id not empty: %w", db.ErrInvalidParameter)
	}
	h = h.clone()

	id, err := newHostId()
	if err != nil {
		return nil, fmt.Errorf("create: static host: %w", err)
	}
	h.PublicId = id

	var newHost *Host
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newHost = h.clone()
			return w.Create(ctx, newHost, db.WithOplog(r.wrapper, h.oplog(oplog.OpType_OP_TYPE_CREATE)))
		},
	)

	if err != nil {
		if db.IsUniqueError(err) {
			return nil, fmt.Errorf("create: static host: in catalog: %s: name %s already exists: %w",
				h.CatalogId, h.Name, db.ErrNotUnique)
		}
		if db.IsCheckConstraintError(err) || db.IsNotNullError(err) {
			return nil, fmt.Errorf("create: static host: in catalog: %s: %q: %w",
				h.CatalogId, h.Address, ErrInvalidAddress)
		}
		return nil, fmt.Errorf("create: static host: in catalog: %s: %w", h.CatalogId, err)
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
func (r *Repository) UpdateHost(ctx context.Context, h *Host, version uint32, fieldMaskPaths []string, opt ...Option) (*Host, int, error) {
	if h == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host: %w", db.ErrNilParameter)
	}
	if h.Host == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host: embedded Host: %w", db.ErrNilParameter)
	}
	if h.PublicId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host: missing public id: %w", db.ErrInvalidParameter)
	}
	if version == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host: no version supplied: %w", db.ErrInvalidParameter)
	}

	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("Name", f):
		case strings.EqualFold("Description", f):
		case strings.EqualFold("Address", f):
		default:
			return nil, db.NoRowsAffected, fmt.Errorf("update: static host: field: %s: %w", f, db.ErrInvalidFieldMask)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"Name":        h.Name,
			"Description": h.Description,
			"Address":     h.Address,
		},
		fieldMaskPaths,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host: %w", db.ErrEmptyFieldMask)
	}

	h = h.clone()

	var rowsUpdated int
	var returnedHost *Host
	_, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedHost = h.clone()
			var err error
			rowsUpdated, err = w.Update(ctx, returnedHost, dbMask, nullFields,
				db.WithOplog(r.wrapper, h.oplog(oplog.OpType_OP_TYPE_UPDATE)),
				db.WithVersion(&version))
			if err == nil && rowsUpdated > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)

	if err != nil {
		if db.IsUniqueError(err) {
			return nil, db.NoRowsAffected, fmt.Errorf("update: static host: %s: name %s already exists: %w",
				h.PublicId, h.Name, db.ErrNotUnique)
		}
		if db.IsCheckConstraintError(err) || db.IsNotNullError(err) {
			return nil, db.NoRowsAffected, fmt.Errorf("update: static host: %s: %q: %w", h.PublicId, h.Address, ErrInvalidAddress)
		}
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host: %s: %w", h.PublicId, err)
	}

	return returnedHost, rowsUpdated, nil
}
