package static

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// CreateCatalog inserts c into the repository and returns a new
// HostCatalog containing the catalog's PublicId. c is not changed. c must
// contain a valid ScopeID. c must not contain a PublicId. The PublicId is
// generated and assigned by the this method. opt is ignored.
//
// Both c.Name and c.Description are optional. If c.Name is set, it must be
// unique within c.ScopeID.
//
// Both c.CreateTime and c.UpdateTime are ignored.
func (r *Repository) CreateCatalog(ctx context.Context, c *HostCatalog, opt ...Option) (*HostCatalog, error) {
	if c == nil {
		return nil, fmt.Errorf("create: static host catalog: %w", db.ErrInvalidParameter)
	}
	if c.HostCatalog == nil {
		return nil, fmt.Errorf("create: static host catalog: embedded HostCatalog: %w", db.ErrInvalidParameter)
	}
	if c.ScopeId == "" {
		return nil, fmt.Errorf("create: static host catalog: no scope id: %w", db.ErrInvalidParameter)
	}
	if c.PublicId != "" {
		return nil, fmt.Errorf("create: static host catalog: public id not empty: %w", db.ErrInvalidParameter)
	}
	c = c.clone()

	opts := getOpts(opt...)

	if opts.withPublicId != "" {
		if !strings.HasPrefix(opts.withPublicId, HostCatalogPrefix+"_") {
			return nil, fmt.Errorf("create: static host catalog: passed-in public ID %q has wrong prefix, should be %q: %w", opts.withPublicId, HostCatalogPrefix, db.ErrInvalidPublicId)
		}
		c.PublicId = opts.withPublicId
	} else {
		id, err := newHostCatalogId()
		if err != nil {
			return nil, fmt.Errorf("create: static host catalog: %w", err)
		}
		c.PublicId = id
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, c.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, fmt.Errorf("create: static host catalog: unable to get oplog wrapper: %w", err)
	}

	metadata := newCatalogMetadata(c, oplog.OpType_OP_TYPE_CREATE)

	var newHostCatalog *HostCatalog
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newHostCatalog = c.clone()
			return w.Create(
				ctx,
				newHostCatalog,
				db.WithOplog(oplogWrapper, metadata),
			)
		},
	)

	if err != nil {
		if db.IsUniqueError(err) {
			return nil, fmt.Errorf("create: static host catalog: in scope: %s: name %s already exists: %w",
				c.ScopeId, c.Name, db.ErrNotUnique)
		}
		return nil, fmt.Errorf("create: static host catalog: in scope: %s: %w", c.ScopeId, err)
	}
	return newHostCatalog, nil
}

// UpdateCatalog updates the repository entry for c.PublicId with the
// values in c for the fields listed in fieldMask. It returns a new
// HostCatalog containing the updated values and a count of the number of
// records updated. c is not changed.
//
// c must contain a valid PublicId. Only c.Name and c.Description can be
// updated. If c.Name is set to a non-empty string, it must be unique
// within c.ScopeID.
//
// An attribute of c will be set to NULL in the database if the attribute
// in c is the zero value and it is included in fieldMask.
func (r *Repository) UpdateCatalog(ctx context.Context, c *HostCatalog, version uint32, fieldMask []string, opt ...Option) (*HostCatalog, int, error) {
	if c == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host catalog: %w", db.ErrInvalidParameter)
	}
	if c.HostCatalog == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host catalog: embedded HostCatalog: %w", db.ErrInvalidParameter)
	}
	if c.PublicId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host catalog: missing public id: %w", db.ErrInvalidParameter)
	}
	if c.ScopeId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host catalog: missing scope id: %w", db.ErrInvalidParameter)
	}
	if len(fieldMask) == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host catalog: %w", db.ErrEmptyFieldMask)
	}

	var dbMask, nullFields []string
	for _, f := range fieldMask {
		switch {
		case strings.EqualFold("name", f) && c.Name == "":
			nullFields = append(nullFields, "name")
		case strings.EqualFold("name", f) && c.Name != "":
			dbMask = append(dbMask, "name")
		case strings.EqualFold("description", f) && c.Description == "":
			nullFields = append(nullFields, "description")
		case strings.EqualFold("description", f) && c.Description != "":
			dbMask = append(dbMask, "description")

		default:
			return nil, db.NoRowsAffected, fmt.Errorf("update: static host catalog: field: %s: %w", f, db.ErrInvalidFieldMask)
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, c.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host catalog: unable to get oplog wrapper: %w", err)
	}

	c = c.clone()

	metadata := newCatalogMetadata(c, oplog.OpType_OP_TYPE_UPDATE)

	var rowsUpdated int
	var returnedCatalog *HostCatalog
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedCatalog = c.clone()
			var err error
			rowsUpdated, err = w.Update(
				ctx,
				returnedCatalog,
				dbMask,
				nullFields,
				db.WithOplog(oplogWrapper, metadata),
				db.WithVersion(&version),
			)
			if err == nil && rowsUpdated > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)

	if err != nil {
		if db.IsUniqueError(err) {
			return nil, db.NoRowsAffected, fmt.Errorf("update: static host catalog: %s: name %s already exists: %w",
				c.PublicId, c.Name, db.ErrNotUnique)
		}
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host catalog: %s: %w", c.PublicId, err)
	}

	return returnedCatalog, rowsUpdated, nil
}

// LookupCatalog returns the HostCatalog for id. Returns nil, nil if no
// HostCatalog is found for id.
func (r *Repository) LookupCatalog(ctx context.Context, id string, opt ...Option) (*HostCatalog, error) {
	if id == "" {
		return nil, fmt.Errorf("lookup: static host catalog: missing public id: %w", db.ErrInvalidParameter)
	}
	c := allocCatalog()
	c.PublicId = id
	if err := r.reader.LookupByPublicId(ctx, c); err != nil {
		if err == db.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("lookup: static host catalog: %s: %w", id, err)
	}
	return c, nil
}

// ListCatalogs returns a slice of HostCatalogs for the scopeId. WithLimit is the only option supported.
func (r *Repository) ListCatalogs(ctx context.Context, scopeId string, opt ...Option) ([]*HostCatalog, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("list: static host catalog: missing scope id: %w", db.ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var hostCatalogs []*HostCatalog
	err := r.reader.SearchWhere(ctx, &hostCatalogs, "scope_id = ?", []interface{}{scopeId}, db.WithLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("list: static host catalog: %w", err)
	}
	return hostCatalogs, nil
}

// DeleteCatalog deletes id from the repository returning a count of the
// number of records deleted.
func (r *Repository) DeleteCatalog(ctx context.Context, id string, opt ...Option) (int, error) {
	if id == "" {
		return db.NoRowsAffected, fmt.Errorf("delete: static host catalog: missing public id: %w", db.ErrInvalidParameter)
	}

	c := allocCatalog()
	c.PublicId = id
	if err := r.reader.LookupByPublicId(ctx, c); err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return db.NoRowsAffected, nil
		}
		return db.NoRowsAffected, fmt.Errorf("delete: static host catalog: failed %w for %s", err, id)
	}
	if c.ScopeId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete: static host catalog: missing scope id: %w", db.ErrInvalidParameter)
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, c.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete: static host catalog: unable to get oplog wrapper: %w", err)
	}

	metadata := newCatalogMetadata(c, oplog.OpType_OP_TYPE_DELETE)

	var rowsDeleted int
	var deleteCatalog *HostCatalog
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			deleteCatalog = c.clone()
			var err error
			rowsDeleted, err = w.Delete(
				ctx,
				deleteCatalog,
				db.WithOplog(oplogWrapper, metadata),
			)
			if err == nil && rowsDeleted > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)

	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete: static host catalog: %s: %w", c.PublicId, err)
	}

	return rowsDeleted, nil
}
