package static

import (
	"context"
	"fmt"
	"strings"

	wrapping "github.com/hashicorp/go-kms-wrapping"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/host/static/store"
	"github.com/hashicorp/watchtower/internal/oplog"
)

// A Repository stores and retrieves the persistent types in the static
// package.
type Repository struct {
	reader  db.Reader
	writer  db.Writer
	wrapper wrapping.Wrapper
}

// NewRepository creates a new Repository.
func NewRepository(r db.Reader, w db.Writer, wrapper wrapping.Wrapper) (*Repository, error) {
	switch {
	case r == nil:
		return nil, fmt.Errorf("db.Reader: %w", db.ErrNilParameter)
	case w == nil:
		return nil, fmt.Errorf("db.Writer: %w", db.ErrNilParameter)
	case wrapper == nil:
		return nil, fmt.Errorf("wrapping.Wrapper: %w", db.ErrNilParameter)
	}

	return &Repository{
		reader:  r,
		writer:  w,
		wrapper: wrapper,
	}, nil
}

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
		return nil, fmt.Errorf("create: static host catalog: %w", db.ErrNilParameter)
	}
	if c.HostCatalog.ScopeId == "" {
		return nil, fmt.Errorf("create: static host catalog: no scope id: %w", db.ErrInvalidParameter)
	}
	if c.PublicId != "" {
		return nil, fmt.Errorf("create: static host catalog: public id not empty: %w", db.ErrInvalidParameter)
	}
	c = c.clone()

	id, err := newHostCatalogId()
	if err != nil {
		return nil, fmt.Errorf("create: static host catalog: %w", err)
	}
	c.PublicId = id

	metadata := newCatalogMetadata(c, oplog.OpType_OP_TYPE_CREATE)

	var newHostCatalog *HostCatalog
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(w db.Writer) error {
			newHostCatalog = c.clone()
			return w.Create(
				ctx,
				newHostCatalog,
				db.WithOplog(r.wrapper, metadata),
			)
		},
	)

	if err != nil {
		if db.IsUnique(err) {
			return nil, fmt.Errorf("create: static host catalog: in scope: %s: name %s already exists: %w",
				c.ScopeId, c.Name, db.ErrNotUnique)
		}
		return nil, fmt.Errorf("create: static host catalog: in scope: %s: %w", c.ScopeId, err)
	}
	return newHostCatalog, nil
}

// UpdateCatalog updates the values in the repository with the values in c
// for c.PublicId and returns a new HostCatalog containing the updated
// values. c is not changed. c must contain a valid PublicId.
//
// Only c.Name and c.Description can be updated. All other values are
// ignored. If c.Name is set, it must be unique within c.ScopeID.
//
// An attributed of c will be set to NULL in the database if the attribute
// in c is the zero value and it is included in fieldMask.
//
// Both c.CreateTime and c.UpdateTime are ignored.
func (r *Repository) UpdateCatalog(ctx context.Context, c *HostCatalog, fieldMask []string, opt ...Option) (*HostCatalog, error) {
	if c == nil {
		return nil, fmt.Errorf("update: static host catalog: %w", db.ErrNilParameter)
	}
	if c.PublicId == "" {
		return nil, fmt.Errorf("update: static host catalog: missing public id: %w", db.ErrInvalidParameter)
	}
	c = c.clone()

	metadata := newCatalogMetadata(c, oplog.OpType_OP_TYPE_UPDATE)

	var dbMask, nullFields []string
	empty := len(fieldMask) == 0

	switch {
	case c.Name == "" && contains(fieldMask, "name"):
		nullFields = append(nullFields, "name")
	case c.Name != "" && (empty || contains(fieldMask, "name")):
		dbMask = append(dbMask, "name")
	}

	switch {
	case c.Description == "" && contains(fieldMask, "description"):
		nullFields = append(nullFields, "description")
	case c.Description != "" && (empty || contains(fieldMask, "description")):
		dbMask = append(dbMask, "description")
	}

	// Nothing to update. The caller may have changed attributes which are
	// not allowed to be updated so return a fresh copy.
	if len(dbMask) == 0 {
		fresh := allocCatalog()
		fresh.PublicId = c.PublicId
		if err := r.reader.LookupByPublicId(ctx, fresh); err != nil {
			if err == db.ErrRecordNotFound {
				return nil, fmt.Errorf("update: static host catalog: %s: %w", fresh.PublicId, db.ErrInvalidPublicId)
			}
			return nil, fmt.Errorf("update: static host catalog: %s: %w", fresh.PublicId, err)
		}
		return fresh, nil
	}

	// TODO(mgaffney,jimlambrt) 05/2020: uncomment the nullFields line
	// below once support for setting columns to nil is added to db.Update.
	var rowsUpdated int
	var returnedCatalog *HostCatalog
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(w db.Writer) error {
			returnedCatalog = c.clone()
			var err error
			rowsUpdated, err = w.Update(
				ctx,
				returnedCatalog,
				dbMask,
				// nullFields,
				db.WithOplog(r.wrapper, metadata),
			)
			if err == nil && rowsUpdated > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)

	if err != nil {
		if db.IsUnique(err) {
			return nil, fmt.Errorf("update: static host catalog: %s: name %s already exists: %w",
				c.PublicId, c.Name, db.ErrNotUnique)
		}
		return nil, fmt.Errorf("update: static host catalog: %s: %w", c.PublicId, err)
	}

	return returnedCatalog, nil
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

// DeleteCatalog deletes id from the repository returning a boolean to
// indicate if the id existed.
func (r *Repository) DeleteCatalog(ctx context.Context, id string, opt ...Option) (bool, error) {
	if id == "" {
		return false, fmt.Errorf("delete: static host catalog: missing public id: %w", db.ErrInvalidParameter)
	}

	c := allocCatalog()
	c.PublicId = id

	metadata := newCatalogMetadata(c, oplog.OpType_OP_TYPE_DELETE)

	var rowsDeleted int
	var deleteCatalog *HostCatalog
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(w db.Writer) error {
			deleteCatalog = c.clone()
			var err error
			rowsDeleted, err = w.Delete(
				ctx,
				deleteCatalog,
				db.WithOplog(r.wrapper, metadata),
			)
			if err == nil && rowsDeleted > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)

	if err != nil {
		return false, fmt.Errorf("delete: static host catalog: %s: %w", c.PublicId, err)
	}

	return rowsDeleted != 0, nil
}

func contains(ss []string, t string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, t) {
			return true
		}
	}
	return false
}

func allocCatalog() *HostCatalog {
	fresh := &HostCatalog{
		HostCatalog: &store.HostCatalog{},
	}
	return fresh
}

func newCatalogMetadata(c *HostCatalog, op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.GetPublicId()},
		"resource-type":      []string{"static host catalog"},
		"op-type":            []string{op.String()},
	}
	if c.ScopeId != "" {
		metadata["scope-id"] = []string{c.ScopeId}
	}
	return metadata
}
