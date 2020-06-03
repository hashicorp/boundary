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
// package. It is not safe to use a repository concurrently.
type Repository struct {
	reader  db.Reader
	writer  db.Writer
	wrapper wrapping.Wrapper
}

// NewRepository creates a new Repository. The returned repository should
// only be used for one transaction and it is not safe for concurrent go
// routines to access it.
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
// contain a valid ScopeId. c must not contain a PublicId. The PublicId is
// generated and assigned by this method. opt is ignored.
//
// Both c.Name and c.Description are optional. If c.Name is set, it must be
// unique within c.ScopeId.
//
// Both c.CreateTime and c.UpdateTime are ignored.
func (r *Repository) CreateCatalog(ctx context.Context, c *HostCatalog, opt ...Option) (*HostCatalog, error) {
	if c == nil {
		return nil, fmt.Errorf("create: static host catalog: %w", db.ErrNilParameter)
	}
	if c.HostCatalog == nil {
		return nil, fmt.Errorf("create: static host catalog: embedded HostCatalog: %w", db.ErrNilParameter)
	}
	if c.ScopeId == "" {
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
// within c.ScopeId.
//
// An attribute of c will be set to NULL in the database if the attribute
// in c is the zero value and it is included in fieldMask.
func (r *Repository) UpdateCatalog(ctx context.Context, c *HostCatalog, fieldMask []string, opt ...Option) (*HostCatalog, int, error) {
	if c == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host catalog: %w", db.ErrNilParameter)
	}
	if c.HostCatalog == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host catalog: embedded HostCatalog: %w", db.ErrNilParameter)
	}
	if c.PublicId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("update: static host catalog: missing public id: %w", db.ErrInvalidParameter)
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
	c = c.clone()

	metadata := newCatalogMetadata(c, oplog.OpType_OP_TYPE_UPDATE)

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
				nullFields,
				db.WithOplog(r.wrapper, metadata),
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

// DeleteCatalog deletes id from the repository returning a count of the
// number of records deleted.
func (r *Repository) DeleteCatalog(ctx context.Context, id string, opt ...Option) (int, error) {
	if id == "" {
		return db.NoRowsAffected, fmt.Errorf("delete: static host catalog: missing public id: %w", db.ErrInvalidParameter)
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
		return db.NoRowsAffected, fmt.Errorf("delete: static host catalog: %s: %w", c.PublicId, err)
	}

	return rowsDeleted, nil
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

// CreateHost inserts h into the repository and returns a new Host
// containing the host's PublicId. h is not changed. h must contain a valid
// StaticHostCatalogId. h must not contain a PublicId. The PublicId is
// generated and assigned by this method. opt is ignored.
//
// h.Address must contain a string where 7 < len(h.Address) < 256. Both
// h.Name and h.Description are optional. If h.Name is set, it must be
// unique within h.StaticHostCatalogId. There are no unique constraints on
// the Address of a host.
//
// Both h.CreateTime and h.UpdateTime are ignored.
func (r *Repository) CreateHost(ctx context.Context, h *Host, opt ...Option) (*Host, error) {
	if h == nil {
		return nil, fmt.Errorf("create: static host: %w", db.ErrNilParameter)
	}
	if h.Host == nil {
		return nil, fmt.Errorf("create: static host: embedded Host: %w", db.ErrNilParameter)
	}
	if h.StaticHostCatalogId == "" {
		return nil, fmt.Errorf("create: static host: no host catalog id: %w", db.ErrInvalidParameter)
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

	metadata := newHostMetadata(h, oplog.OpType_OP_TYPE_CREATE)

	var newHost *Host
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(w db.Writer) error {
			newHost = h.clone()
			return w.Create(
				ctx,
				newHost,
				db.WithOplog(r.wrapper, metadata),
			)
		},
	)

	if err != nil {
		if db.IsUniqueError(err) {
			return nil, fmt.Errorf("create: static host: in catalog: %s: name %s already exists: %w",
				h.StaticHostCatalogId, h.Name, db.ErrNotUnique)
		}
		if db.IsCheckConstraintError(err) {
			return nil, fmt.Errorf("create: static host: in catalog: %s: address %s: %w",
				h.StaticHostCatalogId, h.Address, db.ErrInvalidParameter)
		}
		return nil, fmt.Errorf("create: static host: in catalog: %s: %w", h.StaticHostCatalogId, err)
	}
	return newHost, nil
}

func newHostMetadata(h *Host, op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{h.GetPublicId()},
		"resource-type":      []string{"static host"},
		"op-type":            []string{op.String()},
	}
	if h.StaticHostCatalogId != "" {
		metadata["static-host-catalog-id"] = []string{h.StaticHostCatalogId}
	}
	return metadata
}

// UpdateHost updates the repository entry for h.PublicId with the values
// in h for the fields listed in fieldMask. It returns a new Host
// containing the updated values and a count of the number of records
// updated. h is not changed.
//
// h must contain a valid PublicId. Only h.Name, h.Description, and
// h.Address can be updated. If h.Name is set to a non-empty string, it
// must be unique within h.StaticHostCatalogId. h.Address must contain a
// string where 6 < len(h.Address) < 256.
//
// An attribute of h will be set to NULL in the database if the attribute
// in h is the zero value and it is included in fieldMask.
func (r *Repository) UpdateHost(ctx context.Context, h *Host, fieldMask []string, opt ...Option) (*Host, int, error) {
	return nil, 0, nil
}

// DeleteHost deletes id from the repository returning a count of the
// number of records deleted.
func (r *Repository) DeleteHost(ctx context.Context, id string, opt ...Option) (int, error) {
	return 0, nil
}

// LookupHost returns the host for id. Returns nil, nil if no host is found
// for id.
func (r *Repository) LookupHost(ctx context.Context, id string) (*Host, error) {
	return nil, nil
}

// GetHosts retrieves all hosts for c and returns them in a slice. Returns
// nil, nil if no hosts are found for c.
func (r *Repository) GetHosts(ctx context.Context, c *HostCatalog) ([]*Host, error) {
	return nil, nil
}
