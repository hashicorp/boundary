package static

import (
	"context"
	"errors"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/lib/pq"
)

// Errors returned from this package may be tested against these errors
// with errors.Is.
var (
	// ErrInvalidPublicId indicates an invalid PublicId.
	ErrInvalidPublicId = errors.New("invalid publicId")

	// ErrInvalidParameter is returned by create and update methods if
	// an attribute on a struct contains illegal or invalid values.
	ErrInvalidParameter = errors.New("invalid parameter")

	// ErrNotUnique is returned by create and update methods when a write
	// to the repository resulted in a unique constraint violation.
	ErrNotUnique = errors.New("unique constraint violation")

	// ErrNilParameter is returned when a required parameter is nil.
	ErrNilParameter = errors.New("nil parameter")
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
		return nil, fmt.Errorf("db.Reader: %w", ErrNilParameter)
	case w == nil:
		return nil, fmt.Errorf("db.Writer: %w", ErrNilParameter)
	case wrapper == nil:
		return nil, fmt.Errorf("wrapping.Wrapper: %w", ErrNilParameter)
	}

	return &Repository{
		reader:  r,
		writer:  w,
		wrapper: wrapper,
	}, nil
}

// CreateCatalog inserts c into the repository and returns a new
// HostCatalog containing the catalog's PublicId. c must contain a valid
// ScopeID. c must not contain a PublicId. The PublicId is generated and
// assigned by the this method. opt is ignored.
//
// Both c.Name and c.Description are optional. If c.Name is set, it must be
// unique within c.ScopeID.
//
// Both c.CreateTime and c.UpdateTime are ignored.
func (r *Repository) CreateCatalog(ctx context.Context, c *HostCatalog, opt ...Option) (*HostCatalog, error) {
	if c == nil {
		return nil, fmt.Errorf("create: host catalog: %w", ErrNilParameter)
	}
	if c.HostCatalog.ScopeId == "" {
		return nil, fmt.Errorf("create: host catalog: no scope id: %w", ErrInvalidParameter)
	}
	if c.PublicId != "" {
		return nil, fmt.Errorf("create: host catalog: public id not empty: %w", ErrInvalidParameter)
	}
	id, err := newHostCatalogId()
	if err != nil {
		return nil, err
	}
	c.PublicId = id

	metadata := oplog.Metadata{
		"resource-public-id": []string{c.GetPublicId()},
		"scope-id":           []string{c.ScopeId},
		"resource-type":      []string{"static host catalog"},
		"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
	}

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
		// TODO(mgaffney): extract database specific error handing
		var e *pq.Error
		if errors.As(err, &e) {
			if e.Code.Name() == "unique_violation" {
				return nil, fmt.Errorf("%w: static host catalog: %s in scope: %s already exists",
					ErrNotUnique, c.Name, c.ScopeId)
			}
		}
		return nil, err
	}
	return newHostCatalog, nil
}

// UpdateCatalog updates the values in the repository with the values in c
// for c.PublicId and returns a new HostCatalog containing the updated
// values. c must contain a valid PublicId.
//
// Only c.Name and c.Description can be updated. All other values are
// ignored. If c.Name is set, it must be unique within c.ScopeID.
//
// Both c.CreateTime and c.UpdateTime are ignored.
func (r *Repository) UpdateCatalog(ctx context.Context, c *HostCatalog, fieldMask []string, opt ...Option) (*HostCatalog, error) {
	// TODO(mgaffney): implement method
	return nil, nil
}

// LookupCatalog returns the HostCatalog for id.
func (r *Repository) LookupCatalog(ctx context.Context, id string, opt ...Option) (*HostCatalog, error) {
	// TODO(mgaffney): implement method
	return nil, nil
}

// DeleteCatalog deletes the HostCatalog for id and returns 1 if the
// catalog was deleted or 0 if no host catalog was deleted.
func (r *Repository) DeleteCatalog(ctx context.Context, id string, opt ...Option) (int, error) {
	// TODO(mgaffney): implement method
	return 0, nil
}
