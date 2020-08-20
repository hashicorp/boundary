package static

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
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
