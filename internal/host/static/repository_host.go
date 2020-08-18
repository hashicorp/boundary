package static

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
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
