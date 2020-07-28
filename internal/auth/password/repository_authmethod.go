package password

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
)

// CreateAuthMethod inserts m into the repository and returns a new
// AuthMethod containing the auth method's PublicId. m is not changed. m must
// contain a valid ScopeId. m must not contain a PublicId. The PublicId is
// generated and assigned by this method.
//
// Both m.Name and m.Description are optional. If m.Name is set, it must be
// unique within m.ScopeId.
func (r *Repository) CreateAuthMethod(ctx context.Context, m *AuthMethod, opt ...Option) (*AuthMethod, error) {
	if m == nil {
		return nil, fmt.Errorf("create: password auth method: %w", db.ErrNilParameter)
	}
	if m.AuthMethod == nil {
		return nil, fmt.Errorf("create: password auth method: embedded AuthMethod: %w", db.ErrNilParameter)
	}
	if m.ScopeId == "" {
		return nil, fmt.Errorf("create: password auth method: no scope id: %w", db.ErrInvalidParameter)
	}
	if m.PublicId != "" {
		return nil, fmt.Errorf("create: password auth method: public id not empty: %w", db.ErrInvalidParameter)
	}
	m = m.clone()

	id, err := newAuthMethodId()
	if err != nil {
		return nil, fmt.Errorf("create: password auth method: %w", err)
	}
	m.PublicId = id

	var newAuthMethod *AuthMethod
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newAuthMethod = m.clone()
			return w.Create(ctx, newAuthMethod, db.WithOplog(r.wrapper, m.oplog(oplog.OpType_OP_TYPE_CREATE)))
		},
	)

	if err != nil {
		if db.IsUniqueError(err) {
			return nil, fmt.Errorf("create: password auth method: in scope: %s: name %s already exists: %w",
				m.ScopeId, m.Name, db.ErrNotUnique)
		}
		return nil, fmt.Errorf("create: password auth method: in scope: %s: %w", m.ScopeId, err)
	}
	return newAuthMethod, nil
}
