package password

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
)

// CreateAuthMethod inserts m into the repository and returns a new
// AuthMethod containing the auth method's PublicId. m is not changed. m must
// contain a valid ScopeId. m must not contain a PublicId. The PublicId is
// generated and assigned by this method. opt is ignored.
//
// Both m.Name and m.Description are optional. If m.Name is set, it must be
// unique within m.ScopeId.
//
// Both m.CreateTime and m.UpdateTime are ignored.
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

	c, err := NewArgon2Configuration(id)
	if err != nil {
		return nil, fmt.Errorf("create: password auth method: %w", err)
	}
	m.PasswordConfId = c.PublicId

	mMetaData := newAuthMethodMetadata(m, oplog.OpType_OP_TYPE_CREATE)
	cMetaData := newArgon2ConfMetadata(c, oplog.OpType_OP_TYPE_CREATE)

	var newAuthMethod *AuthMethod
	var newArgon2Conf *Argon2Configuration
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newArgon2Conf = c.clone()
			if err := w.Create(ctx, newArgon2Conf, db.WithOplog(r.wrapper, cMetaData)); err != nil {
				return err
			}
			newAuthMethod = m.clone()
			return w.Create(ctx, newAuthMethod, db.WithOplog(r.wrapper, mMetaData))
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

func allocAuthMethod() *AuthMethod {
	fresh := &AuthMethod{
		AuthMethod: &store.AuthMethod{},
	}
	return fresh
}

func newAuthMethodMetadata(m *AuthMethod, op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{m.GetPublicId()},
		"resource-type":      []string{"password auth method"},
		"op-type":            []string{op.String()},
	}
	if m.ScopeId != "" {
		metadata["scope-id"] = []string{m.ScopeId}
	}
	return metadata
}

func newArgon2ConfMetadata(c *Argon2Configuration, op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.GetPublicId()},
		"resource-type":      []string{"password argon2 conf"},
		"op-type":            []string{op.String()},
	}
	if c.AuthPasswordMethodId != "" {
		metadata["auth-password-method-id"] = []string{c.AuthPasswordMethodId}
	}
	return metadata
}
