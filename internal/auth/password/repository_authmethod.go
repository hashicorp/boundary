package password

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
)

// CreateAuthMethod inserts m into the repository and returns a new
// AuthMethod containing the auth method's PublicId. m is not changed. m must
// contain a valid ScopeId. m must not contain a PublicId. The PublicId is
// generated and assigned by this method.
//
// WithConfiguration is the only valid option. All other options are
// ignored.
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

	opts := getOpts(opt...)
	c, ok := opts.withConfig.(*Argon2Configuration)
	if !ok {
		return nil, fmt.Errorf("create: password auth method: unknown configuration: %w", ErrUnsupportedConfiguration)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("create: password auth method: %w", err)
	}

	c.PrivateId, err = newArgon2ConfigurationId()
	if err != nil {
		return nil, fmt.Errorf("create: password auth method: %w", err)
	}
	m.PasswordConfId, c.PasswordMethodId = c.PrivateId, m.PublicId

	var newAuthMethod *AuthMethod
	var newArgon2Conf *Argon2Configuration
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newArgon2Conf = c.clone()
			if err := w.Create(ctx, newArgon2Conf, db.WithOplog(r.wrapper, c.oplog(oplog.OpType_OP_TYPE_CREATE))); err != nil {
				return err
			}
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

// LookupAuthMethod will look up an auth method in the repository.  If the auth method is not
// found, it will return nil, nil.  All options are ignored.
func (r *Repository) LookupAuthMethod(ctx context.Context, withPublicId string, opt ...Option) (*AuthMethod, error) {
	if withPublicId == "" {
		return nil, fmt.Errorf("lookup: password auth method: missing public id %w", db.ErrInvalidParameter)
	}
	a := allocAuthMethod()
	a.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &a); err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("lookup: password auth method: failed %w for %s", err, withPublicId)
	}
	return &a, nil
}

// ListAuthMethods returns a slice of AuthMethods for the scopeId. WithLimit is the only option supported.
func (r *Repository) ListAuthMethods(ctx context.Context, withScopeId string, opt ...Option) ([]*AuthMethod, error) {
	if withScopeId == "" {
		return nil, fmt.Errorf("list: password auth method: missing scope id: %w", db.ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var authMethods []*AuthMethod
	err := r.reader.SearchWhere(ctx, &authMethods, "scope_id = ?", []interface{}{withScopeId}, db.WithLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("list: password auth method: %w", err)
	}
	return authMethods, nil
}

// DeleteAuthMethods deletes the auth method for the provided id from the repository returning a count of the
// number of records deleted.  All options are ignored.
func (r *Repository) DeleteAuthMethods(ctx context.Context, withPublicId string, opt ...Option) (int, error) {
	if withPublicId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete: password auth method: missing public id: %w", db.ErrInvalidParameter)
	}
	am := allocAuthMethod()
	am.PublicId = withPublicId

	var rowsDeleted int
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			metadata := am.oplog(oplog.OpType_OP_TYPE_DELETE)
			dAc := am.clone()
			rowsDeleted, err = w.Delete(ctx, dAc, db.WithOplog(r.wrapper, metadata))
			if err == nil && rowsDeleted > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)

	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete: password auth method: %s: %w", withPublicId, err)
	}

	return rowsDeleted, nil
}

// UpdateAuthMethod will update an auth method in the repository and return
// the written auth method.  MinPasswordLength and MinUserNameLength should
// not be set to null, but instead use the default values returned by
// NewAuthMethod.  fieldMaskPaths provides field_mask.proto paths for fields
// that should be updated.  Fields will be set to NULL if the field is a zero
// value and included in fieldMask. Name and Description are the only updatable
// fields, If no updatable fields are included in the fieldMaskPaths, then an
// error is returned.
func (r *Repository) UpdateAuthMethod(ctx context.Context, authMethod *AuthMethod, fieldMaskPaths []string, opt ...Option) (*AuthMethod, int, error) {
	if authMethod == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update: password auth method: missing authMethod %w", db.ErrNilParameter)
	}
	if authMethod.PublicId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("update: password auth method: missing authMethod public id %w", db.ErrInvalidParameter)
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("name", f):
		case strings.EqualFold("description", f):
		case strings.EqualFold("MinUserNameLength", f):
		case strings.EqualFold("MinPasswordLength", f):
		default:
			return nil, db.NoRowsAffected, fmt.Errorf("update: password auth method: field: %s: %w", f, db.ErrInvalidFieldMask)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = buildUpdatePaths(
		map[string]interface{}{
			"Name":              authMethod.Name,
			"Description":       authMethod.Description,
			"MinPasswordLength": authMethod.MinPasswordLength,
			"MinUserNameLength": authMethod.MinUserNameLength,
		},
		fieldMaskPaths,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("update: password auth method: %w", db.ErrEmptyFieldMask)
	}

	upAuthMethod := authMethod.clone()
	var rowsUpdated int
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			dbOpts := []db.Option{db.WithOplog(r.wrapper, upAuthMethod.oplog(oplog.OpType_OP_TYPE_UPDATE))}
			var err error
			rowsUpdated, err = w.Update(
				ctx,
				upAuthMethod,
				dbMask,
				nullFields,
				dbOpts...,
			)
			if err == nil && rowsUpdated > 1 {
				// return err, which will result in a rollback of the update
				return errors.New("error more than 1 resource would have been updated ")
			}
			return err
		},
	)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, db.NoRowsAffected, fmt.Errorf("update: password auth method: authMethod %s already exists in scope %s", authMethod.Name, authMethod.ScopeId)
		}
		return nil, db.NoRowsAffected, fmt.Errorf("update: password auth method: %w for %s", err, authMethod.PublicId)
	}
	return upAuthMethod, rowsUpdated, err
}
