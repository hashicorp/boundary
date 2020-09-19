package password

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// CreateAuthMethod inserts m into the repository and returns a new
// AuthMethod containing the auth method's PublicId. m is not changed. m must
// contain a valid ScopeId. m must not contain a PublicId. The PublicId is
// generated and assigned by this method.
//
// WithConfiguration and WithPublicId are the only valid options. All other
// options are ignored.
//
// Both m.Name and m.Description are optional. If m.Name is set, it must be
// unique within m.ScopeId.
func (r *Repository) CreateAuthMethod(ctx context.Context, m *AuthMethod, opt ...Option) (*AuthMethod, error) {
	if m == nil {
		return nil, fmt.Errorf("create: password auth method: %w", db.ErrInvalidParameter)
	}
	if m.AuthMethod == nil {
		return nil, fmt.Errorf("create: password auth method: embedded AuthMethod: %w", db.ErrInvalidParameter)
	}
	if m.ScopeId == "" {
		return nil, fmt.Errorf("create: password auth method: no scope id: %w", db.ErrInvalidParameter)
	}
	if m.PublicId != "" {
		return nil, fmt.Errorf("create: password auth method: public id not empty: %w", db.ErrInvalidParameter)
	}
	m = m.clone()

	opts := getOpts(opt...)

	if opts.withPublicId != "" {
		if !strings.HasPrefix(opts.withPublicId, AuthMethodPrefix+"_") {
			return nil, fmt.Errorf("create: password auth method: passed-in public ID %q has wrong prefix, should be %q: %w", opts.withPublicId, AuthMethodPrefix, db.ErrInvalidPublicId)
		}
		m.PublicId = opts.withPublicId
	} else {
		id, err := newAuthMethodId()
		if err != nil {
			return nil, fmt.Errorf("create: password auth method: %w", err)
		}
		m.PublicId = id
	}

	c, ok := opts.withConfig.(*Argon2Configuration)
	if !ok {
		return nil, fmt.Errorf("create: password auth method: unknown configuration: %w", ErrUnsupportedConfiguration)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("create: password auth method: %w", err)
	}

	var err error
	c.PrivateId, err = newArgon2ConfigurationId()
	if err != nil {
		return nil, fmt.Errorf("create: password auth method: %w", err)
	}
	m.PasswordConfId, c.PasswordMethodId = c.PrivateId, m.PublicId

	oplogWrapper, err := r.kms.GetWrapper(ctx, m.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, fmt.Errorf("create: password auth method: unable to get oplog wrapper: %w", err)
	}

	var newAuthMethod *AuthMethod
	var newArgon2Conf *Argon2Configuration
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newArgon2Conf = c.clone()
			if err := w.Create(ctx, newArgon2Conf, db.WithOplog(oplogWrapper, c.oplog(oplog.OpType_OP_TYPE_CREATE))); err != nil {
				return err
			}
			newAuthMethod = m.clone()
			return w.Create(ctx, newAuthMethod, db.WithOplog(oplogWrapper, m.oplog(oplog.OpType_OP_TYPE_CREATE)))
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
func (r *Repository) LookupAuthMethod(ctx context.Context, publicId string, opt ...Option) (*AuthMethod, error) {
	if publicId == "" {
		return nil, fmt.Errorf("lookup: password auth method: missing public id %w", db.ErrInvalidParameter)
	}
	a := allocAuthMethod()
	a.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, &a); err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("lookup: password auth method: failed %w for %s", err, publicId)
	}
	return &a, nil
}

// ListAuthMethods returns a slice of AuthMethods for the scopeId. WithLimit is the only option supported.
func (r *Repository) ListAuthMethods(ctx context.Context, scopeId string, opt ...Option) ([]*AuthMethod, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("list: password auth method: missing scope id: %w", db.ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var authMethods []*AuthMethod
	err := r.reader.SearchWhere(ctx, &authMethods, "scope_id = ?", []interface{}{scopeId}, db.WithLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("list: password auth method: %w", err)
	}
	return authMethods, nil
}

// DeleteAuthMethod deletes the auth method for the provided id from the repository returning a count of the
// number of records deleted.  All options are ignored.
func (r *Repository) DeleteAuthMethod(ctx context.Context, scopeId, publicId string, opt ...Option) (int, error) {
	if publicId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete: password auth method: missing public id: %w", db.ErrInvalidParameter)
	}
	am := allocAuthMethod()
	am.PublicId = publicId

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete: password auth method: unable to get oplog wrapper: %w", err)
	}

	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			metadata := am.oplog(oplog.OpType_OP_TYPE_DELETE)
			dAc := am.clone()
			rowsDeleted, err = w.Delete(ctx, dAc, db.WithOplog(oplogWrapper, metadata))
			if err == nil && rowsDeleted > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)

	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete: password auth method: %s: %w", publicId, err)
	}

	return rowsDeleted, nil
}

// TODO: Fix the MinPasswordLength and MinLoginNameLength update path so they dont have
//  to rely on the response of NewAuthMethod but instead can be unset in order to be
//  set to the default values.

// UpdateAuthMethod will update an auth method in the repository and return
// the written auth method.  MinPasswordLength and MinLoginNameLength should
// not be set to null, but instead use the default values returned by
// NewAuthMethod.  fieldMaskPaths provides field_mask.proto paths for fields
// that should be updated.  Fields will be set to NULL if the field is a zero
// value and included in fieldMask. Name, Description, MinPasswordLength,
// and MinLoginNameLength are the only updatable fields, If no updatable fields
// are included in the fieldMaskPaths, then an error is returned.
func (r *Repository) UpdateAuthMethod(ctx context.Context, authMethod *AuthMethod, version uint32, fieldMaskPaths []string, opt ...Option) (*AuthMethod, int, error) {
	if authMethod == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update: password auth method: missing authMethod: %w", db.ErrInvalidParameter)
	}
	if authMethod.PublicId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("update: password auth method: missing authMethod public id: %w", db.ErrInvalidParameter)
	}
	if authMethod.ScopeId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("update: password auth method: scope id empty: %w", db.ErrInvalidParameter)
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("name", f):
		case strings.EqualFold("description", f):
		case strings.EqualFold("MinLoginNameLength", f):
		case strings.EqualFold("MinPasswordLength", f):
		default:
			return nil, db.NoRowsAffected, fmt.Errorf("update: password auth method: field: %s: %w", f, db.ErrInvalidFieldMask)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"Name":               authMethod.Name,
			"Description":        authMethod.Description,
			"MinPasswordLength":  authMethod.MinPasswordLength,
			"MinLoginNameLength": authMethod.MinLoginNameLength,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("update: password auth method: %w", db.ErrEmptyFieldMask)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, authMethod.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update: password auth method: unable to get oplog wrapper: %w", err)
	}

	upAuthMethod := authMethod.clone()
	var rowsUpdated int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			dbOpts := []db.Option{
				db.WithOplog(oplogWrapper, upAuthMethod.oplog(oplog.OpType_OP_TYPE_UPDATE)),
				db.WithVersion(&version),
			}
			var err error
			rowsUpdated, err = w.Update(
				ctx,
				upAuthMethod,
				dbMask,
				nullFields,
				dbOpts...,
			)
			if err == nil && rowsUpdated > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, db.NoRowsAffected, fmt.Errorf("update: password auth method: authMethod %s already exists in scope %s: %w", authMethod.Name, authMethod.ScopeId, db.ErrNotUnique)
		}
		return nil, db.NoRowsAffected, fmt.Errorf("update: password auth method: %w for %s", err, authMethod.PublicId)
	}
	return upAuthMethod, rowsUpdated, err
}
