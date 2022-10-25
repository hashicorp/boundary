package password

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-dbw"
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
	const op = "password.(Repository).CreateAuthMethod"
	if m == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing AuthMethod")
	}
	if m.AuthMethod == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing embedded AuthMethod")
	}
	if m.ScopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if m.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}
	m = m.Clone()

	opts := GetOpts(opt...)

	if opts.withPublicId != "" {
		if !strings.HasPrefix(opts.withPublicId, AuthMethodPrefix+"_") {
			return nil, errors.New(ctx, errors.InvalidPublicId, op, fmt.Sprintf("passed-in public ID %q has wrong prefix, should be %q", opts.withPublicId, AuthMethodPrefix))
		}
		m.PublicId = opts.withPublicId
	} else {
		id, err := newAuthMethodId()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		m.PublicId = id
	}

	c, ok := opts.withConfig.(*Argon2Configuration)
	if !ok {
		return nil, errors.New(ctx, errors.PasswordUnsupportedConfiguration, op, "unknown configuration")
	}
	if err := c.validate(); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var err error
	c.PrivateId, err = newArgon2ConfigurationId()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	m.PasswordConfId, c.PasswordMethodId = c.PrivateId, m.PublicId

	oplogWrapper, err := r.kms.GetWrapper(ctx, m.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("unable to get oplog wrapper"))
	}

	var newAuthMethod *AuthMethod
	var newArgon2Conf *Argon2Configuration
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newArgon2Conf = c.clone()
			if err := w.Create(ctx, newArgon2Conf, db.WithOplog(oplogWrapper, c.oplog(oplog.OpType_OP_TYPE_CREATE))); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create argon conf"))
			}
			newAuthMethod = m.Clone()
			if err := w.Create(ctx, newAuthMethod, db.WithOplog(oplogWrapper, m.oplog(oplog.OpType_OP_TYPE_CREATE))); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create auth method"))
			}
			return nil
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("in scope: %s: name %s already exists", m.ScopeId, m.Name))
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(m.ScopeId))
	}
	return newAuthMethod, nil
}

// LookupAuthMethod will look up an auth method in the repository.  If the auth method is not
// found, it will return nil, nil.  All options are ignored.
func (r *Repository) LookupAuthMethod(ctx context.Context, publicId string, _ ...Option) (*AuthMethod, error) {
	const op = "password.(Repository).LookupAuthMethod"
	if publicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	return r.lookupAuthMethod(ctx, publicId)
}

// ListAuthMethods returns a slice of AuthMethods for the scopeId. WithLimit and
// WithOrder options are the only option supported.
func (r *Repository) ListAuthMethods(ctx context.Context, scopeIds []string, opt ...Option) ([]*AuthMethod, error) {
	const op = "password.(Repository).ListAuthMethods"
	if len(scopeIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	authMethods, err := r.getAuthMethods(ctx, "", scopeIds, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return authMethods, nil
}

// DeleteAuthMethod deletes the auth method for the provided id from the repository returning a count of the
// number of records deleted.  All options are ignored.
func (r *Repository) DeleteAuthMethod(ctx context.Context, scopeId, publicId string, opt ...Option) (int, error) {
	const op = "password.(Repository).DeleteAuthMethod"
	if publicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	am := allocAuthMethod()
	am.PublicId = publicId

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt),
			errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			metadata := am.oplog(oplog.OpType_OP_TYPE_DELETE)
			dAc := am.Clone()
			rowsDeleted, err = w.Delete(ctx, dAc, db.WithOplog(oplogWrapper, metadata))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsDeleted > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been deleted")
			}
			return nil
		},
	)

	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(publicId))
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
	const op = "password.(Repository).UpdateAuthMethod"
	if authMethod == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing authMethod")
	}
	if authMethod.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing authMethod public id")
	}
	if authMethod.ScopeId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("Name", f):
		case strings.EqualFold("Description", f):
		case strings.EqualFold("MinLoginNameLength", f):
		case strings.EqualFold("MinPasswordLength", f):
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, f)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbw.BuildUpdatePaths(
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
		return nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "field mask must not be empty")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, authMethod.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt),
			errors.WithMsg("unable to get oplog wrapper"))
	}

	upAuthMethod := authMethod.Clone()
	var rowsUpdated int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
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
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsUpdated > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been updated")
			}
			// we need a new repo, that's using the same reader/writer as this TxHandler
			txRepo := &Repository{
				reader: reader,
				writer: w,
				kms:    r.kms,
				// intentionally not setting the defaultLimit, so we'll get all
				// the account ids without a limit
			}
			upAuthMethod, err = txRepo.lookupAuthMethod(ctx, upAuthMethod.PublicId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to lookup auth method after update"))
			}
			if upAuthMethod == nil {
				return errors.New(ctx, errors.RecordNotFound, op, "unable to lookup auth method after update")
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, db.NoRowsAffected, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("authMethod %s already exists in scope %s", authMethod.Name, authMethod.ScopeId))
		}
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(authMethod.PublicId))
	}
	return upAuthMethod, rowsUpdated, nil
}

// lookupAuthMethod will lookup a single auth method
func (r *Repository) lookupAuthMethod(ctx context.Context, authMethodId string, opt ...Option) (*AuthMethod, error) {
	const op = "oidc.(Repository).lookupAuthMethod"
	var err error
	ams, err := r.getAuthMethods(ctx, authMethodId, nil, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	switch {
	case len(ams) == 0:
		return nil, nil // not an error to return no rows for a "lookup"
	case len(ams) > 1:
		return nil, errors.New(ctx, errors.NotSpecificIntegrity, op, fmt.Sprintf("%s matched more than 1 ", authMethodId))
	default:
		return ams[0], nil
	}
}

// getAuthMethods allows the caller to either lookup a specific AuthMethod via
// its id or search for a set AuthMethods within a set of scopes.  Passing both
// scopeIds and a authMethodId is an error. The WithLimit and
// WithOrderByCreateTime options are supported and all other options are
// ignored.
//
// The AuthMethod returned has its IsPrimaryAuthMethod bool set.
//
// When no record is found it returns nil, nil
func (r *Repository) getAuthMethods(ctx context.Context, authMethodId string, scopeIds []string, opt ...Option) ([]*AuthMethod, error) {
	const op = "password.(Repository).getAuthMethods"
	if authMethodId == "" && len(scopeIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing search criteria: both auth method id and Scope IDs are empty")
	}
	if authMethodId != "" && len(scopeIds) > 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "searching for both an auth method id and Scope IDs is not supported")
	}

	dbArgs := []db.Option{}
	opts := GetOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	dbArgs = append(dbArgs, db.WithLimit(limit))

	if opts.withOrderByCreateTime {
		if opts.ascending {
			dbArgs = append(dbArgs, db.WithOrder("create_time asc"))
		} else {
			dbArgs = append(dbArgs, db.WithOrder("create_time"))
		}
	}

	var args []interface{}
	var where []string
	switch {
	case authMethodId != "":
		where, args = append(where, "public_id = ?"), append(args, authMethodId)
	default:
		where, args = append(where, "scope_id in(?)"), append(args, scopeIds)
	}

	var views []*authMethodView
	err := r.reader.SearchWhere(ctx, &views, strings.Join(where, " and "), args, dbArgs...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	if len(views) == 0 { // we're done if nothing is found.
		return nil, nil
	}
	authMethods := make([]*AuthMethod, 0, len(views))
	for _, am := range views {
		authMethods = append(authMethods, &AuthMethod{AuthMethod: am.AuthMethod})
	}
	return authMethods, nil
}
