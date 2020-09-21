package password

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// CreateAccount inserts a into the repository and returns a new Account
// containing the account's PublicId. a is not changed. a must contain a
// valid AuthMethodId. a must not contain a PublicId. The PublicId is
// generated and assigned by this method.
//
// a must contain a valid LoginName. a.LoginName must be unique within
// a.AuthMethodId.
//
// WithPassword is the only valid option. All other options are ignored.
//
// Both a.Name and a.Description are optional. If a.Name is set, it must be
// unique within a.AuthMethodId.
func (r *Repository) CreateAccount(ctx context.Context, scopeId string, a *Account, opt ...Option) (*Account, error) {
	if a == nil {
		return nil, fmt.Errorf("create: password account: %w", db.ErrInvalidParameter)
	}
	if a.Account == nil {
		return nil, fmt.Errorf("create: password account: embedded Account: %w", db.ErrInvalidParameter)
	}
	if a.AuthMethodId == "" {
		return nil, fmt.Errorf("create: password account: no auth method id: %w", db.ErrInvalidParameter)
	}
	if a.PublicId != "" {
		return nil, fmt.Errorf("create: password account: public id not empty: %w", db.ErrInvalidParameter)
	}
	if scopeId == "" {
		return nil, fmt.Errorf("create: password account: scope id empty: %w", db.ErrInvalidParameter)
	}
	if !validLoginName(a.LoginName) {
		return nil, fmt.Errorf("create: password account: invalid login name; must be all-lowercase alphanumeric: %w", db.ErrInvalidParameter)
	}

	cc, err := r.currentConfig(ctx, a.AuthMethodId)
	if err != nil {
		return nil, fmt.Errorf("create: password account: retrieve current configuration: %w", err)
	}

	if cc.MinLoginNameLength > len(a.LoginName) {
		return nil, fmt.Errorf("create: password account: user name %q: %w", a.LoginName, ErrTooShort)
	}

	a = a.clone()
	id, err := newAccountId()
	if err != nil {
		return nil, fmt.Errorf("create: password account: %w", err)
	}
	a.PublicId = id

	opts := getOpts(opt...)

	var cred *Argon2Credential
	if opts.withPassword {
		if cc.MinPasswordLength > len(opts.password) {
			return nil, fmt.Errorf("create: password account: password: %w", ErrTooShort)
		}
		if cred, err = newArgon2Credential(id, opts.password, cc.argon2()); err != nil {
			return nil, fmt.Errorf("create: password account: %w", err)
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, fmt.Errorf("create: password account: unable to get oplog wrapper: %w", err)
	}
	databaseWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, fmt.Errorf("create: password account: unable to get database wrapper: %w", err)
	}

	var newCred *Argon2Credential
	var newAccount *Account
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newAccount = a.clone()
			if err := w.Create(ctx, newAccount, db.WithOplog(oplogWrapper, a.oplog(oplog.OpType_OP_TYPE_CREATE))); err != nil {
				return err
			}

			if cred != nil {
				newCred = cred.clone()
				if err := newCred.encrypt(ctx, databaseWrapper); err != nil {
					return err
				}
				if err := w.Create(ctx, newCred, db.WithOplog(oplogWrapper, cred.oplog(oplog.OpType_OP_TYPE_CREATE))); err != nil {
					return err
				}
			}
			return nil
		},
	)

	if err != nil {
		if db.IsUniqueError(err) {
			return nil, fmt.Errorf("create: password account: in auth method: %s: name %q or loginName %q already exists: %w",
				a.AuthMethodId, a.Name, a.LoginName, db.ErrNotUnique)
		}
		return nil, fmt.Errorf("create: password account: in auth method: %s: %w", a.AuthMethodId, err)
	}
	return newAccount, nil
}

// LookupAccount will look up an account in the repository.  If the account is not
// found, it will return nil, nil.  All options are ignored.
func (r *Repository) LookupAccount(ctx context.Context, withPublicId string, opt ...Option) (*Account, error) {
	if withPublicId == "" {
		return nil, fmt.Errorf("lookup: password account: missing public id %w", db.ErrInvalidParameter)
	}
	a := allocAccount()
	a.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, a); err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("lookup: password account: failed %w for %s", err, withPublicId)
	}
	return a, nil
}

// ListAccounts in an auth method and supports WithLimit option.
func (r *Repository) ListAccounts(ctx context.Context, withAuthMethodId string, opt ...Option) ([]*Account, error) {
	if withAuthMethodId == "" {
		return nil, fmt.Errorf("list: password account: missing auth method id %w", db.ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var accts []*Account
	err := r.reader.SearchWhere(ctx, &accts, "auth_method_id = ?", []interface{}{withAuthMethodId}, db.WithLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("list: password account: %w", err)
	}
	return accts, nil
}

// DeleteAccount deletes the account for the provided id from the repository returning a count of the
// number of records deleted.  All options are ignored.
func (r *Repository) DeleteAccount(ctx context.Context, scopeId, withPublicId string, opt ...Option) (int, error) {
	if withPublicId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete: password account: missing public id: %w", db.ErrInvalidParameter)
	}
	if scopeId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete: password account: scope id empty: %w", db.ErrInvalidParameter)
	}
	ac := allocAccount()
	ac.PublicId = withPublicId

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete: password account: unable to get oplog wrapper: %w", err)
	}

	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			metadata := ac.oplog(oplog.OpType_OP_TYPE_DELETE)
			dAc := ac.clone()
			rowsDeleted, err = w.Delete(ctx, dAc, db.WithOplog(oplogWrapper, metadata))
			if err == nil && rowsDeleted > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)

	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete: password account: %s: %w", withPublicId, err)
	}

	return rowsDeleted, nil
}

var reInvalidLoginName = regexp.MustCompile("[^a-z0-9.]")

func validLoginName(u string) bool {
	if u == "" {
		return false
	}
	return !reInvalidLoginName.Match([]byte(u))
}

// UpdateAccount updates the repository entry for a.PublicId with the
// values in a for the fields listed in fieldMaskPaths. It returns a new
// Account containing the updated values and a count of the number of
// records updated. a is not changed.
//
// a must contain a valid PublicId. Only a.Name, a.Description and
// a.LoginName can be updated. If a.Name is set to a non-empty string, it
// must be unique within a.AuthMethodId. If a.LoginName is set to a
// non-empty string, it must be unique within a.AuthMethodId.
//
// An attribute of a will be set to NULL in the database if the attribute
// in a is the zero value and it is included in fieldMaskPaths. a.LoginName
// cannot be set to NULL.
func (r *Repository) UpdateAccount(ctx context.Context, scopeId string, a *Account, version uint32, fieldMaskPaths []string, opt ...Option) (*Account, int, error) {
	if a == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update: password account: %w", db.ErrInvalidParameter)
	}
	if a.Account == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update: password account: embedded Account: %w", db.ErrInvalidParameter)
	}
	if a.PublicId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("update: password account: missing public id: %w", db.ErrInvalidParameter)
	}
	if version == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("update: password account: no version supplied: %w", db.ErrInvalidParameter)
	}
	if scopeId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("update: password account: scope id empty: %w", db.ErrInvalidParameter)
	}

	var changeLoginName bool
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("Name", f):
		case strings.EqualFold("Description", f):
		case strings.EqualFold("LoginName", f):
			if !validLoginName(a.LoginName) {
				return nil, db.NoRowsAffected, fmt.Errorf("update: password account: invalid user name: %w", db.ErrInvalidParameter)
			}
			changeLoginName = true
		default:
			return nil, db.NoRowsAffected, fmt.Errorf("update: password account: field: %s: %w", f, db.ErrInvalidFieldMask)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"Name":        a.Name,
			"Description": a.Description,
			"LoginName":   a.LoginName,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("update: password account: %w", db.ErrEmptyFieldMask)
	}

	if changeLoginName {
		cc, err := r.currentConfigForAccount(ctx, a.PublicId)
		if err != nil {
			return nil, db.NoRowsAffected, fmt.Errorf("update: password account: retrieve current configuration: %w", err)
		}
		if cc.MinLoginNameLength > len(a.LoginName) {
			return nil, db.NoRowsAffected, fmt.Errorf("update: password account: user name %q: %w", a.LoginName, ErrTooShort)
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update: password account: unable to get oplog wrapper: %w", err)
	}

	a = a.clone()

	metadata := a.oplog(oplog.OpType_OP_TYPE_UPDATE)

	var rowsUpdated int
	var returnedAccount *Account
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedAccount = a.clone()
			var err error
			rowsUpdated, err = w.Update(ctx, returnedAccount, dbMask, nullFields, db.WithOplog(oplogWrapper, metadata), db.WithVersion(&version))
			if err == nil && rowsUpdated > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)

	if err != nil {
		if db.IsUniqueError(err) {
			return nil, db.NoRowsAffected, fmt.Errorf("update: password account: %s: name %s already exists: %w",
				a.PublicId, a.Name, db.ErrNotUnique)
		}
		return nil, db.NoRowsAffected, fmt.Errorf("update: password account: %s: %w", a.PublicId, err)
	}

	return returnedAccount, rowsUpdated, nil
}
