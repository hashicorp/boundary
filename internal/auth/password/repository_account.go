package password

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/intglobals"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-dbw"
)

// CreateAccount inserts a into the repository and returns a new Account
// containing the account's PublicId. a is not changed. a must contain a valid
// AuthMethodId. a must not contain a PublicId. The PublicId is generated and
// assigned by this method.
//
// a must contain a valid LoginName. a.LoginName must be unique within
// a.AuthMethodId.
//
// WithPassword and WithPublicId are the only valid options. All other options
// are ignored.
//
// Both a.Name and a.Description are optional. If a.Name is set, it must be
// unique within a.AuthMethodId.
func (r *Repository) CreateAccount(ctx context.Context, scopeId string, a *Account, opt ...Option) (*Account, error) {
	const op = "password.(Repository).CreateAccount"
	if a == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing Account")
	}
	if a.Account == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing embedded Account")
	}
	if a.AuthMethodId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	}
	if a.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id must be empty")
	}
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if !validLoginName(a.LoginName) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("login name must be all-lowercase alphanumeric, period or hyphen. got: %s", a.LoginName))
	}

	cc, err := r.currentConfig(ctx, a.AuthMethodId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("retrieve current configuration"))
	}

	if cc.MinLoginNameLength > len(a.LoginName) {
		return nil, errors.New(ctx, errors.TooShort, op, fmt.Sprintf("username: %s, must be longer than %d", a.LoginName, cc.MinLoginNameLength))
	}

	opts := GetOpts(opt...)

	a = a.clone()
	if opts.withPublicId != "" {
		if !strings.HasPrefix(opts.withPublicId, intglobals.NewPasswordAccountPrefix+"_") {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "chosen account id does not have a valid prefix")
		}
		a.PublicId = opts.withPublicId
	} else {
		id, err := newAccountId()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		a.PublicId = id
	}

	var cred *Argon2Credential
	if opts.withPassword {
		if cc.MinPasswordLength > len(opts.password) {
			return nil, errors.New(ctx, errors.PasswordTooShort, op, fmt.Sprintf("must be longer than %v", cc.MinPasswordLength))
		}
		if cred, err = newArgon2Credential(a.PublicId, opts.password, cc.argon2()); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"), errors.WithCode(errors.Encrypt))
	}
	databaseWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"), errors.WithCode(errors.Encrypt))
	}

	var newCred *Argon2Credential
	var newAccount *Account
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newAccount = a.clone()
			if err := w.Create(ctx, newAccount, db.WithOplog(oplogWrapper, a.oplog(oplog.OpType_OP_TYPE_CREATE))); err != nil {
				return errors.Wrap(ctx, err, op)
			}

			if cred != nil {
				newCred = cred.clone()
				if err := newCred.encrypt(ctx, databaseWrapper); err != nil {
					return errors.Wrap(ctx, err, op)
				}
				if err := w.Create(ctx, newCred, db.WithOplog(oplogWrapper, cred.oplog(oplog.OpType_OP_TYPE_CREATE))); err != nil {
					return errors.Wrap(ctx, err, op)
				}
			}
			return nil
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("in auth method %s: name %q or loginName %q already exists",
				a.AuthMethodId, a.Name, a.LoginName))
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(a.AuthMethodId))
	}
	return newAccount, nil
}

// LookupAccount will look up an account in the repository.  If the account is not
// found, it will return nil, nil.  All options are ignored.
func (r *Repository) LookupAccount(ctx context.Context, withPublicId string, opt ...Option) (*Account, error) {
	const op = "password.(Repository).LookupAccount"
	if withPublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	a := allocAccount()
	a.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, a); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", withPublicId)))
	}
	return a, nil
}

// ListAccounts in an auth method and supports WithLimit option.
func (r *Repository) ListAccounts(ctx context.Context, withAuthMethodId string, opt ...Option) ([]*Account, error) {
	const op = "password.(Repository).ListAccounts"
	if withAuthMethodId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	}
	opts := GetOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var accts []*Account
	err := r.reader.SearchWhere(ctx, &accts, "auth_method_id = ?", []interface{}{withAuthMethodId}, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return accts, nil
}

// DeleteAccount deletes the account for the provided id from the repository returning a count of the
// number of records deleted.  All options are ignored.
func (r *Repository) DeleteAccount(ctx context.Context, scopeId, withPublicId string, opt ...Option) (int, error) {
	const op = "password.(Repository).DeleteAccount"
	if withPublicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	if scopeId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	ac := allocAccount()
	ac.PublicId = withPublicId

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("unable to get oplog wrapper"))
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
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(withPublicId))
	}

	return rowsDeleted, nil
}

var reInvalidLoginName = regexp.MustCompile("[^a-z0-9.-]")

func validLoginName(u string) bool {
	if u == "" {
		return false
	}
	return !reInvalidLoginName.MatchString(u)
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
	const op = "password.(Repository).UpdateAccount"
	if a == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing Account")
	}
	if a.Account == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing embedded Account")
	}
	if a.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	if version == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if scopeId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}

	var changeLoginName bool
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("Name", f):
		case strings.EqualFold("Description", f):
		case strings.EqualFold("LoginName", f):
			if !validLoginName(a.LoginName) {
				return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op,
					fmt.Sprintf("invalid username: must be all-lowercase alphanumeric, period or hyphen, got %s", a.LoginName))
			}
			changeLoginName = true
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, f)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbw.BuildUpdatePaths(
		map[string]interface{}{
			"Name":        a.Name,
			"Description": a.Description,
			"LoginName":   a.LoginName,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "missing field mask")
	}

	if changeLoginName {
		cc, err := r.currentConfigForAccount(ctx, a.PublicId)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("retrieve current configuration"))
		}
		if cc.MinLoginNameLength > len(a.LoginName) {
			return nil, db.NoRowsAffected, errors.New(ctx, errors.TooShort, op,
				fmt.Sprintf("username: %s, must be longer than %v", a.LoginName, cc.MinLoginNameLength))
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt),
			errors.WithMsg(("unable to get oplog wrapper")))
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
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsUpdated > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been updated")
			}
			return nil
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, db.NoRowsAffected, errors.New(ctx, errors.NotUnique, op,
				fmt.Sprintf("name %s already exists: %s", a.Name, a.PublicId))
		}
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(a.PublicId))
	}

	return returnedAccount, rowsUpdated, nil
}
