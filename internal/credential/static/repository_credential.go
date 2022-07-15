package static

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// CreateUsernamePasswordCredential inserts c into the repository and returns a new
// UsernamePasswordCredential containing the credential's PublicId. c is not
// changed. c must not contain a PublicId. The PublicId is generated and
// assigned by this method. c must contain a valid StoreId.
//
// The password is encrypted and a HmacSha256 of the password is calculated. Only the
// PasswordHmac is returned, the plain-text and encrypted password is not returned.
//
// Both c.Name and c.Description are optional. If c.Name is set, it must
// be unique within c.ScopeId. Both c.CreateTime and c.UpdateTime are
// ignored.
func (r *Repository) CreateUsernamePasswordCredential(
	ctx context.Context,
	scopeId string,
	c *UsernamePasswordCredential,
	_ ...Option,
) (*UsernamePasswordCredential, error) {
	const op = "static.(Repository).CreateUsernamePasswordCredential"
	if c == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing credential")
	}
	if c.UsernamePasswordCredential == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing embedded credential")
	}
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if c.Username == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing username")
	}
	if c.Password == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing password")
	}
	if c.StoreId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing store id")
	}
	if c.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}

	c = c.clone()
	id, err := newUsernamePasswordCredentialId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	c.PublicId = id
	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	// encrypt
	databaseWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}
	if err := c.encrypt(ctx, databaseWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var newCred *UsernamePasswordCredential
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newCred = c.clone()
			if err := w.Create(ctx, newCred,
				db.WithOplog(oplogWrapper, newCred.oplog(oplog.OpType_OP_TYPE_CREATE))); err != nil {
				return errors.Wrap(ctx, err, op)
			}

			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in store: %s: name %s already exists", c.StoreId, c.Name)))
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in store: %s", c.StoreId)))
	}

	// Clear password fields, only passwordHmac should be returned
	newCred.CtPassword = nil
	newCred.Password = nil

	return newCred, nil
}

// LookupCredential returns the Credential for the publicId. Returns
// nil, nil if no Credential is found for the publicId.
// TODO: This should hit a view and return the interface type...
func (r *Repository) LookupCredential(ctx context.Context, publicId string, _ ...Option) (*UsernamePasswordCredential, error) {
	const op = "static.(Repository).LookupCredential"
	if publicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	cred := allocUsernamePasswordCredential()
	cred.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, cred); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", publicId)))
	}

	// Clear password fields, only passwordHmac should be returned
	cred.CtPassword = nil
	cred.Password = nil

	return cred, nil
}

// UpdateUsernamePasswordCredential updates the repository entry for c.PublicId with
// the values in c for the fields listed in fieldMaskPaths. It returns a
// new UsernamePasswordCredential containing the updated values and a count of the
// number of records updated. c is not changed.
//
// c must contain a valid PublicId. Only Name, Description, Username and Password can be
// changed. If c.Name is set to a non-empty string, it must be unique within c.ScopeId.
//
// An attribute of c will be set to NULL in the database if the attribute
// in c is the zero value and it is included in fieldMaskPaths.
func (r *Repository) UpdateUsernamePasswordCredential(ctx context.Context,
	scopeId string,
	c *UsernamePasswordCredential,
	version uint32,
	fieldMaskPaths []string,
	_ ...Option,
) (*UsernamePasswordCredential, int, error) {
	const op = "static.(Repository).UpdateUsernamePasswordCredential"
	if c == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing Credential")
	}
	if c.UsernamePasswordCredential == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing embedded Credential")
	}
	if c.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	if version == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if scopeId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if c.StoreId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing store id")
	}
	c = c.clone()

	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold(nameField, f):
		case strings.EqualFold(descriptionField, f):
		case strings.EqualFold(usernameField, f):
		case strings.EqualFold(passwordField, f):
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, f)
		}
	}
	dbMask, nullFields := dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			nameField:        c.Name,
			descriptionField: c.Description,
			usernameField:    c.Username,
			passwordField:    c.Password,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "missing field mask")
	}

	for _, f := range fieldMaskPaths {
		if strings.EqualFold(passwordField, f) {
			// Password has been updated, re-encrypt and recalculate hmac
			databaseWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
			if err != nil {
				return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
			}
			if err := c.encrypt(ctx, databaseWrapper); err != nil {
				return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
			}

			// Set PasswordHmac and CtPassword masks for update.
			dbMask = append(dbMask, "PasswordHmac", "CtPassword")
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected,
			errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsUpdated int
	var returnedCredential *UsernamePasswordCredential
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedCredential = c.clone()
			var err error
			rowsUpdated, err = w.Update(ctx, returnedCredential,
				dbMask, nullFields,
				db.WithOplog(oplogWrapper, returnedCredential.oplog(oplog.OpType_OP_TYPE_UPDATE)),
				db.WithVersion(&version))
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
		return nil, db.NoRowsAffected, err
	}

	// Clear password fields, only passwordHmac should be returned
	returnedCredential.CtPassword = nil
	returnedCredential.Password = nil

	return returnedCredential, rowsUpdated, nil
}

// ListCredentials returns a slice of UsernamePasswordCredentials for the
// scopeIds. WithLimit is the only option supported.
// TODO: This should hit a view and return the interface type...
func (r *Repository) ListCredentials(ctx context.Context, storeId string, opt ...Option) ([]*UsernamePasswordCredential, error) {
	const op = "static.(Repository).ListCredentials"
	if storeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no storeId")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var creds []*UsernamePasswordCredential
	err := r.reader.SearchWhere(ctx, &creds, "store_id = ?", []interface{}{storeId}, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	for _, c := range creds {
		// Clear password fields, only passwordHmac should be returned
		c.CtPassword = nil
		c.Password = nil
	}

	return creds, nil
}

// DeleteCredential deletes publicId from the repository and returns
// the number of records deleted. All options are ignored.
// TODO: This should hit a view...
func (r *Repository) DeleteCredential(ctx context.Context, scopeId, id string, _ ...Option) (int, error) {
	const op = "static.(Repository).DeleteCredential"
	if id == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	if scopeId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	}

	c := allocUsernamePasswordCredential()
	c.PublicId = id

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
			rowsDeleted, err = w.Delete(ctx, c, db.WithOplog(oplogWrapper, c.oplog(oplog.OpType_OP_TYPE_DELETE)))
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
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(id))
	}

	return rowsDeleted, nil
}
