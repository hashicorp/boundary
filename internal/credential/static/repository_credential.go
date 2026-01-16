// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-dbw"
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
// be unique within c.ProjectId. Both c.CreateTime and c.UpdateTime are
// ignored.
func (r *Repository) CreateUsernamePasswordCredential(
	ctx context.Context,
	projectId string,
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
	if projectId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
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
	id, err := credential.NewUsernamePasswordCredentialId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	c.PublicId = id
	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	// encrypt
	databaseWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
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

	// Clear password fields, only PasswordHmac should be returned
	newCred.CtPassword = nil
	newCred.Password = nil

	return newCred, nil
}

// CreateUsernamePasswordDomainCredential inserts c into the repository and returns a new
// UsernamePasswordDomainCredential containing the credential's PublicId. c is not
// changed. c must not contain a PublicId. The PublicId is generated and
// assigned by this method. c must contain a valid StoreId.
//
// The password is encrypted and a HmacSha256 of the password is calculated. Only the
// PasswordHmac is returned, the plain-text and encrypted password is not returned.
//
// Both c.Name and c.Description are optional. If c.Name is set, it must
// be unique within c.ProjectId. Both c.CreateTime and c.UpdateTime are
// ignored.
func (r *Repository) CreateUsernamePasswordDomainCredential(
	ctx context.Context,
	projectId string,
	c *UsernamePasswordDomainCredential,
	_ ...Option,
) (*UsernamePasswordDomainCredential, error) {
	const op = "static.(Repository).CreateUsernamePasswordDomainCredential"
	if c == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing credential")
	}
	if c.UsernamePasswordDomainCredential == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing embedded credential")
	}
	if projectId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
	}
	if c.Username == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing username")
	}
	if c.Domain == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing domain")
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
	id, err := credential.NewUsernamePasswordDomainCredentialId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	c.PublicId = id
	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	// encrypt
	databaseWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}
	if err := c.encrypt(ctx, databaseWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var newCred *UsernamePasswordDomainCredential
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

	// Clear password fields, only PasswordHmac should be returned
	newCred.CtPassword = nil
	newCred.Password = nil

	return newCred, nil
}

// CreatePasswordCredential inserts c into the repository and returns a new
// PasswordCredential containing the credential's PublicId. c is not
// changed. c must not contain a PublicId. The PublicId is generated and
// assigned by this method. c must contain a valid StoreId.
//
// The password is encrypted and a HmacSha256 of the password is calculated. Only the
// PasswordHmac is returned, the plain-text and encrypted password is not returned.
//
// Both c.Name and c.Description are optional. If c.Name is set, it must
// be unique within c.ProjectId. Both c.CreateTime and c.UpdateTime are
// ignored.
func (r *Repository) CreatePasswordCredential(
	ctx context.Context,
	projectId string,
	c *PasswordCredential,
	_ ...Option,
) (*PasswordCredential, error) {
	const op = "static.(Repository).CreatePasswordCredential"
	if c == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing credential")
	}
	if c.PasswordCredential == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing embedded credential")
	}
	if projectId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
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
	id, err := credential.NewPasswordCredentialId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	c.PublicId = id
	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	// encrypt
	databaseWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}
	if err := c.encrypt(ctx, databaseWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var newCred *PasswordCredential
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

	// Clear password fields, only PasswordHmac should be returned
	newCred.CtPassword = nil
	newCred.Password = nil

	return newCred, nil
}

// CreateSshPrivateKeyCredential inserts c into the repository and returns a new
// SshPrivateKeyCredential containing the credential's PublicId. c is not
// changed. c must not contain a PublicId. The PublicId is generated and
// assigned by this method. c must contain a valid StoreId.
//
// The private key is encrypted and a HmacSha256 of the private key is
// calculated. If a passphrase is supplied, it is also encrypted and an HmacSha256
// of passphrase is calculated. Only the PrivateKeyHmac (and
// PrivateKeyPassphraseHmac) is returned, the plain-text and encrypted private
// key and passphrase are not returned.
//
// Both c.Name and c.Description are optional. If c.Name is set, it must be
// unique within c.ProjectId. Both c.CreateTime and c.UpdateTime are ignored.
func (r *Repository) CreateSshPrivateKeyCredential(
	ctx context.Context,
	projectId string,
	c *SshPrivateKeyCredential,
	_ ...Option,
) (*SshPrivateKeyCredential, error) {
	const op = "static.(Repository).CreateSshPrivateKeyCredential"
	if c == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing credential")
	}
	if c.SshPrivateKeyCredential == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing embedded credential")
	}
	if projectId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
	}
	if c.Username == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing username")
	}
	if c.PrivateKey == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing private key")
	}
	if c.StoreId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing store id")
	}
	if c.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}

	c = c.clone()
	id, err := credential.NewSshPrivateKeyCredentialId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	c.PublicId = id
	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	// encrypt
	databaseWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}
	if err := c.encrypt(ctx, databaseWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var newCred *SshPrivateKeyCredential
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

	// Clear private key fields, only PrivateKeyHmac should be returned
	newCred.PrivateKeyEncrypted = nil
	newCred.PrivateKey = nil

	// Clear passphrase fields, only PrivateKeyPassphraseHmac should be returned if it exists
	newCred.PrivateKeyPassphraseEncrypted = nil
	newCred.PrivateKeyPassphrase = nil

	return newCred, nil
}

// CreateJsonCredential inserts c into the repository and returns a new
// JsonCredential containing the credential's PublicId. c is not
// changed. c must not contain a PublicId. The PublicId is generated and
// assigned by this method. c must contain a valid StoreId.
//
// The object is encrypted and a HmacSha256 of the object is
// calculated. Only the ObjectHmac is returned, the plain-text and encrypted
// object is not returned.
//
// Both c.Name and c.Description are optional. If c.Name is set, it must be
// unique within c.ProjectId. Both c.CreateTime and c.UpdateTime are ignored.
func (r *Repository) CreateJsonCredential(
	ctx context.Context,
	projectId string,
	c *JsonCredential,
	_ ...Option,
) (*JsonCredential, error) {
	const op = "static.(Repository).CreateJsonCredential"
	if c == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing credential")
	}
	if c.JsonCredential == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing embedded credential")
	}
	if projectId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
	}
	if c.Object == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing object")
	}
	if c.StoreId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing store id")
	}
	if c.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}

	c = c.clone()
	id, err := credential.NewJsonCredentialId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	c.PublicId = id
	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	// encrypt
	databaseWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}
	if err := c.encrypt(ctx, databaseWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var newCred *JsonCredential
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

	// Clear object fields, only ObjectHmac should be returned
	newCred.ObjectEncrypted = nil
	newCred.Object = nil

	return newCred, nil
}

// LookupCredential returns the Credential for the publicId. Returns
// nil, nil if no Credential is found for the publicId.
// TODO: This should hit a view and return the interface type...
func (r *Repository) LookupCredential(ctx context.Context, publicId string, _ ...Option) (credential.Static, error) {
	const op = "static.(Repository).LookupCredential"
	if publicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}

	var cred credential.Static

	switch globals.ResourceInfoFromPrefix(publicId).Subtype {
	case credential.UsernamePasswordSubtype:
		upCred := allocUsernamePasswordCredential()
		upCred.PublicId = publicId
		if err := r.reader.LookupByPublicId(ctx, upCred); err != nil {
			if errors.IsNotFoundError(err) {
				return nil, nil
			}
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", publicId)))
		}
		// Clear password fields, only passwordHmac should be returned
		upCred.CtPassword = nil
		upCred.Password = nil
		cred = upCred

	case credential.UsernamePasswordDomainSubtype:
		updCred := allocUsernamePasswordDomainCredential()
		updCred.PublicId = publicId
		if err := r.reader.LookupByPublicId(ctx, updCred); err != nil {
			if errors.IsNotFoundError(err) {
				return nil, nil
			}
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", publicId)))
		}
		// Clear password fields, only passwordHmac should be returned
		updCred.CtPassword = nil
		updCred.Password = nil
		cred = updCred

	case credential.PasswordSubtype:
		pCred := allocPasswordCredential()
		pCred.PublicId = publicId
		if err := r.reader.LookupByPublicId(ctx, pCred); err != nil {
			if errors.IsNotFoundError(err) {
				return nil, nil
			}
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", publicId)))
		}
		// Clear password fields, only passwordHmac should be returned
		pCred.CtPassword = nil
		pCred.Password = nil
		cred = pCred

	case credential.SshPrivateKeySubtype:
		spkCred := allocSshPrivateKeyCredential()
		spkCred.PublicId = publicId
		if err := r.reader.LookupByPublicId(ctx, spkCred); err != nil {
			if errors.IsNotFoundError(err) {
				return nil, nil
			}
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", publicId)))
		}
		// Clear private key fields, only privateKeyHmac should be returned
		spkCred.PrivateKeyEncrypted = nil
		spkCred.PrivateKey = nil
		// Clear passphrase fields, only PrivateKeyPassphraseHmac should be returned if it exists
		spkCred.PrivateKeyPassphraseEncrypted = nil
		spkCred.PrivateKeyPassphrase = nil
		cred = spkCred

	case credential.JsonSubtype:
		jsonCred := allocJsonCredential()
		jsonCred.PublicId = publicId
		if err := r.reader.LookupByPublicId(ctx, jsonCred); err != nil {
			if errors.IsNotFoundError(err) {
				return nil, nil
			}
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for : %s", publicId)))
		}
		// Clear object fields, only ObjectHmac should be returned
		jsonCred.ObjectEncrypted = nil
		jsonCred.Object = nil
		cred = jsonCred
	}

	return cred, nil
}

// UpdateUsernamePasswordCredential updates the repository entry for c.PublicId with
// the values in c for the fields listed in fieldMaskPaths. It returns a
// new UsernamePasswordCredential containing the updated values and a count of the
// number of records updated. c is not changed.
//
// c must contain a valid PublicId. Only Name, Description, Username and Password can be
// changed. If c.Name is set to a non-empty string, it must be unique within c.ProjectId.
//
// An attribute of c will be set to NULL in the database if the attribute
// in c is the zero value and it is included in fieldMaskPaths.
func (r *Repository) UpdateUsernamePasswordCredential(ctx context.Context,
	projectId string,
	c *UsernamePasswordCredential,
	version uint32,
	fieldMaskPaths []string,
	_ ...Option,
) (*UsernamePasswordCredential, int, error) {
	const op = "static.(Repository).UpdateUsernamePasswordCredential"
	if c == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing credential")
	}
	if c.UsernamePasswordCredential == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing embedded credential")
	}
	if c.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	if version == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if projectId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
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
	dbMask, nullFields := dbw.BuildUpdatePaths(
		map[string]any{
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
			databaseWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
			if err != nil {
				return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
			}
			if err := c.encrypt(ctx, databaseWrapper); err != nil {
				return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
			}

			// Set PasswordHmac and CtPassword masks for update.
			dbMask = append(dbMask, "PasswordHmac", "CtPassword", "KeyId")
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
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

	// Clear password fields, only PasswordHmac should be returned
	returnedCredential.CtPassword = nil
	returnedCredential.Password = nil

	return returnedCredential, rowsUpdated, nil
}

// UpdateUsernamePasswordDomainCredential updates the repository entry for c.PublicId with
// the values in c for the fields listed in fieldMaskPaths. It returns a
// new UsernamePasswordDomainCredential containing the updated values and a count of the
// number of records updated. c is not changed.
//
// c must contain a valid PublicId. Only Name, Description, Username, Password, and Domain can be
// changed. If c.Name is set to a non-empty string, it must be unique within c.ProjectId.
//
// An attribute of c will be set to NULL in the database if the attribute
// in c is the zero value and it is included in fieldMaskPaths.
func (r *Repository) UpdateUsernamePasswordDomainCredential(ctx context.Context,
	projectId string,
	c *UsernamePasswordDomainCredential,
	version uint32,
	fieldMaskPaths []string,
	_ ...Option,
) (*UsernamePasswordDomainCredential, int, error) {
	const op = "static.(Repository).UpdateUsernamePasswordDomainCredential"
	if c == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing credential")
	}
	if c.UsernamePasswordDomainCredential == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing embedded credential")
	}
	if c.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	if version == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if projectId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
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
		case strings.EqualFold(domainField, f):
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, f)
		}
	}
	dbMask, nullFields := dbw.BuildUpdatePaths(
		map[string]any{
			nameField:        c.Name,
			descriptionField: c.Description,
			usernameField:    c.Username,
			passwordField:    c.Password,
			domainField:      c.Domain,
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
			databaseWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
			if err != nil {
				return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
			}
			if err := c.encrypt(ctx, databaseWrapper); err != nil {
				return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
			}

			// Set PasswordHmac and CtPassword masks for update.
			dbMask = append(dbMask, "PasswordHmac", "CtPassword", "KeyId")
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected,
			errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsUpdated int
	var returnedCredential *UsernamePasswordDomainCredential
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

	// Clear password fields, only PasswordHmac should be returned
	returnedCredential.CtPassword = nil
	returnedCredential.Password = nil

	return returnedCredential, rowsUpdated, nil
}

// UpdatePasswordCredential updates the repository entry for c.PublicId with
// the values in c for the fields listed in fieldMaskPaths. It returns a
// new PasswordCredential containing the updated values and a count of the
// number of records updated. c is not changed.
//
// c must contain a valid PublicId. Only Name, Description and Password can be
// changed. If c.Name is set to a non-empty string, it must be unique within c.ProjectId.
//
// An attribute of c will be set to NULL in the database if the attribute
// in c is the zero value and it is included in fieldMaskPaths.
func (r *Repository) UpdatePasswordCredential(ctx context.Context,
	projectId string,
	c *PasswordCredential,
	version uint32,
	fieldMaskPaths []string,
	_ ...Option,
) (*PasswordCredential, int, error) {
	const op = "static.(Repository).UpdatePasswordCredential"
	if c == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing credential")
	}
	if c.PasswordCredential == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing embedded credential")
	}
	if c.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	if version == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if projectId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
	}
	if c.StoreId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing store id")
	}
	c = c.clone()

	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold(nameField, f):
		case strings.EqualFold(descriptionField, f):
		case strings.EqualFold(passwordField, f):
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, f)
		}
	}
	dbMask, nullFields := dbw.BuildUpdatePaths(
		map[string]any{
			nameField:        c.Name,
			descriptionField: c.Description,
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
			databaseWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
			if err != nil {
				return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
			}
			if err := c.encrypt(ctx, databaseWrapper); err != nil {
				return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
			}

			// Set PasswordHmac and CtPassword masks for update.
			dbMask = append(dbMask, "PasswordHmac", "CtPassword", "KeyId")
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected,
			errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsUpdated int
	var returnedCredential *PasswordCredential
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

	// Clear password fields, only PasswordHmac should be returned
	returnedCredential.CtPassword = nil
	returnedCredential.Password = nil

	return returnedCredential, rowsUpdated, nil
}

// UpdateSshPrivateKeyCredential updates the repository entry for c.PublicId
// with the values in c for the fields listed in fieldMaskPaths. It returns a
// new SshPrivateKeyCredential containing the updated values and a count of the
// number of records updated. c is not changed.
//
// c must contain a valid PublicId. Only Name, Description, Username,
// PrivateKey and PrivateKeyPassphrase can be changed. If c.Name is set to a non-empty string, it
// must be unique within c.ProjectId.
//
// An attribute of c will be set to NULL in the database if the attribute in c
// is the zero value and it is included in fieldMaskPaths.
func (r *Repository) UpdateSshPrivateKeyCredential(ctx context.Context,
	projectId string,
	c *SshPrivateKeyCredential,
	version uint32,
	fieldMaskPaths []string,
	_ ...Option,
) (*SshPrivateKeyCredential, int, error) {
	const op = "static.(Repository).UpdateSshPrivateKeyCredential"
	if c == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing credential")
	}
	if c.SshPrivateKeyCredential == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing embedded credential")
	}
	if c.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	if version == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if projectId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
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
		case strings.EqualFold(privateKeyField, f):
		case strings.EqualFold(PrivateKeyPassphraseField, f):
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, f)
		}
	}
	dbMask, nullFields := dbw.BuildUpdatePaths(
		map[string]any{
			nameField:                 c.Name,
			descriptionField:          c.Description,
			usernameField:             c.Username,
			privateKeyField:           c.PrivateKey,
			PrivateKeyPassphraseField: c.PrivateKeyPassphrase,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "missing field mask")
	}

	var performedEncryption bool
	for _, f := range fieldMaskPaths {
		if strings.EqualFold(privateKeyField, f) || strings.EqualFold(PrivateKeyPassphraseField, f) {
			if !performedEncryption {
				// We don't need to encrypt twice so keep track
				performedEncryption = true

				databaseWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
				if err != nil {
					return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
				}
				if err := c.encrypt(ctx, databaseWrapper); err != nil {
					return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
				}
			}

			dbMask = append(dbMask, "KeyId")
			if strings.EqualFold(privateKeyField, f) {
				// Set PrivateKeyHmac and PrivateKeyEncrypted masks for update.
				dbMask = append(dbMask, "PrivateKeyHmac", "PrivateKeyEncrypted")
			}
			if strings.EqualFold(PrivateKeyPassphraseField, f) {
				// Set PassphraseHmac and PassphraseEncrypted masks for update.
				dbMask = append(dbMask, "PrivateKeyPassphraseHmac", "PrivateKeyPassphraseEncrypted")
			}
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected,
			errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsUpdated int
	var returnedCredential *SshPrivateKeyCredential
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

	// Clear private key fields, only PrivateKeyHmac should be returned
	returnedCredential.PrivateKeyEncrypted = nil
	returnedCredential.PrivateKey = nil

	// Clear passphrase fields, only PrivateKeyPassphraseHmac should be returned if it exists
	returnedCredential.PrivateKeyPassphraseEncrypted = nil
	returnedCredential.PrivateKeyPassphrase = nil

	return returnedCredential, rowsUpdated, nil
}

// UpdateJsonCredential updates the repository entry for c.PublicId
// with the values in c for the fields listed in fieldMaskPaths. It returns a
// new JsonCredential containing the updated values and a count of the
// number of records updated. c is not changed.
//
// c must contain a valid PublicId. Only Name, Description and
// Json can be changed. If c.Name is set to a non-empty string, it must be
// unique within c.ProjectId.
//
// An attribute of c will be set to NULL in the database if the attribute in c
// is the zero value and it is included in fieldMaskPaths.
func (r *Repository) UpdateJsonCredential(ctx context.Context,
	projectId string,
	c *JsonCredential,
	version uint32,
	fieldMaskPaths []string,
	_ ...Option,
) (*JsonCredential, int, error) {
	const op = "static.(Repository).UpdateJsonCredential"
	if c == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing credential")
	}
	if c.JsonCredential == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing embedded credential")
	}
	if c.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	if version == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if projectId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
	}
	if c.StoreId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing store id")
	}
	c = c.clone()

	// each field in the json secret will be passed into the fieldMaskPaths as an individual path
	// that shares the same prefix: attributes.object.
	// for example attributes.object.username & attributes.object.password
	// fieldMaskPaths elements will be deduped if sharing the same prefix attributes.object.
	// and the values will be substituted with a single value Object.
	var hasSecret bool
	reducedFieldMaskPaths := []string{}
	for _, f := range fieldMaskPaths {
		if strings.HasPrefix(f, "attributes.object.") {
			hasSecret = true
			continue
		}
		reducedFieldMaskPaths = append(reducedFieldMaskPaths, f)
	}
	if hasSecret {
		reducedFieldMaskPaths = append(reducedFieldMaskPaths, objectField)
	}

	for _, f := range reducedFieldMaskPaths {
		switch {
		case strings.EqualFold(nameField, f):
		case strings.EqualFold(descriptionField, f):
		case strings.EqualFold(objectField, f):
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, f)
		}
	}
	dbMask, nullFields := dbw.BuildUpdatePaths(
		map[string]any{
			nameField:        c.Name,
			descriptionField: c.Description,
			objectField:      c.Object,
		},
		reducedFieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "missing field mask")
	}

	if hasSecret {
		// Json secret has been updated, re-encrypt and recalculate hmac
		databaseWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
		}
		if err := c.encrypt(ctx, databaseWrapper); err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}

		// Set ObjectHmac and ObjectEncrypted masks for update.
		dbMask = append(dbMask, "ObjectHmac", "ObjectEncrypted", "KeyId")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected,
			errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsUpdated int
	var returnedCredential *JsonCredential
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

	// Clear object fields, only ObjectHmac should be returned
	returnedCredential.ObjectEncrypted = nil
	returnedCredential.Object = nil

	return returnedCredential, rowsUpdated, nil
}

// ListCredentials returns a slice of static credentials
// for the storeId. Supports the following options:
//   - credential.WithLimit
//   - credential.WithStartPageAfterItem
func (r *Repository) ListCredentials(ctx context.Context, storeId string, opt ...credential.Option) ([]credential.Static, time.Time, error) {
	const op = "static.(Repository).ListCredentials"
	if storeId == "" {
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "no storeId")
	}
	opts, err := credential.GetOpts(opt...)
	if err != nil {
		return nil, time.Time{}, errors.Wrap(ctx, err, op)
	}
	limit := r.defaultLimit
	if opts.WithLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.WithLimit
	}
	query := fmt.Sprintf(listCredentialsTemplate, limit)
	args := []any{sql.Named("store_id", storeId)}
	if opts.WithStartPageAfterItem != nil {
		query = fmt.Sprintf(listCredentialsPageTemplate, limit)
		args = append(args,
			sql.Named("last_item_create_time", opts.WithStartPageAfterItem.GetCreateTime()),
			sql.Named("last_item_id", opts.WithStartPageAfterItem.GetPublicId()),
		)
	}

	creds, transactionTimestamp, err := r.queryCredentials(ctx, query, args)
	if err != nil {
		return nil, time.Time{}, errors.Wrap(ctx, err, op)
	}

	// Sort final slice to ensure correct ordering.
	// We sort by create time descending (most recently created first).
	slices.SortFunc(creds, func(i, j credential.Static) int {
		return j.GetCreateTime().AsTime().Compare(i.GetCreateTime().AsTime())
	})

	return creds, transactionTimestamp, nil
}

// ListCredentialRefresh returns a slice of static credentials
// for the storeId. Supports the following options:
//   - credential.WithLimit
//   - credential.WithStartPageAfterItem
func (r *Repository) ListCredentialsRefresh(ctx context.Context, storeId string, updatedAfter time.Time, opt ...credential.Option) ([]credential.Static, time.Time, error) {
	const op = "static.(Repository).ListCredentials"
	switch {
	case storeId == "":
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing credential store ID")
	case updatedAfter.IsZero():
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing updated after time")
	}
	opts, err := credential.GetOpts(opt...)
	if err != nil {
		return nil, time.Time{}, errors.Wrap(ctx, err, op)
	}
	limit := r.defaultLimit
	if opts.WithLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.WithLimit
	}

	query := fmt.Sprintf(listCredentialsRefreshTemplate, limit)
	args := []any{
		sql.Named("store_id", storeId),
		sql.Named("updated_after_time", timestamp.New(updatedAfter)),
	}
	if opts.WithStartPageAfterItem != nil {
		query = fmt.Sprintf(listCredentialsRefreshPageTemplate, limit)
		args = append(args,
			sql.Named("last_item_update_time", opts.WithStartPageAfterItem.GetUpdateTime()),
			sql.Named("last_item_id", opts.WithStartPageAfterItem.GetPublicId()),
		)
	}

	creds, transactionTimestamp, err := r.queryCredentials(ctx, query, args)
	if err != nil {
		return nil, time.Time{}, errors.Wrap(ctx, err, op)
	}

	// Sort final slice to ensure correct ordering.
	// We sort by update time descending (most recently updated first).
	slices.SortFunc(creds, func(i, j credential.Static) int {
		return j.GetUpdateTime().AsTime().Compare(i.GetUpdateTime().AsTime())
	})

	return creds, transactionTimestamp, nil
}

func (r *Repository) queryCredentials(ctx context.Context, query string, args []any) ([]credential.Static, time.Time, error) {
	const op = "static.(Repository).queryCredentials"

	var creds []credential.Static
	var transactionTimestamp time.Time
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(rd db.Reader, w db.Writer) error {
		rows, err := rd.Query(ctx, query, args)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		var results []listCredentialResult
		for rows.Next() {
			if err := rd.ScanRows(ctx, rows, &results); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}
		if err := rows.Err(); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		for _, result := range results {
			cred, err := result.toCredential(ctx)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			creds = append(creds, cred)
		}
		transactionTimestamp, err = rd.Now(ctx)
		return err
	}); err != nil {
		return nil, time.Time{}, err
	}

	return creds, transactionTimestamp, nil
}

// DeleteCredential deletes publicId from the repository and returns
// the number of records deleted. All options are ignored.
// TODO: This should hit a view...
func (r *Repository) DeleteCredential(ctx context.Context, projectId, id string, _ ...Option) (int, error) {
	const op = "static.(Repository).DeleteCredential"
	if id == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	if projectId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no project id")
	}

	var input any
	var md oplog.Metadata
	switch globals.ResourceInfoFromPrefix(id).Subtype {
	case credential.UsernamePasswordSubtype:
		c := allocUsernamePasswordCredential()
		c.PublicId = id
		input = c
		md = c.oplog(oplog.OpType_OP_TYPE_DELETE)
	case credential.UsernamePasswordDomainSubtype:
		c := allocUsernamePasswordDomainCredential()
		c.PublicId = id
		input = c
		md = c.oplog(oplog.OpType_OP_TYPE_DELETE)
	case credential.PasswordSubtype:
		c := allocPasswordCredential()
		c.PublicId = id
		input = c
		md = c.oplog(oplog.OpType_OP_TYPE_DELETE)
	case credential.SshPrivateKeySubtype:
		c := allocSshPrivateKeyCredential()
		c.PublicId = id
		input = c
		md = c.oplog(oplog.OpType_OP_TYPE_DELETE)
	case credential.JsonSubtype:
		c := allocJsonCredential()
		c.PublicId = id
		input = c
		md = c.oplog(oplog.OpType_OP_TYPE_DELETE)
	default:
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "unknown type")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			rowsDeleted, err = w.Delete(ctx, input, db.WithOplog(oplogWrapper, md))
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

// EstimatedCredentialCount returns an estimate of the number of static credentials
func (r *Repository) EstimatedCredentialCount(ctx context.Context) (int, error) {
	const op = "static.(Repository).EstimatedCredentialCount"
	rows, err := r.reader.Query(ctx, estimateCountCredentials, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total static credentials"))
	}
	var count int
	for rows.Next() {
		if err := r.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total static credentials"))
		}
	}
	if err := rows.Err(); err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total static credentials"))
	}
	return count, nil
}

// ListDeletedCredentialIds lists the public IDs of any credentials deleted since the timestamp provided.
func (r *Repository) ListDeletedCredentialIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	const op = "static.(Repository).ListDeletedCredentialIds"
	var credentialStoreIds []string
	var transactionTimestamp time.Time
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		var deletedJSONCredentials []*deletedJSONCredential
		if err := r.SearchWhere(ctx, &deletedJSONCredentials, "delete_time >= ?", []any{since}); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted JSON credentials"))
		}
		for _, cl := range deletedJSONCredentials {
			credentialStoreIds = append(credentialStoreIds, cl.PublicId)
		}
		var deletedUsernamePasswordCredentials []*deletedUsernamePasswordCredential
		if err := r.SearchWhere(ctx, &deletedUsernamePasswordCredentials, "delete_time >= ?", []any{since}); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted username password credentials"))
		}
		for _, cl := range deletedUsernamePasswordCredentials {
			credentialStoreIds = append(credentialStoreIds, cl.PublicId)
		}
		var deletedUsernamePasswordDomainCredentials []*deletedUsernamePasswordDomainCredential
		if err := r.SearchWhere(ctx, &deletedUsernamePasswordDomainCredentials, "delete_time >= ?", []any{since}); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted username password domain credentials"))
		}
		for _, cl := range deletedUsernamePasswordDomainCredentials {
			credentialStoreIds = append(credentialStoreIds, cl.PublicId)
		}
		var deletedPasswordCredentials []*deletedPasswordCredential
		if err := r.SearchWhere(ctx, &deletedPasswordCredentials, "delete_time >= ?", []any{since}); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted password credentials"))
		}
		for _, cl := range deletedPasswordCredentials {
			credentialStoreIds = append(credentialStoreIds, cl.PublicId)
		}
		var deletedSSHPrivateKeyCredentials []*deletedSSHPrivateKeyCredential
		if err := r.SearchWhere(ctx, &deletedSSHPrivateKeyCredentials, "delete_time >= ?", []any{since}); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted ssh private key credentials"))
		}
		for _, cl := range deletedSSHPrivateKeyCredentials {
			credentialStoreIds = append(credentialStoreIds, cl.PublicId)
		}
		var err error
		transactionTimestamp, err = r.Now(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query transaction timestamp"))
		}
		return nil
	}); err != nil {
		return nil, time.Time{}, err
	}
	return credentialStoreIds, transactionTimestamp, nil
}
