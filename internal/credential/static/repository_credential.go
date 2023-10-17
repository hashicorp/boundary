// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/subtypes"
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

	switch subtypes.SubtypeFromId(credential.Domain, publicId) {
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

// ListCredentials returns a slice of UsernamePasswordCredentials, SshPrivateKeyCredentials, and JsonCredentials
// for the storeId. Supports the following options:
//   - WithLimit
//   - WithStartPageAfterItem
func (r *Repository) ListCredentials(ctx context.Context, storeId string, opt ...credential.Option) ([]credential.Static, error) {
	const op = "static.(Repository).ListCredentials"
	if storeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no storeId")
	}
	opts, err := credential.GetOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	limit := r.defaultLimit
	if opts.WithLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.WithLimit
	}

	args := []any{sql.Named("store_id", storeId)}
	whereClause := "store_id = @store_id"
	// Ordering and pagination are tightly coupled.
	// We order by update_time ascending so that new
	// and updated items appear at the end of the pagination.
	// We need to further order by public_id to distinguish items
	// with identical update times.
	withOrder := "update_time asc, public_id asc"
	if opts.WithStartPageAfterItem != nil {
		// Now that the order is defined, we can use a simple where
		// clause to only include items updated since the specified
		// start of the page. We use greater than or equal for the update
		// time as there may be items with identical update_times. We
		// then use PublicId as a tiebreaker.
		args = append(args,
			sql.Named("after_item_update_time", opts.WithStartPageAfterItem.UpdateTime),
			sql.Named("after_item_id", opts.WithStartPageAfterItem.PublicId),
		)
		whereClause += " and (update_time > @after_item_update_time or (update_time = @after_item_update_time and public_id > @after_item_id))"
	}

	// Note: this could be parallelized (fan out) but would increase
	// DB load.

	var upCreds []*UsernamePasswordCredential
	if err := r.reader.SearchWhere(ctx, &upCreds, whereClause, args, db.WithLimit(limit), db.WithOrder(withOrder)); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var spkCreds []*SshPrivateKeyCredential
	if err := r.reader.SearchWhere(ctx, &spkCreds, whereClause, args, db.WithLimit(limit), db.WithOrder(withOrder)); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var jsonCreds []*JsonCredential
	if err := r.reader.SearchWhere(ctx, &jsonCreds, whereClause, args, db.WithLimit(limit), db.WithOrder(withOrder)); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	ret := make([]credential.Static, 0, len(upCreds)+len(spkCreds)+len(jsonCreds))

	for _, c := range upCreds {
		// Clear password fields, only PasswordHmac should be returned
		c.CtPassword = nil
		c.Password = nil
		ret = append(ret, c)
	}

	for _, c := range spkCreds {
		// Clear private key fields, only PrivateKeyHmac should be returned
		c.PrivateKeyEncrypted = nil
		c.PrivateKey = nil

		// Clear passphrase fields, only PrivateKeyPassphraseHmac should be returned if it exists
		c.PrivateKeyPassphraseEncrypted = nil
		c.PrivateKeyPassphrase = nil
		ret = append(ret, c)
	}

	for _, c := range jsonCreds {
		// Clear the object fields, only ObjectHmac should be returned
		c.ObjectEncrypted = nil
		c.Object = nil
		ret = append(ret, c)
	}

	// Sort final slice to ensure correct ordering.
	// Note: instead of appending to a slice and then sorting,
	// we could insert in-place, but in practice the runtime of
	// this function will be dominated by the 3 DB roundtrips, so
	// we're doing the simpler thing here.
	slices.SortFunc(ret, func(i, j credential.Static) int {
		return i.GetUpdateTime().AsTime().Compare(j.GetUpdateTime().AsTime())
	})

	// Truncate result to at most limit results
	if limit > 0 && len(ret) > limit {
		ret = ret[:limit]
	}

	return ret, nil
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
	switch subtypes.SubtypeFromId(credential.Domain, id) {
	case credential.UsernamePasswordSubtype:
		c := allocUsernamePasswordCredential()
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

// EstimatedCredentialCount returns an estimate of the number of static credential stores
func (r *Repository) EstimatedCredentialCount(ctx context.Context) (int, error) {
	const op = "static.(Repository).EstimatedCredentialCount"
	rows, err := r.reader.Query(ctx, estimateCountCredentials, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total static credential stores"))
	}
	var count int
	for rows.Next() {
		if err := r.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total static credential stores"))
		}
	}
	return count, nil
}

// ListDeletedCredentialIds lists the public IDs of any credential stores deleted since the timestamp provided.
// Supported options:
//   - credential.WithReaderWriter
func (r *Repository) ListDeletedCredentialIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	var credentialStoreIds []string
	const op = "static.(Repository).ListDeletedCredentialIds"
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
