// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-dbw"
)

// CreateSSHCertificateCredentialLibrary inserts l into the repository and returns a new
// SSHCertificateCredentialLibrary containing the credential library's PublicId. l is not
// changed. l must contain a valid StoreId. l must not contain a PublicId.
// The PublicId is generated and assigned by this method.
//
// Both l.Name and l.Description are optional. If l.Name is set, it must be
// unique within l.StoreId.
//
// Both l.CreateTime and l.UpdateTime are ignored.
func (r *Repository) CreateSSHCertificateCredentialLibrary(ctx context.Context, projectId string, l *SSHCertificateCredentialLibrary, _ ...Option) (*SSHCertificateCredentialLibrary, error) {
	const op = "vault.(Repository).CreateSSHCertificateCredentialLibrary"
	if l == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil SSHCertificateCredentialLibrary")
	}
	if l.SSHCertificateCredentialLibrary == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil embedded l")
	}
	if l.StoreId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no store id")
	}
	if l.VaultPath == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no vault path")
	}
	if l.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}
	if projectId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no project id")
	}
	if l.Username == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no username")
	}

	l = l.clone()

	if l.KeyType == "" {
		l.KeyType = KeyTypeEd25519
	}

	if l.KeyBits == KeyBitsDefault {
		l.KeyBits = l.getDefaultKeyBits()
	}

	if l.GetCredentialType() == "" {
		l.SSHCertificateCredentialLibrary.CredentialType = string(globals.SshCertificateCredentialType)
	}
	if l.GetCredentialType() != string(globals.SshCertificateCredentialType) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "invalid credential type")
	}

	id, err := newSSHCertificateCredentialLibraryId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	l.setId(id)

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var newSSHCertificateCredentialLibrary *SSHCertificateCredentialLibrary
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			var msgs []*oplog.Message
			ticket, err := w.GetTicket(ctx, l)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			// insert credential library
			newSSHCertificateCredentialLibrary = l.clone()
			var lOplogMsg oplog.Message
			if err := w.Create(ctx, newSSHCertificateCredentialLibrary, db.NewOplogMsg(&lOplogMsg)); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			msgs = append(msgs, &lOplogMsg)

			metadata := l.oplog(oplog.OpType_OP_TYPE_CREATE)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in credential store: %s: name %s already exists", l.StoreId, l.Name)))
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in credential store: %s", l.StoreId)))
	}
	return newSSHCertificateCredentialLibrary, nil
}

// UpdateSSHCertificateCredentialLibrary updates the repository entry for l.PublicId with
// the values in l for the fields listed in fieldMaskPaths. It returns a
// new SSHCertificateCredentialLibrary containing the updated values and a count of the
// number of records updated. l is not changed.
//
// l must contain a valid PublicId. Name, Description, VaultPath, Username,
// KeyType, KeyBits, Ttl, KeyId, CriticalOptions, and Extensions can be updated. If
// l.Name is set to a non-empty string, it must be unique within l.StoreId.
//
// An attribute of l will be set to NULL in the database if the attribute
// in l is the zero value and it is included in fieldMaskPaths.
func (r *Repository) UpdateSSHCertificateCredentialLibrary(ctx context.Context, projectId string, l *SSHCertificateCredentialLibrary, version uint32, fieldMaskPaths []string, _ ...Option) (*SSHCertificateCredentialLibrary, int, error) {
	const op = "vault.(Repository).UpdateSSHCertificateCredentialLibrary"
	if l == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing SSHCertificateCredentialLibrary")
	}
	if l.SSHCertificateCredentialLibrary == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing embedded SSHCertificateCredentialLibrary")
	}
	if l.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	if version == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if projectId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
	}
	l = l.clone()

	var keyTypeChange, keyBitChangeDefault bool

	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold(nameField, f):
		case strings.EqualFold(descriptionField, f):
		case strings.EqualFold(vaultPathField, f):
		case strings.EqualFold(usernameField, f):
		case strings.EqualFold(keyTypeField, f):
			keyTypeChange = true
		case strings.EqualFold(keyBitsField, f):
			keyBitChangeDefault = l.KeyBits == KeyBitsDefault
		case strings.EqualFold(ttlField, f):
		case strings.EqualFold(keyIdField, f):
		case strings.EqualFold(CriticalOptionsField, f):
		case strings.EqualFold(ExtensionsField, f):
		case strings.EqualFold(AdditionalValidPrincipalsField, f):
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, f)
		}
	}

	if keyTypeChange && l.KeyType == "" {
		l.KeyType = KeyTypeEd25519
	}

	if keyTypeChange && keyBitChangeDefault {
		l.KeyBits = l.getDefaultKeyBits()
	}

	origLib, err := r.LookupSSHCertificateCredentialLibrary(ctx, l.PublicId)
	switch {
	case err != nil:
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	case origLib == nil:
		return nil, db.NoRowsAffected, errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("credential library %s", l.PublicId))
	}

	if keyBitChangeDefault && !keyTypeChange {
		l.KeyBits = origLib.getDefaultKeyBits()
	}

	var dbMask, nullFields []string
	dbMask, nullFields = dbw.BuildUpdatePaths(
		map[string]any{
			nameField:                      l.Name,
			descriptionField:               l.Description,
			vaultPathField:                 l.VaultPath,
			usernameField:                  l.Username,
			keyTypeField:                   l.KeyType,
			keyBitsField:                   l.KeyBits,
			ttlField:                       l.Ttl,
			keyIdField:                     l.KeyId,
			CriticalOptionsField:           l.CriticalOptions,
			ExtensionsField:                l.Extensions,
			AdditionalValidPrincipalsField: l.AdditionalValidPrincipals,
		},
		fieldMaskPaths,
		[]string{keyBitsField},
	)

	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "missing field mask")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt),
			errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsUpdated int
	var returnedCredentialLibrary *SSHCertificateCredentialLibrary
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(rr db.Reader, w db.Writer) error {
			var msgs []*oplog.Message
			ticket, err := w.GetTicket(ctx, l)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			l := l.clone()
			var lOplogMsg oplog.Message

			// Update the credential library table
			switch {
			case len(dbMask) == 0 && len(nullFields) == 0:
				// the credential library's fields are not being updated,
				// just one of it's child objects, so we just need to
				// update the library's version.
				l.Version = version + 1
				rowsUpdated, err = w.Update(ctx, l, []string{"Version"}, nil, db.NewOplogMsg(&lOplogMsg), db.WithVersion(&version))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update credential library version"))
				}
				switch rowsUpdated {
				case 1:
				case 0:
					return nil
				default:
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated credential library version and %d rows updated", rowsUpdated))
				}
			default:
				rowsUpdated, err = w.Update(ctx, l, dbMask, nullFields, db.NewOplogMsg(&lOplogMsg), db.WithVersion(&version))
				if err != nil {
					if errors.IsUniqueError(err) {
						return errors.New(ctx, errors.NotUnique, op,
							fmt.Sprintf("name %s already exists: %s", l.Name, l.PublicId))
					}
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update credential library"))
				}
				switch rowsUpdated {
				case 1:
				case 0:
					return nil
				default:
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated credential library and %d rows updated", rowsUpdated))
				}
			}
			msgs = append(msgs, &lOplogMsg)

			metadata := l.oplog(oplog.OpType_OP_TYPE_UPDATE)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}

			accl := allocSSHCertificateCredentialLibrary()
			accl.PublicId = l.PublicId
			if err = rr.LookupById(ctx, accl); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve updated credential library"))
			}
			returnedCredentialLibrary = accl
			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, db.NoRowsAffected, errors.New(ctx, errors.NotUnique, op,
				fmt.Sprintf("name %s already exists: %s", l.Name, l.PublicId))
		}
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(l.PublicId))
	}

	return returnedCredentialLibrary, rowsUpdated, nil
}

// LookupSSHCertificateCredentialLibrary returns the SSHCertificateCredentialLibrary for publicId.
// Returns nil, nil if no SSHCertificateCredentialLibrary is found for publicId.
func (r *Repository) LookupSSHCertificateCredentialLibrary(ctx context.Context, publicId string, _ ...Option) (*SSHCertificateCredentialLibrary, error) {
	const op = "vault.(Repository).LookupCredentialLibrary"
	if publicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	l := allocSSHCertificateCredentialLibrary()
	l.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, l); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", publicId)))
	}
	return l, nil
}

// DeleteSSHCertificateCredentialLibrary deletes publicId from the repository and returns
// the number of records deleted.
func (r *Repository) DeleteSSHCertificateCredentialLibrary(ctx context.Context, projectId string, publicId string, _ ...Option) (int, error) {
	const op = "vault.(Repository).DeleteSSHCertificateCredentialLibrary"
	if publicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	if projectId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no project id")
	}

	l := allocSSHCertificateCredentialLibrary()
	l.PublicId = publicId

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			dl := l.clone()
			rowsDeleted, err = w.Delete(ctx, dl, db.WithOplog(oplogWrapper, l.oplog(oplog.OpType_OP_TYPE_DELETE)))
			if err == nil && rowsDeleted > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 CredentialLibrary would have been deleted")
			}
			return err
		},
	)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("delete failed for %s", l.PublicId)))
	}

	return rowsDeleted, nil
}
