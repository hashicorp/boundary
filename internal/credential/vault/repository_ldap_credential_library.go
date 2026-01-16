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

// CreateLdapCredentialLibrary creates a new Vault LDAP credential library. It
// inserts the input domain object into the repository and returns the inserted
// domain object. No options are supported.
//
// The input domain object is not mutated, must contain a valid credential store
// id and must not contain a public id.
func (r *Repository) CreateLdapCredentialLibrary(ctx context.Context, projectId string, l *LdapCredentialLibrary, _ ...Option) (*LdapCredentialLibrary, error) {
	const op = "vault.(Repository).CreateLdapCredentialLibrary"
	if projectId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no project id")
	}
	if l == nil || l.LdapCredentialLibrary == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil input domain object")
	}
	if l.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}
	if l.StoreId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no store id")
	}
	if l.VaultPath == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no vault path")
	}
	l = l.clone()

	if l.GetCredentialType() == "" {
		l.LdapCredentialLibrary.CredentialType = string(globals.UsernamePasswordDomainCredentialType)
	}
	if l.GetCredentialType() != string(globals.UsernamePasswordDomainCredentialType) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "invalid credential type")
	}

	id, err := newLdapCredentialLibraryId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	l.setId(id)

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var insertedLdapCredLib *LdapCredentialLibrary
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			insertedLdapCredLib = l.clone()
			err = w.Create(ctx, insertedLdapCredLib,
				db.WithOplog(oplogWrapper, insertedLdapCredLib.oplog(oplog.OpType_OP_TYPE_CREATE)),
			)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}

			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("in credential store: %s: name %s already exists", l.StoreId, l.Name))
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("credential store: %s", l.StoreId))
	}

	return insertedLdapCredLib, nil
}

// UpdateLdapCredentialLibrary updates an existing Vault LDAP credential library
// in the repository. It returns a domain object containing the updated state
// and the number of updated records. No options are supported.
//
// The input domain object is not mutated and must contain a valid public id.
func (r *Repository) UpdateLdapCredentialLibrary(ctx context.Context, projectId string, l *LdapCredentialLibrary, version uint32, fieldMaskPaths []string, _ ...Option) (*LdapCredentialLibrary, int, error) {
	const op = "vault.(Repository).UpdateLdapCredentialLibrary"
	if projectId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no project id")
	}
	if version == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if l == nil || l.LdapCredentialLibrary == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "nil domain object")
	}
	if l.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}

	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold(nameField, f):
		case strings.EqualFold(descriptionField, f):
		case strings.EqualFold(vaultPathField, f):
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, fmt.Sprintf("%q field mask path is unsupported", f))
		}
	}

	dbMask, nullFields := dbw.BuildUpdatePaths(
		map[string]any{
			nameField:        l.Name,
			descriptionField: l.Description,
			vaultPathField:   l.VaultPath,
		}, fieldMaskPaths, nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "missing field mask")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var updatedCredLib *LdapCredentialLibrary
	var rowsUpdated int
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			updated, err := w.Update(ctx, l.clone(), dbMask, nullFields,
				db.WithOplog(oplogWrapper, l.oplog(oplog.OpType_OP_TYPE_UPDATE)),
				db.WithVersion(&version),
			)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update credential library"))
			}
			if updated > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 credential library would have been updated")
			}
			rowsUpdated = updated

			updatedCredLib = allocLdapCredentialLibrary()
			updatedCredLib.PublicId = l.GetPublicId()
			err = r.LookupByPublicId(ctx, updatedCredLib)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve updated credential library"))
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("name %s already exists: %s", l.Name, l.PublicId))
		}
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("failed to update credential library %s", l.PublicId))
	}

	return updatedCredLib, rowsUpdated, nil
}

// LookupLdapCredentialLibrary looks up an existing Vault LDAP credential
// library in the repository. It returns the domain object for the given public
// id, if it exists. Returns nil, nil if not found. No options are supported.
func (r *Repository) LookupLdapCredentialLibrary(ctx context.Context, publicId string, _ ...Option) (*LdapCredentialLibrary, error) {
	const op = "vault.(Repository).LookupLdapCredentialLibrary"
	if publicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}

	l := allocLdapCredentialLibrary()
	l.PublicId = publicId
	err := r.reader.LookupByPublicId(ctx, l)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("lookup failed for id %s", publicId))
	}

	return l, nil
}

// DeleteLdapCredentialLibrary deletes the Vault LDAP credential library with
// the given public id from the repository. Returns the number of records
// deleted. No options are supported.
func (r *Repository) DeleteLdapCredentialLibrary(ctx context.Context, projectId string, publicId string, _ ...Option) (int, error) {
	const op = "vault.(Repository).DeleteLdapCredentialLibrary"
	if publicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	if projectId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no project id")
	}

	l := allocLdapCredentialLibrary()
	l.PublicId = publicId

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsDeleted int
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			rowsDeleted, err = w.Delete(ctx, l, db.WithOplog(oplogWrapper, l.oplog(oplog.OpType_OP_TYPE_DELETE)))
			if err == nil && rowsDeleted > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 credential library would have been deleted")
			}
			return err
		},
	)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("delete failed for id %s", l.PublicId))
	}

	return rowsDeleted, nil
}
