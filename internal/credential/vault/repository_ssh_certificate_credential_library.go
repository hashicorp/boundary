package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
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

	id, err := newSSHCertificateCredentialLibraryId()
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
// l must contain a valid PublicId. Only Name, Description, VaultPath,
// HttpMethod, HttpRequestBody, and MappingOverride can be updated. If
// l.Name is set to a non-empty string, it must be unique within l.StoreId.
//
// An attribute of l will be set to NULL in the database if the attribute
// in l is the zero value and it is included in fieldMaskPaths except for
// HttpMethod.  If HttpMethod is in the fieldMaskPath but l.HttpMethod
// is not set it will be set to the value "GET".  If storage has a value
// for HttpRequestBody when l.HttpMethod is set to GET the update will fail.
// func (r *Repository) UpdateSSHCertificateCredentialLibrary(ctx context.Context, projectId string, l *SSHCertificateCredentialLibrary, version uint32, fieldMaskPaths []string, _ ...Option) (*CredentialLibrary, int, error) {
// 	const op = "vault.(Repository).UpdateSSHCertificateCredentialLibrary"
// 	if l == nil {
// 		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing SSHCertificateCredentialLibrary")
// 	}
// 	if l.SSHCertificateCredentialLibrary == nil {
// 		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing embedded SSHCertificateCredentialLibrary")
// 	}
// 	if l.PublicId == "" {
// 		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
// 	}
// 	if version == 0 {
// 		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
// 	}
// 	if projectId == "" {
// 		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
// 	}
// 	l = l.clone()

// 	for _, f := range fieldMaskPaths {
// 		switch {
// 		case strings.EqualFold(nameField, f):
// 		case strings.EqualFold(descriptionField, f):
// 		case strings.EqualFold(vaultPathField, f):
// 		// case strings.EqualFold(usernameField, f):

// 		default:
// 			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, f)
// 		}
// 	}
// 	var dbMask, nullFields []string
// 	dbMask, nullFields = dbw.BuildUpdatePaths(
// 		map[string]any{
// 			nameField:        l.Name,
// 			descriptionField: l.Description,
// 			vaultPathField:   l.VaultPath,
// 		},
// 		fieldMaskPaths,
// 		nil,
// 	)

// 	if len(dbMask) == 0 && len(nullFields) == 0 {
// 		return nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "missing field mask")
// 	}

// 	origLib, err := r.LookupCredentialLibrary(ctx, l.PublicId)
// 	switch {
// 	case err != nil:
// 		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
// 	case origLib == nil:
// 		return nil, db.NoRowsAffected, errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("credential library %s", l.PublicId))
// 	}

// 	var filteredDbMask, filteredNullFields []string
// 	for _, f := range dbMask {
// 		switch {
// 		case strings.EqualFold(MappingOverrideField, f):
// 		default:
// 			filteredDbMask = append(filteredDbMask, f)
// 		}
// 	}
// 	for _, f := range nullFields {
// 		switch {
// 		case strings.EqualFold(MappingOverrideField, f):
// 		default:
// 			filteredNullFields = append(filteredNullFields, f)
// 		}
// 	}

// 	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
// 	if err != nil {
// 		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt),
// 			errors.WithMsg("unable to get oplog wrapper"))
// 	}

// 	var rowsUpdated int
// 	var returnedCredentialLibrary *CredentialLibrary
// 	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
// 		func(rr db.Reader, w db.Writer) error {
// 			var msgs []*oplog.Message
// 			ticket, err := w.GetTicket(ctx, l)
// 			if err != nil {
// 				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
// 			}

// 			l := l.clone()
// 			var lOplogMsg oplog.Message

// 			// Update the credential library table
// 			switch {
// 			case len(filteredDbMask) == 0 && len(filteredNullFields) == 0:
// 				// the credential library's fields are not being updated,
// 				// just one of it's child objects, so we just need to
// 				// update the library's version.
// 				l.Version = version + 1
// 				rowsUpdated, err = w.Update(ctx, l, []string{"Version"}, nil, db.NewOplogMsg(&lOplogMsg), db.WithVersion(&version))
// 				if err != nil {
// 					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update credential library version"))
// 				}
// 				switch rowsUpdated {
// 				case 1:
// 				case 0:
// 					return nil
// 				default:
// 					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated credential library version and %d rows updated", rowsUpdated))
// 				}
// 			default:
// 				rowsUpdated, err = w.Update(ctx, l, filteredDbMask, filteredNullFields, db.NewOplogMsg(&lOplogMsg), db.WithVersion(&version))
// 				if err != nil {
// 					if errors.IsUniqueError(err) {
// 						return errors.New(ctx, errors.NotUnique, op,
// 							fmt.Sprintf("name %s already exists: %s", l.Name, l.PublicId))
// 					}
// 					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update credential library"))
// 				}
// 				switch rowsUpdated {
// 				case 1:
// 				case 0:
// 					return nil
// 				default:
// 					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated credential library and %d rows updated", rowsUpdated))
// 				}
// 			}
// 			msgs = append(msgs, &lOplogMsg)

// 			// Update a credential mapping override table if applicable
// 			if updateMappingOverride {
// 				// delete the current mapping override if it exists
// 				if origLib.MappingOverride != nil {
// 					var msg oplog.Message
// 					rowsDeleted, err := w.Delete(ctx, origLib.MappingOverride, db.NewOplogMsg(&msg))
// 					switch {
// 					case err != nil:
// 						return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete mapping override"))
// 					default:
// 						switch rowsDeleted {
// 						case 0, 1:
// 						default:
// 							return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("delete mapping override and %d rows deleted", rowsDeleted))
// 						}
// 					}
// 					msgs = append(msgs, &msg)
// 				}
// 				// insert a new mapping override if specified
// 				if l.MappingOverride != nil {
// 					var msg oplog.Message
// 					l.MappingOverride.setLibraryId(l.PublicId)
// 					if err := w.Create(ctx, l.MappingOverride, db.NewOplogMsg(&msg)); err != nil {
// 						return errors.Wrap(ctx, err, op)
// 					}
// 					msgs = append(msgs, &msg)
// 				}
// 			}

// 			metadata := l.oplog(oplog.OpType_OP_TYPE_UPDATE)
// 			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
// 				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
// 			}

// 			pl := allocListLookupLibrary()
// 			pl.PublicId = l.PublicId
// 			if err := rr.LookupByPublicId(ctx, pl); err != nil {
// 				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve updated credential library"))
// 			}
// 			returnedCredentialLibrary = pl.toCredentialLibrary()
// 			return nil
// 		},
// 	)

// 	if err != nil {
// 		if errors.IsUniqueError(err) {
// 			return nil, db.NoRowsAffected, errors.New(ctx, errors.NotUnique, op,
// 				fmt.Sprintf("name %s already exists: %s", l.Name, l.PublicId))
// 		}
// 		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(l.PublicId))
// 	}

// 	return returnedCredentialLibrary, rowsUpdated, nil
// }
