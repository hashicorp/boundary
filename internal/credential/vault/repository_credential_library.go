// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-secure-stdlib/strutil"
)

// CreateCredentialLibrary inserts l into the repository and returns a new
// CredentialLibrary containing the credential library's PublicId. l is not
// changed. l must contain a valid StoreId. l must not contain a PublicId.
// The PublicId is generated and assigned by this method.
//
// Both l.Name and l.Description are optional. If l.Name is set, it must be
// unique within l.StoreId.
//
// Both l.CreateTime and l.UpdateTime are ignored.
func (r *Repository) CreateCredentialLibrary(ctx context.Context, projectId string, l *CredentialLibrary, _ ...Option) (*CredentialLibrary, error) {
	const op = "vault.(Repository).CreateCredentialLibrary"
	if l == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil CredentialLibrary")
	}
	if l.CredentialLibrary == nil {
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
	l = l.clone()

	if l.HttpMethod == "" {
		l.HttpMethod = string(MethodGet)
	}

	if err := l.validate(ctx, op); err != nil {
		return nil, err // intentionally not wrapped.
	}

	id, err := newCredentialLibraryId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	l.setId(id)

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var newCredentialLibrary *CredentialLibrary
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			var msgs []*oplog.Message
			ticket, err := w.GetTicket(ctx, l)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			// insert credential library
			newCredentialLibrary = l.clone()
			var lOplogMsg oplog.Message
			if err := w.Create(ctx, newCredentialLibrary, db.NewOplogMsg(&lOplogMsg)); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			msgs = append(msgs, &lOplogMsg)

			// insert mapper override (if exists)
			if l.MappingOverride != nil {
				var msg oplog.Message
				if err := w.Create(ctx, newCredentialLibrary.MappingOverride, db.NewOplogMsg(&msg)); err != nil {
					return errors.Wrap(ctx, err, op)
				}
				newCredentialLibrary.MappingOverride.sanitize()
				msgs = append(msgs, &msg)
			}

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
	return newCredentialLibrary, nil
}

// UpdateCredentialLibrary updates the repository entry for l.PublicId with
// the values in l for the fields listed in fieldMaskPaths. It returns a
// new CredentialLibrary containing the updated values and a count of the
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
func (r *Repository) UpdateCredentialLibrary(ctx context.Context, projectId string, l *CredentialLibrary, version uint32, fieldMaskPaths []string, _ ...Option) (*CredentialLibrary, int, error) {
	const op = "vault.(Repository).UpdateCredentialLibrary"
	if l == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing CredentialLibrary")
	}
	if l.CredentialLibrary == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing embedded CredentialLibrary")
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

	var updateMappingOverride bool
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold(nameField, f):
		case strings.EqualFold(descriptionField, f):
		case strings.EqualFold(vaultPathField, f):
		case strings.EqualFold(httpMethodField, f):
		case strings.EqualFold(httpRequestBodyField, f):
		case strings.EqualFold(MappingOverrideField, f):
			updateMappingOverride = true
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, f)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbw.BuildUpdatePaths(
		map[string]any{
			nameField:            l.Name,
			descriptionField:     l.Description,
			vaultPathField:       l.VaultPath,
			httpMethodField:      l.HttpMethod,
			httpRequestBodyField: l.HttpRequestBody,
			MappingOverrideField: l.MappingOverride,
		},
		fieldMaskPaths,
		nil,
	)

	if strutil.StrListContains(nullFields, httpMethodField) {
		// GET is the default value for the HttpMethod field in
		// CredentialLibrary. The http_method column in the database does
		// not allow NULL values but it also does not define a default
		// value. Therefore, if the httpMethodField is in nullFields:
		// remove it from nullFields then add it to dbMask and set the
		// value to GET.
		dbMask = append(dbMask, httpMethodField)
		nullFields = strutil.StrListDelete(nullFields, httpMethodField)
		l.HttpMethod = string(MethodGet)
	}

	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "missing field mask")
	}

	origLib, err := r.LookupCredentialLibrary(ctx, l.PublicId)
	switch {
	case err != nil:
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	case origLib == nil:
		return nil, db.NoRowsAffected, errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("credential library %s", l.PublicId))
	case updateMappingOverride && !validMappingOverride(l.MappingOverride, origLib.CredentialType()):
		return nil, db.NoRowsAffected, errors.New(ctx, errors.VaultInvalidMappingOverride, op, "invalid mapping override for credential type")
	}

	var filteredDbMask, filteredNullFields []string
	for _, f := range dbMask {
		switch {
		case strings.EqualFold(MappingOverrideField, f):
		default:
			filteredDbMask = append(filteredDbMask, f)
		}
	}
	for _, f := range nullFields {
		switch {
		case strings.EqualFold(MappingOverrideField, f):
		default:
			filteredNullFields = append(filteredNullFields, f)
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt),
			errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsUpdated int
	var returnedCredentialLibrary *CredentialLibrary
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
			case len(filteredDbMask) == 0 && len(filteredNullFields) == 0:
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
				rowsUpdated, err = w.Update(ctx, l, filteredDbMask, filteredNullFields, db.NewOplogMsg(&lOplogMsg), db.WithVersion(&version))
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

			// Update a credential mapping override table if applicable
			if updateMappingOverride {
				// delete the current mapping override if it exists
				if origLib.MappingOverride != nil {
					var msg oplog.Message
					rowsDeleted, err := w.Delete(ctx, origLib.MappingOverride, db.NewOplogMsg(&msg))
					switch {
					case err != nil:
						return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete mapping override"))
					default:
						switch rowsDeleted {
						case 0, 1:
						default:
							return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("delete mapping override and %d rows deleted", rowsDeleted))
						}
					}
					msgs = append(msgs, &msg)
				}
				// insert a new mapping override if specified
				if l.MappingOverride != nil {
					var msg oplog.Message
					l.MappingOverride.setLibraryId(l.PublicId)
					if err := w.Create(ctx, l.MappingOverride, db.NewOplogMsg(&msg)); err != nil {
						return errors.Wrap(ctx, err, op)
					}
					msgs = append(msgs, &msg)
				}
			}

			metadata := l.oplog(oplog.OpType_OP_TYPE_UPDATE)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}

			pl := allocListLookupLibrary()
			pl.PublicId = l.PublicId
			if err := rr.LookupByPublicId(ctx, pl); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve updated credential library"))
			}
			returnedCredentialLibrary = pl.toCredentialLibrary()
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

// LookupCredentialLibrary returns the CredentialLibrary for publicId.
// Returns nil, nil if no CredentialLibrary is found for publicId.
func (r *Repository) LookupCredentialLibrary(ctx context.Context, publicId string, _ ...Option) (*CredentialLibrary, error) {
	const op = "vault.(Repository).LookupCredentialLibrary"
	if publicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	l := allocListLookupLibrary()
	l.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, l); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", publicId)))
	}
	return l.toCredentialLibrary(), nil
}

// listLookupLibrary is a credential library and any of library's credential
// mapping overrides. It does not include encrypted data and is safe to
// return external to boundary.
type listLookupLibrary struct {
	PublicId                      string `gorm:"primary_key"`
	StoreId                       string
	Name                          string
	Description                   string
	CreateTime                    *timestamp.Timestamp
	UpdateTime                    *timestamp.Timestamp
	Version                       uint32
	VaultPath                     string
	HttpMethod                    string
	HttpRequestBody               []byte
	CredentialType                string
	UsernameAttribute             string
	PasswordAttribute             string
	PrivateKeyAttribute           string
	PrivateKeyPassphraseAttribute string
}

func allocListLookupLibrary() *listLookupLibrary {
	return &listLookupLibrary{}
}

func (pl *listLookupLibrary) toCredentialLibrary() *CredentialLibrary {
	cl := allocCredentialLibrary()
	cl.PublicId = pl.PublicId
	cl.StoreId = pl.StoreId
	cl.Name = pl.Name
	cl.Description = pl.Description
	cl.CreateTime = pl.CreateTime
	cl.UpdateTime = pl.UpdateTime
	cl.Version = pl.Version
	cl.VaultPath = pl.VaultPath
	cl.HttpMethod = pl.HttpMethod
	cl.HttpRequestBody = pl.HttpRequestBody
	cl.CredentialLibrary.CredentialType = pl.CredentialType

	switch pl.CredentialType {
	case string(credential.UsernamePasswordType):
		if pl.UsernameAttribute != "" || pl.PasswordAttribute != "" {
			up := allocUsernamePasswordOverride()
			up.LibraryId = pl.PublicId
			up.UsernameAttribute = pl.UsernameAttribute
			up.PasswordAttribute = pl.PasswordAttribute
			up.sanitize()
			cl.MappingOverride = up
		}
	case string(credential.SshPrivateKeyType):
		if pl.UsernameAttribute != "" || pl.PrivateKeyAttribute != "" || pl.PrivateKeyPassphraseAttribute != "" {
			pk := allocSshPrivateKeyOverride()
			pk.LibraryId = pl.PublicId
			pk.UsernameAttribute = pl.UsernameAttribute
			pk.PrivateKeyAttribute = pl.PrivateKeyAttribute
			pk.PrivateKeyPassphraseAttribute = pl.PrivateKeyPassphraseAttribute
			pk.sanitize()
			cl.MappingOverride = pk
		}
	}
	return cl
}

// TableName returns the table name for gorm.
func (*listLookupLibrary) TableName() string { return "credential_vault_library_list_lookup" }

// GetPublicId returns the public id.
func (pl *listLookupLibrary) GetPublicId() string { return pl.PublicId }

// DeleteCredentialLibrary deletes publicId from the repository and returns
// the number of records deleted.
func (r *Repository) DeleteCredentialLibrary(ctx context.Context, projectId string, publicId string, _ ...Option) (int, error) {
	const op = "vault.(Repository).DeleteCredentialLibrary"
	if publicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	if projectId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no project id")
	}

	l := allocCredentialLibrary()
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

// listCredentialLibraries returns a slice of CredentialLibraries for the
// storeId. Supports the following options:
//   - credential.WithLimit
//   - credential.WithStartPageAfterItem
func (r *Repository) listCredentialLibraries(ctx context.Context, storeId string, opt ...credential.Option) ([]credential.Library, error) {
	const op = "vault.(Repository).listCredentialLibraries"
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
			sql.Named("after_item_update_time", opts.WithStartPageAfterItem.GetUpdateTime()),
			sql.Named("after_item_id", opts.WithStartPageAfterItem.GetPublicId()),
		)
		whereClause += " and (update_time > @after_item_update_time or (update_time = @after_item_update_time and public_id > @after_item_id))"
	}
	var vaultLibs []*CredentialLibrary
	if err := r.reader.SearchWhere(ctx, &vaultLibs, whereClause, args, db.WithLimit(limit), db.WithOrder(withOrder)); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	var libs []credential.Library
	for _, lib := range vaultLibs {
		libs = append(libs, lib)
	}
	return libs, nil
}

// estimatedLibraryCount returns an estimate of the number of Vault credential libraries
func (r *Repository) estimatedLibraryCount(ctx context.Context) (int, error) {
	const op = "vault.(Repository).estimatedLibraryCount"
	rows, err := r.reader.Query(ctx, estimateCountCredentialLibraries, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total Vault credential libraries"))
	}
	var count int
	for rows.Next() {
		if err := r.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total Vault credential libraries"))
		}
	}
	return count, nil
}

// listDeletedLibraryIds lists the public IDs of any credential libraries deleted since the timestamp provided.
// Supported options:
//   - credential.WithReaderWriter
func (r *Repository) listDeletedLibraryIds(ctx context.Context, since time.Time, opt ...credential.Option) ([]string, error) {
	const op = "vault.(Repository).listDeletedLibraryIds"
	opts, err := credential.GetOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	rdr := r.reader
	if opts.WithReader != nil {
		rdr = opts.WithReader
	}
	var deletedCredentialLibraries []*deletedCredentialLibrary
	if err := rdr.SearchWhere(ctx, &deletedCredentialLibraries, "delete_time >= ?", []any{since}); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted credential libraries"))
	}
	var credentialLibraryIds []string
	for _, cl := range deletedCredentialLibraries {
		credentialLibraryIds = append(credentialLibraryIds, cl.PublicId)
	}
	return credentialLibraryIds, nil
}
