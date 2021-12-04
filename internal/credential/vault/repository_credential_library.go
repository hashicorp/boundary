package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
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
func (r *Repository) CreateCredentialLibrary(ctx context.Context, scopeId string, l *CredentialLibrary, _ ...Option) (*CredentialLibrary, error) {
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
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	}
	l = l.clone()

	if l.HttpMethod == "" {
		l.HttpMethod = string(MethodGet)
	}

	if err := l.validate(ctx, op); err != nil {
		return nil, err // intentionally not wrapped.
	}

	id, err := newCredentialLibraryId()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	l.setId(id)

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var newCredentialLibrary *CredentialLibrary
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			var msgs []*oplog.Message
			ticket, err := w.GetTicket(l)
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
// HttpMethod, HttpRequestBody, UsernameAttribute, and PasswordAttribute
// can be updated. If l.Name is set to a non-empty string, it must be
// unique within l.StoreId.
//
// An attribute of l will be set to NULL in the database if the attribute
// in l is the zero value and it is included in fieldMaskPaths except for
// HttpMethod. If HttpMethod is in the fieldMaskPath but l.HttpMethod is
// not set it will be set to the value "GET". If storage has a value for
// HttpRequestBody when l.HttpMethod is set to GET the update will fail.
func (r *Repository) UpdateCredentialLibrary(ctx context.Context, scopeId string, l *CredentialLibrary, version uint32, fieldMaskPaths []string, _ ...Option) (*CredentialLibrary, int, error) {
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
	if scopeId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
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
		case strings.EqualFold(usernameAttributeField, f), strings.EqualFold(passwordAttributeField, f):
			updateMappingOverride = true
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, f)
		}
	}

	fieldValues := map[string]interface{}{
		nameField:            l.Name,
		descriptionField:     l.Description,
		vaultPathField:       l.VaultPath,
		httpMethodField:      l.HttpMethod,
		httpRequestBodyField: l.HttpRequestBody,
	}

	if updateMappingOverride {
		switch m := l.MappingOverride.(type) {
		case nil:
			fieldValues[usernameAttributeField] = ""
			fieldValues[passwordAttributeField] = ""
		case *UserPasswordOverride:
			fieldValues[usernameAttributeField] = m.UsernameAttribute
			fieldValues[passwordAttributeField] = m.PasswordAttribute
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.VaultInvalidMappingOverride, op, "Unknown mapping override")
		}
	}

	dbMask, nullFields := dbcommon.BuildUpdatePaths(fieldValues, fieldMaskPaths, nil)

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
	case origLib.Version != version:
		return nil, db.NoRowsAffected, errors.New(ctx, errors.VersionMismatch, op, fmt.Sprintf("update version %d does not match db version %d", version, origLib.Version))
	case updateMappingOverride && !validMappingOverride(l.MappingOverride, origLib.CredentialType()):
		return nil, db.NoRowsAffected, errors.New(ctx, errors.VaultInvalidMappingOverride, op, "invalid mapping override for credential type")
	}

	var filteredDbMask, filteredNullFields []string
	mappingOverrideDbMask := make(map[string]bool)
	for _, f := range dbMask {
		switch {
		case strings.EqualFold(usernameAttributeField, f):
			mappingOverrideDbMask[usernameAttributeField] = true
		case strings.EqualFold(passwordAttributeField, f):
			mappingOverrideDbMask[passwordAttributeField] = true
		default:
			filteredDbMask = append(filteredDbMask, f)
		}
	}
	for _, f := range nullFields {
		switch {
		case strings.EqualFold(usernameAttributeField, f), strings.EqualFold(passwordAttributeField, f):
		default:
			filteredNullFields = append(filteredNullFields, f)
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt),
			errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsUpdated int
	var returnedCredentialLibrary *CredentialLibrary
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(rr db.Reader, w db.Writer) error {
			var msgs []*oplog.Message
			ticket, err := w.GetTicket(l)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			l := l.clone()
			var lOplogMsg oplog.Message

			// Update the credential library table
			switch {
			case len(filteredDbMask) == 0 && len(filteredNullFields) == 0:
				// the credential library's fields are not being updated,
				// just one of its child objects, so we just need to
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
			if updateMappingOverride {
				chg, err := calcMappingOverrideChange(op, origLib, l, fieldMaskPaths)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to calculate change to mapping override"))
				}
				msg, err := chg(ctx, w)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to change mapping override"))
				}
				msgs = append(msgs, msg)
			}
			metadata := l.oplog(oplog.OpType_OP_TYPE_UPDATE)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}

			pl := allocPublicLibrary()
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

type changeFunc func(ctx context.Context, w db.Writer) (*oplog.Message, error)

func calcMappingOverrideChange(op errors.Op, ol, nl *CredentialLibrary, dbMask []string) (changeFunc, error) {
	om, nm := ol.MappingOverride, nl.MappingOverride
	if om == nil && nm == nil {
		return noChange, nil
	}

	insertFn := func(mo MappingOverride) changeFunc {
		mo.setLibraryId(ol.PublicId)
		return func(ctx context.Context, w db.Writer) (*oplog.Message, error) {
			var msg oplog.Message
			if err := w.Create(ctx, mo, db.NewOplogMsg(&msg)); err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			return &msg, nil
		}
	}

	deleteFn := func(mo MappingOverride) changeFunc {
		mo.setLibraryId(ol.PublicId)
		return func(ctx context.Context, w db.Writer) (*oplog.Message, error) {
			var msg oplog.Message
			rowsDeleted, err := w.Delete(ctx, mo, db.NewOplogMsg(&msg))
			switch {
			case err != nil:
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete mapping override"))
			default:
				switch rowsDeleted {
				case 0, 1:
				default:
					return nil, errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("delete mapping override and %d rows deleted", rowsDeleted))
				}
			}
			return &msg, nil
		}
	}

	updateFn := func(mo MappingOverride, dbMask []string) changeFunc {
		mo.setLibraryId(ol.PublicId)
		return func(ctx context.Context, w db.Writer) (*oplog.Message, error) {
			var msg oplog.Message
			rowsUpdated, err := w.Update(ctx, mo, dbMask, nil, db.NewOplogMsg(&msg))
			switch {
			case err != nil:
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update mapping override"))
			default:
				switch rowsUpdated {
				case 0, 1:
				default:
					return nil, errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("update mapping override and %d rows updated", rowsUpdated))
				}
			}
			return &msg, nil
		}
	}

	mappingOverrideMask := make(map[string]bool)
	for _, f := range dbMask {
		switch {
		case strings.EqualFold(usernameAttributeField, f):
			mappingOverrideMask[usernameAttributeField] = true
		case strings.EqualFold(passwordAttributeField, f):
			mappingOverrideMask[passwordAttributeField] = true
		}
	}

	switch {
	case om == nil && nm != nil:
		nmp, ok := nm.(*UserPasswordOverride)
		if !ok {
			return nil, fmt.Errorf("unexpected mapping override type %T: %v", nm, nm)
		}
		dmp := allocUserPasswordOverride()
		if mappingOverrideMask[usernameAttributeField] {
			dmp.setUsernameAttribute(nmp.UsernameAttribute)
		}
		if mappingOverrideMask[passwordAttributeField] {
			dmp.setPasswordAttribute(nmp.PasswordAttribute)
		}
		if dmp.UsernameAttribute == "" && dmp.PasswordAttribute == "" {
			return noChange, nil
		}
		return insertFn(dmp), nil
	case om != nil && nm == nil:
		// delete attributes in dbmask
		dm := om.clone()
		dmp, ok := dm.(*UserPasswordOverride)
		if !ok {
			return nil, fmt.Errorf("unexpected mapping override type %T: %v", dm, dm)
		}
		var mask []string
		if mappingOverrideMask[usernameAttributeField] {
			mask = append(mask, usernameAttributeField)
			dmp.deleteUsernameAttribute()
		}
		if mappingOverrideMask[passwordAttributeField] {
			mask = append(mask, passwordAttributeField)
			dmp.deletePasswordAttribute()
		}
		if dmp.UsernameAttribute == noOverride && dmp.PasswordAttribute == noOverride {
			return deleteFn(dmp), nil
		}
		return updateFn(dmp, mask), nil
	case om != nil && nm != nil:
		// delete or update
		dm := om.clone()
		dmp, ok := dm.(*UserPasswordOverride)
		if !ok {
			return nil, fmt.Errorf("unexpected mapping override type %T: %v", dm, dm)
		}
		nmp, ok := nm.(*UserPasswordOverride)
		if !ok {
			return nil, fmt.Errorf("unexpected mapping override type %T: %v", nm, nm)
		}
		var mask []string
		if mappingOverrideMask[usernameAttributeField] {
			mask = append(mask, usernameAttributeField)
			switch nmp.UsernameAttribute {
			case "":
				dmp.deleteUsernameAttribute()
			default:
				dmp.setUsernameAttribute(nmp.UsernameAttribute)
			}
		}
		if mappingOverrideMask[passwordAttributeField] {
			mask = append(mask, passwordAttributeField)
			switch nmp.PasswordAttribute {
			case "":
				dmp.deletePasswordAttribute()
			default:
				dmp.setPasswordAttribute(nmp.PasswordAttribute)
			}
		}
		if dmp.UsernameAttribute == noOverride && dmp.PasswordAttribute == noOverride {
			return deleteFn(dmp), nil
		}
		return updateFn(dmp, mask), nil
	}
	return noChange, nil
}

func noChange(_ context.Context, _ db.Writer) (*oplog.Message, error) {
	return nil, nil
}

// LookupCredentialLibrary returns the CredentialLibrary for publicId.
// Returns nil, nil if no CredentialLibrary is found for publicId.
func (r *Repository) LookupCredentialLibrary(ctx context.Context, publicId string, _ ...Option) (*CredentialLibrary, error) {
	const op = "vault.(Repository).LookupCredentialLibrary"
	if publicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	l := allocPublicLibrary()
	l.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, l); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", publicId)))
	}
	return l.toCredentialLibrary(), nil
}

type publicLibrary struct {
	PublicId          string `gorm:"primary_key"`
	StoreId           string
	Name              string
	Description       string
	CreateTime        *timestamp.Timestamp
	UpdateTime        *timestamp.Timestamp
	Version           uint32
	VaultPath         string
	HttpMethod        string
	HttpRequestBody   []byte
	CredentialType    string
	UsernameAttribute string
	PasswordAttribute string
}

func allocPublicLibrary() *publicLibrary {
	return &publicLibrary{}
}

func (pl *publicLibrary) toCredentialLibrary() *CredentialLibrary {
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

	if pl.UsernameAttribute != "" || pl.PasswordAttribute != "" {
		up := allocUserPasswordOverride()
		up.LibraryId = pl.PublicId
		up.UsernameAttribute = pl.UsernameAttribute
		up.PasswordAttribute = pl.PasswordAttribute
		up.sanitize()
		cl.MappingOverride = up
	}
	return cl
}

// TableName returns the table name for gorm.
func (_ *publicLibrary) TableName() string { return "credential_vault_library_public" }

// GetPublicId returns the public id.
func (pl *publicLibrary) GetPublicId() string { return pl.PublicId }

// DeleteCredentialLibrary deletes publicId from the repository and returns
// the number of records deleted.
func (r *Repository) DeleteCredentialLibrary(ctx context.Context, scopeId string, publicId string, _ ...Option) (int, error) {
	const op = "vault.(Repository).DeleteCredentialLibrary"
	if publicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	if scopeId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	}

	l := allocCredentialLibrary()
	l.PublicId = publicId

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
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

// ListCredentialLibraries returns a slice of CredentialLibraries for the
// storeId. WithLimit is the only option supported.
func (r *Repository) ListCredentialLibraries(ctx context.Context, storeId string, opt ...Option) ([]*CredentialLibrary, error) {
	const op = "vault.(Repository).ListCredentialLibraries"
	if storeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no storeId")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var libs []*CredentialLibrary
	err := r.reader.SearchWhere(ctx, &libs, "store_id = ?", []interface{}{storeId}, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return libs, nil
}
