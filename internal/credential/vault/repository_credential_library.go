package vault

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
		return nil, errors.New(errors.InvalidParameter, op, "nil CredentialLibrary")
	}
	if l.CredentialLibrary == nil {
		return nil, errors.New(errors.InvalidParameter, op, "nil embedded l")
	}
	if l.StoreId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no store id")
	}
	if l.VaultPath == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no vault path")
	}
	if l.PublicId != "" {
		return nil, errors.New(errors.InvalidParameter, op, "public id not empty")
	}
	if scopeId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no scope id")
	}
	l = l.clone()

	id, err := newCredentialLibraryId()
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	l.PublicId = id

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var newCredentialLibrary *CredentialLibrary
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newCredentialLibrary = l.clone()
			err := w.Create(ctx, newCredentialLibrary, db.WithOplog(oplogWrapper, l.oplog(oplog.OpType_OP_TYPE_CREATE)))
			if err != nil {
				return errors.Wrap(err, op)
			}
			return nil
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("in credential store: %s: name %s already exists", l.StoreId, l.Name)))
		}
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("in credential store: %s", l.StoreId)))
	}
	return newCredentialLibrary, nil
}

// UpdateCredentialLibrary updates the repository entry for l.PublicId with
// the values in l for the fields listed in fieldMaskPaths. It returns a
// new CredentialLibrary containing the updated values and a count of the
// number of records updated. l is not changed.
//
// l must contain a valid PublicId. Only Name, Description, VaultPath,
// HttpMethod, and HttpRequestBody can be updated. If l.Name is set to a
// non-empty string, it must be unique within l.StoreId.
//
// An attribute of l will be set to NULL in the database if the attribute
// in l is the zero value and it is included in fieldMaskPaths.
func (r *Repository) UpdateCredentialLibrary(ctx context.Context, scopeId string, l *CredentialLibrary, version uint32, fieldMaskPaths []string, _ ...Option) (*CredentialLibrary, int, error) {
	const op = "vault.(Repository).UpdateCredentialLibrary"
	if l == nil {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing CredentialLibrary")
	}
	if l.CredentialLibrary == nil {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing embedded CredentialLibrary")
	}
	if l.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidPublicId, op, "missing public id")
	}
	if version == 0 {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing version")
	}
	if scopeId == "" {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing scope id")
	}

	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("Name", f):
		case strings.EqualFold("Description", f):
		case strings.EqualFold("VaultPath", f):
		case strings.EqualFold("HttpMethod", f):
		case strings.EqualFold("HttpRequestBody", f):
		default:
			return nil, db.NoRowsAffected, errors.New(errors.InvalidFieldMask, op, f)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"Name":            l.Name,
			"Description":     l.Description,
			"VaultPath":       l.VaultPath,
			"HttpMethod":      l.HttpMethod,
			"HttpRequestBody": l.HttpRequestBody,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(errors.EmptyFieldMask, op, "missing field mask")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithCode(errors.Encrypt),
			errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsUpdated int
	var returnedCredentialLibrary *CredentialLibrary
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedCredentialLibrary = l.clone()
			var err error
			rowsUpdated, err = w.Update(ctx, returnedCredentialLibrary, dbMask, nullFields,
				db.WithOplog(oplogWrapper, l.oplog(oplog.OpType_OP_TYPE_UPDATE)),
				db.WithVersion(&version))
			if err == nil && rowsUpdated > 1 {
				return errors.New(errors.MultipleRecords, op, "more than 1 resource would have been updated")
			}
			return err
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, db.NoRowsAffected, errors.New(errors.NotUnique, op,
				fmt.Sprintf("name %s already exists: %s", l.Name, l.PublicId))
		}
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(l.PublicId))
	}

	return returnedCredentialLibrary, rowsUpdated, nil
}

// LookupCredentialLibrary returns the CredentialLibrary for publicId.
// Returns nil, nil if no CredentialLibrary is found for publicId.
func (r *Repository) LookupCredentialLibrary(ctx context.Context, publicId string, _ ...Option) (*CredentialLibrary, error) {
	const op = "vault.(Repository).LookupCredentialLibrary"
	if publicId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no public id")
	}
	l := allocCredentialLibrary()
	l.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, l); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", publicId)))
	}
	return l, nil
}

// DeleteCredentialLibrary deletes publicId from the repository and returns
// the number of records deleted.
func (r *Repository) DeleteCredentialLibrary(ctx context.Context, scopeId string, publicId string, _ ...Option) (int, error) {
	const op = "vault.(Repository).DeleteCredentialLibrary"
	if publicId == "" {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "no public id")
	}
	if scopeId == "" {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "no scope id")
	}

	l := allocCredentialLibrary()
	l.PublicId = publicId

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			dl := l.clone()
			rowsDeleted, err = w.Delete(ctx, dl, db.WithOplog(oplogWrapper, l.oplog(oplog.OpType_OP_TYPE_DELETE)))
			if err == nil && rowsDeleted > 1 {
				return errors.New(errors.MultipleRecords, op, "more than 1 CredentialLibrary would have been deleted")
			}
			return err
		},
	)

	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("delete failed for %s", l.PublicId)))
	}

	return rowsDeleted, nil
}
