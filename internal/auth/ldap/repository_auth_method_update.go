package ldap

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-secure-stdlib/strutil"
)

const (
	OperationalStateField     = "OperationalState"
	VersionField              = "Version"
	IsPrimaryAuthMethodField  = "IsPrimaryAuthMethod"
	NameField                 = "Name"
	DescriptionField          = "Description"
	StartTlsField             = "StartTls"
	InsecureTlsField          = "InsecureTls"
	DiscoverDnField           = "DiscoverDn"
	AnonGroupSearchField      = "AnonGroupSearch"
	UpnDomainField            = "UpnDomain"
	UrlsField                 = "Urls"
	UserDnField               = "UserDn"
	UserAttrField             = "UserAttr"
	UserFilterField           = "UserFilter"
	EnableGroupsField         = "EnableGroups"
	UseTokenGroupsField       = "UseTokenGroups"
	GroupDnField              = "GroupDn"
	GroupAttrField            = "GroupAttr"
	GroupFilterField          = "GroupFilter"
	CertificatesField         = "Certificates"
	ClientCertificateField    = "ClientCertificate"
	ClientCertificateKeyField = "ClientCertificateKey"
	BindDnField               = "BindDn"
	BindPasswordField         = "BindPassword"
)

// UpdateAuthMethod will retrieve the auth method from the repository,
// and update it based on the field masks provided.
//
// fieldMaskPaths provides field_mask.proto paths for fields that should
// be updated.  Fields will be set to NULL if the field is a
// zero value and included in fieldMask. Name, Description, StartTLs,
// DiscoverDn, AnonGroupSearch, UpnDomain, UserDn, UserAttr, UserFilter,
// GroupDn, GroupAttr, GroupFilter, ClientCertificateKey, ClientCertificate,
// BindDn and BindPassword are all updatable fields. The AuthMethod's Value
// Objects of Urls and Certificates are also updatable. If no updatable fields
// are included in the fieldMaskPaths, then an error is returned.
//
// No Options are currently supported.
func (r *Repository) UpdateAuthMethod(ctx context.Context, am *AuthMethod, version uint32, fieldMaskPaths []string, _ ...Option) (*AuthMethod, int, error) {
	const op = "ldap.(AuthMethod).Update"
	switch {
	case am == nil:
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing auth method")
	case am.AuthMethod == nil:
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing auth method store")
	case am.PublicId == "":
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if err := validateFieldMask(ctx, fieldMaskPaths); err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	dbMask, nullFields := dbw.BuildUpdatePaths(
		map[string]any{
			NameField:                 am.Name,
			DescriptionField:          am.Description,
			StartTlsField:             am.StartTls,
			InsecureTlsField:          am.InsecureTls,
			DiscoverDnField:           am.DiscoverDn,
			AnonGroupSearchField:      am.AnonGroupSearch,
			UpnDomainField:            am.UpnDomain,
			UserDnField:               am.UserDn,
			UserAttrField:             am.UserAttr,
			UserFilterField:           am.UserFilter,
			EnableGroupsField:         am.EnableGroups,
			UseTokenGroupsField:       am.UseTokenGroups,
			GroupDnField:              am.GroupDn,
			GroupAttrField:            am.GroupAttr,
			GroupFilterField:          am.GroupFilter,
			CertificatesField:         am.Certificates,
			ClientCertificateField:    am.ClientCertificate,
			ClientCertificateKeyField: am.ClientCertificateKey,
			BindDnField:               am.BindDn,
			BindPasswordField:         am.BindPassword,
			UrlsField:                 am.Urls,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "empty field mask")
	}
	if strutil.StrListContains(nullFields, UrlsField) {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing urls (you cannot delete all of them; there must be at least one)")
	}

	origAm, err := r.LookupAuthMethod(ctx, am.PublicId)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	if origAm == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("auth method %q", am.PublicId))
	}
	// there's no reason to continue if another controller has already updated this auth method.
	if origAm.Version != version {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.VersionMismatch, op, fmt.Sprintf("update version %d doesn't match db version %d", version, origAm.Version))
	}

	dbWrapper, err := r.kms.GetWrapper(ctx, origAm.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}
	addUrls, deleteUrls, err := valueObjectChanges(ctx, origAm.PublicId, UrlVO, am.Urls, origAm.Urls, dbMask, nullFields)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	addCerts, deleteCerts, err := valueObjectChanges(ctx, origAm.PublicId, CertificateVO, am.Certificates, origAm.Certificates, dbMask, nullFields)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	var addUserSearchConf, deleteUserSearchConf any
	if strListContainsOneOf(dbMask, UserDnField, UserAttrField, UserAttrField) {
		addUserSearchConf, err = NewUserEntrySearchConf(ctx, am.PublicId, WithUserDn(ctx, am.UserDn), WithUserAttr(ctx, am.UserAttr), WithUserFilter(ctx, am.UserFilter))
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
	}
	combinedMasks := append(dbMask, nullFields...)
	if strListContainsOneOf(combinedMasks, UserDnField, UserAttrField, UserAttrField) {
		deleteUserSearchConf, err = NewUserEntrySearchConf(ctx, am.PublicId, WithUserDn(ctx, origAm.UserDn), WithUserAttr(ctx, origAm.UserAttr), WithUserFilter(ctx, origAm.UserFilter))
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
	}
	var addGroupSearchConf, deleteGroupSearchConf any
	if strListContainsOneOf(dbMask, GroupDnField, GroupAttrField, GroupAttrField) {
		addGroupSearchConf, err = NewGroupEntrySearchConf(ctx, am.PublicId, WithGroupDn(ctx, am.GroupDn), WithGroupAttr(ctx, am.GroupAttr), WithGroupFilter(ctx, am.GroupFilter))
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
	}
	if strListContainsOneOf(combinedMasks, GroupDnField, GroupAttrField, GroupAttrField) {
		deleteGroupSearchConf, err = NewGroupEntrySearchConf(ctx, am.PublicId, WithGroupDn(ctx, origAm.GroupDn), WithGroupAttr(ctx, origAm.GroupAttr), WithGroupFilter(ctx, origAm.GroupFilter))
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
	}
	var addClientCert, deleteClientCert any
	if strListContainsOneOf(dbMask, ClientCertificateField, ClientCertificateKeyField) {
		cc, err := NewClientCertificate(ctx, am.PublicId, am.ClientCertificateKey, am.ClientCertificate)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
		if err := cc.encrypt(ctx, dbWrapper); err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
		addClientCert = cc
	}
	if strListContainsOneOf(combinedMasks, ClientCertificateField, ClientCertificateKeyField) {
		deleteClientCert, err = NewClientCertificate(ctx, am.PublicId, origAm.ClientCertificateKey, origAm.ClientCertificate)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
	}
	var addBindCred, deleteBindCred any
	if strListContainsOneOf(dbMask, BindDnField, BindPasswordField) {
		bc, err := NewBindCredential(ctx, am.PublicId, am.BindDn, []byte(am.BindPassword))
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
		if err := bc.encrypt(ctx, dbWrapper); err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
		addBindCred = bc
	}
	if strListContainsOneOf(combinedMasks, BindDnField, BindPasswordField) {
		deleteBindCred, err = NewBindCredential(ctx, am.PublicId, origAm.BindDn, []byte(origAm.BindPassword))
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
	}

	var filteredDbMask, filteredNullFields []string
	for _, f := range dbMask {
		switch f {
		case
			UrlsField,
			CertificatesField,
			UserDnField, UserAttrField, UserFilterField,
			GroupDnField, GroupAttrField, GroupFilterField,
			ClientCertificateField, ClientCertificateKeyField,
			BindDnField, BindPasswordField:
			continue
		default:
			filteredDbMask = append(filteredDbMask, f)
		}
	}
	for _, f := range nullFields {
		switch f {
		case
			StartTlsField, InsecureTlsField, DiscoverDnField, AnonGroupSearchField, EnableGroupsField, UseTokenGroupsField,
			UrlsField,
			CertificatesField,
			UserDnField, UserAttrField, UserFilterField,
			GroupDnField, GroupAttrField, GroupFilterField,
			ClientCertificateField, ClientCertificateKeyField,
			BindDnField, BindPasswordField:
			continue
		default:
			filteredNullFields = append(filteredNullFields, f)
		}
	}

	// handle no changes...
	if len(filteredDbMask) == 0 &&
		len(filteredNullFields) == 0 &&
		len(addUrls) == 0 &&
		len(deleteUrls) == 0 &&
		len(addCerts) == 0 &&
		len(deleteCerts) == 0 &&
		addUserSearchConf == nil &&
		deleteUserSearchConf == nil &&
		addGroupSearchConf == nil &&
		deleteGroupSearchConf == nil &&
		addClientCert == nil &&
		deleteClientCert == nil &&
		addBindCred == nil &&
		deleteBindCred == nil {
		return origAm, db.NoRowsAffected, nil
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, origAm.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	var updatedAm *AuthMethod
	var rowsUpdated int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 7) // AuthMethod, Algs*2, Certs*2, Audiences*2
			ticket, err := w.GetTicket(ctx, am)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			var authMethodOplogMsg oplog.Message
			switch {
			case len(filteredDbMask) == 0 && len(filteredNullFields) == 0:
				// the auth method's fields are not being updated, just it's value objects, so we need to just update the auth
				// method's version.
				updatedAm = am.clone()
				updatedAm.Version = uint32(version) + 1
				rowsUpdated, err = w.Update(ctx, updatedAm, []string{VersionField}, nil, db.NewOplogMsg(&authMethodOplogMsg), db.WithVersion(&version))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update auth method version"))
				}
				if rowsUpdated != 1 {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated auth method version and %d rows updated", rowsUpdated))
				}
			default:
				updatedAm = am.clone()
				rowsUpdated, err = w.Update(ctx, updatedAm, filteredDbMask, filteredNullFields, db.NewOplogMsg(&authMethodOplogMsg), db.WithVersion(&version))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update auth method"))
				}
				if rowsUpdated != 1 {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated auth method and %d rows updated", rowsUpdated))
				}
			}
			msgs = append(msgs, &authMethodOplogMsg)

			if len(deleteCerts) > 0 {
				deleteCertOplogMsgs := make([]*oplog.Message, 0, len(deleteCerts))
				rowsDeleted, err := w.DeleteItems(ctx, deleteCerts, db.NewOplogMsgs(&deleteCertOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete certificates"))
				}
				if rowsDeleted != len(deleteCerts) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("certificates deleted %d did not match request for %d", rowsDeleted, len(deleteCerts)))
				}
				msgs = append(msgs, deleteCertOplogMsgs...)
			}
			if len(addCerts) > 0 {
				addCertsOplogMsgs := make([]*oplog.Message, 0, len(addCerts))
				if err := w.CreateItems(ctx, addCerts, db.NewOplogMsgs(&addCertsOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add certificates"))
				}
				msgs = append(msgs, addCertsOplogMsgs...)
			}

			if len(deleteUrls) > 0 {
				deleteAudsOplogMsgs := make([]*oplog.Message, 0, len(deleteUrls))
				rowsDeleted, err := w.DeleteItems(ctx, deleteUrls, db.NewOplogMsgs(&deleteAudsOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete URLs"))
				}
				if rowsDeleted != len(deleteUrls) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("urls deleted %d did not match request for %d", rowsDeleted, len(deleteUrls)))
				}
				msgs = append(msgs, deleteAudsOplogMsgs...)
			}
			if len(addUrls) > 0 {
				addUrlsOplogMsgs := make([]*oplog.Message, 0, len(addUrls))
				if err := w.CreateItems(ctx, addUrls, db.NewOplogMsgs(&addUrlsOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add urls"))
				}
				msgs = append(msgs, addUrlsOplogMsgs...)
			}

			if deleteUserSearchConf != nil {
				var deleteUserSearchConfMsg oplog.Message
				rowsDeleted, err := w.Delete(ctx, deleteUserSearchConf, db.NewOplogMsg(&deleteUserSearchConfMsg))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete user search conf"))
				}
				if rowsDeleted != 1 {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("user search conf deleted %d did not match request for 1", rowsDeleted))
				}
				msgs = append(msgs, &deleteUserSearchConfMsg)
			}
			if addUserSearchConf != nil {
				var addUserSearchConfOplogMsg oplog.Message
				if err := w.Create(ctx, addUserSearchConf, db.NewOplogMsg(&addUserSearchConfOplogMsg)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add user search conf"))
				}
				msgs = append(msgs, &addUserSearchConfOplogMsg)
			}

			if deleteGroupSearchConf != nil {
				var deleteGroupSearchConfMsg oplog.Message
				rowsDeleted, err := w.Delete(ctx, deleteGroupSearchConf, db.NewOplogMsg(&deleteGroupSearchConfMsg))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete group search conf"))
				}
				if rowsDeleted != 1 {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("group search conf deleted %d did not match request for 1", rowsDeleted))
				}
				msgs = append(msgs, &deleteGroupSearchConfMsg)
			}
			if addGroupSearchConf != nil {
				var addGroupSearchConfOplogMsg oplog.Message
				if err := w.Create(ctx, addGroupSearchConf, db.NewOplogMsg(&addGroupSearchConfOplogMsg)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add group search conf"))
				}
				msgs = append(msgs, &addGroupSearchConfOplogMsg)
			}

			if deleteClientCert != nil {
				var deleteClientCertMsg oplog.Message
				rowsDeleted, err := w.Delete(ctx, deleteClientCert, db.NewOplogMsg(&deleteClientCertMsg))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete client cert"))
				}
				if rowsDeleted != 1 {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("client cert deleted %d did not match request for 1", rowsDeleted))
				}
				msgs = append(msgs, &deleteClientCertMsg)
			}
			if addClientCert != nil {
				var addClientCertOplogMsg oplog.Message
				if err := w.Create(ctx, addClientCert, db.NewOplogMsg(&addClientCertOplogMsg)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add client cert"))
				}
				msgs = append(msgs, &addClientCertOplogMsg)
			}

			if deleteBindCred != nil {
				var deleteBindCredMsg oplog.Message
				rowsDeleted, err := w.Delete(ctx, deleteBindCred, db.NewOplogMsg(&deleteBindCredMsg))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete bind credential conf"))
				}
				if rowsDeleted != 1 {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("bind credential deleted %d did not match request for 1", rowsDeleted))
				}
				msgs = append(msgs, &deleteBindCredMsg)
			}
			if addBindCred != nil {
				var addBindCredOplogMsg oplog.Message
				if err := w.Create(ctx, addBindCred, db.NewOplogMsg(&addBindCredOplogMsg)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add bind credential"))
				}
				msgs = append(msgs, &addBindCredOplogMsg)
			}

			metadata, err := updatedAm.oplog(ctx, oplog.OpType_OP_TYPE_UPDATE)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to generate oplog metadata"))
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}
			// we need a new repo, that's using the same reader/writer as this TxHandler
			txRepo := &Repository{
				reader: reader,
				writer: w,
				kms:    r.kms,
				// intentionally not setting the defaultLimit, so we'll get all
				// the account ids without a limit
			}
			updatedAm, err = txRepo.lookupAuthMethod(ctx, updatedAm.PublicId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to lookup auth method after update"))
			}
			if updatedAm == nil {
				return errors.New(ctx, errors.RecordNotFound, op, "unable to lookup auth method after update")
			}
			return nil
		},
	)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return updatedAm, rowsUpdated, nil
}

// validateFieldMasks ensures that all the fields in the mask are updatable
func validateFieldMask(ctx context.Context, fieldMaskPaths []string) error {
	const op = "ldap.validateFieldMasks"
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold(NameField, f):
		case strings.EqualFold(DescriptionField, f):
		case strings.EqualFold(StartTlsField, f):
		case strings.EqualFold(InsecureTlsField, f):
		case strings.EqualFold(DiscoverDnField, f):
		case strings.EqualFold(AnonGroupSearchField, f):
		case strings.EqualFold(UpnDomainField, f):
		case strings.EqualFold(UserDnField, f):
		case strings.EqualFold(UserAttrField, f):
		case strings.EqualFold(UserFilterField, f):
		case strings.EqualFold(EnableGroupsField, f):
		case strings.EqualFold(UseTokenGroupsField, f):
		case strings.EqualFold(GroupDnField, f):
		case strings.EqualFold(GroupAttrField, f):
		case strings.EqualFold(GroupFilterField, f):
		case strings.EqualFold(CertificatesField, f):
		case strings.EqualFold(ClientCertificateField, f):
		case strings.EqualFold(ClientCertificateKeyField, f):
		case strings.EqualFold(BindDnField, f):
		case strings.EqualFold(BindPasswordField, f):
		case strings.EqualFold(UrlsField, f):
		default:
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid field mask: %q", f))
		}
	}
	return nil
}

// voName represents the names of auth method value objects
type voName string

const (
	CertificateVO voName = "Certificates"
	UrlVO         voName = "Urls"
)

// validVoName decides if the name is valid
func validVoName(name voName) bool {
	switch name {
	case CertificateVO, UrlVO:
		return true
	default:
		return false
	}
}

// factoryFunc defines a func type for value object factories
type factoryFunc func(ctx context.Context, publicId string, idx int, i any) (any, error)

// supportedFactories are the currently supported factoryFunc for value objects
var supportedFactories = map[voName]factoryFunc{
	CertificateVO: func(ctx context.Context, publicId string, idx int, i any) (any, error) {
		str := fmt.Sprintf("%s", i)
		return NewCertificate(ctx, publicId, str)
	},
	UrlVO: func(ctx context.Context, publicId string, idx int, i any) (any, error) {
		u, err := url.Parse(fmt.Sprintf("%s", i))
		if err != nil {
			return nil, errors.Wrap(ctx, err, "ldap.urlFactory")
		}
		return NewUrl(ctx, publicId, idx+1, u)
	},
}

// valueObjectChanges takes the new and old list of VOs (value objects) and
// using the dbMasks/nullFields it will return lists of VOs which need to be
// added and deleted in order to reconcile auth method's value objects.
func valueObjectChanges(
	ctx context.Context,
	publicId string,
	valueObjectName voName,
	newVOs,
	oldVOs,
	dbMask,
	nullFields []string,
) (add []any, del []any, e error) {
	const op = "ldap.valueObjectChanges"
	switch {
	case publicId == "":
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	case !validVoName(valueObjectName):
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid value object name: %s", valueObjectName))
	case !strutil.StrListContains(dbMask, string(valueObjectName)) && !strutil.StrListContains(nullFields, string(valueObjectName)):
		return nil, nil, nil
	case len(strutil.RemoveDuplicates(newVOs, false)) != len(newVOs):
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("duplicate new %s", valueObjectName))
	case len(strutil.RemoveDuplicates(oldVOs, false)) != len(oldVOs):
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("duplicate old %s", valueObjectName))
	}

	factory, ok := supportedFactories[valueObjectName]
	if !ok {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unsupported factory for value object: %s", valueObjectName))
	}

	foundVOs := map[string]int{}
	for i, a := range oldVOs {
		foundVOs[a] = i
	}
	var adds []any
	var deletes []any
	if strutil.StrListContains(nullFields, string(valueObjectName)) {
		deletes = make([]any, 0, len(oldVOs))
		for i, v := range oldVOs {
			deleteObj, err := factory(ctx, publicId, i, v)
			if err != nil {
				return nil, nil, errors.Wrap(ctx, err, op)
			}
			deletes = append(deletes, deleteObj)
			delete(foundVOs, v)
		}
	}
	if strutil.StrListContains(dbMask, string(valueObjectName)) {
		adds = make([]any, 0, len(newVOs))
		for i, v := range newVOs {
			if _, ok := foundVOs[v]; ok {
				delete(foundVOs, v)
				continue
			}
			obj, err := factory(ctx, publicId, i, v)
			if err != nil {
				return nil, nil, errors.Wrap(ctx, err, op)
			}
			adds = append(adds, obj)
			delete(foundVOs, v)
		}
	}
	if len(foundVOs) > 0 {
		for v := range foundVOs {
			obj, err := factory(ctx, publicId, foundVOs[v], v)
			if err != nil {
				return nil, nil, errors.Wrap(ctx, err, op)
			}
			deletes = append(deletes, obj)
			delete(foundVOs, v)
		}
	}
	return adds, deletes, nil
}

func strListContainsOneOf(haystack []string, needles ...string) bool {
	for _, item := range haystack {
		for _, n := range needles {
			if item == n {
				return true
			}
		}
	}
	return false
}
