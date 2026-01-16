// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
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
	AccountAttributeMapsField = "AccountAttributeMaps"
	GroupNamesField           = "GroupNames"
	DerefAliasesField         = "DereferenceAliases"
	MaximumPageSizeField      = "MaximumPageSize"
)

// isEmpty returns true if all the args are empty.  Only supports checking
// strings and pointers, all other types are assumed to be empty.
func isEmpty(args ...any) bool {
	for _, i := range args {
		switch v := reflect.ValueOf(i); v.Kind() {
		case reflect.Pointer:
			if !v.IsNil() {
				return false
			}
		case reflect.String:
			if v.String() != "" {
				return false
			}
		}
	}
	return true
}

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
			OperationalStateField:     am.OperationalState,
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
			AccountAttributeMapsField: am.AccountAttributeMaps,
			DerefAliasesField:         am.DereferenceAliases,
			MaximumPageSizeField:      am.MaximumPageSize,
		},
		fieldMaskPaths,
		[]string{
			StartTlsField,
			InsecureTlsField,
			DiscoverDnField,
			AnonGroupSearchField,
			EnableGroupsField,
			UseTokenGroupsField,
			MaximumPageSizeField,
		},
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "empty field mask")
	}
	if strutil.StrListContains(nullFields, UrlsField) {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing urls (you cannot delete all of them; there must be at least one)")
	}

	origAm, err := r.LookupAuthMethod(ctx, am.PublicId)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("%q auth method not found", am.PublicId))
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
	au, du, err := valueObjectChanges(ctx, origAm.PublicId, UrlVO, am.Urls, origAm.Urls, dbMask, nullFields)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update urls"))
	}
	addUrls := []*Url{}
	for _, u := range au {
		addUrls = append(addUrls, u.(*Url))
	}
	deleteUrls := []*Url{}
	for _, u := range du {
		deleteUrls = append(deleteUrls, u.(*Url))
	}
	ac, dc, err := valueObjectChanges(ctx, origAm.PublicId, CertificateVO, am.Certificates, origAm.Certificates, dbMask, nullFields)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update certificates"))
	}
	deleteCerts := []*Certificate{}
	for _, c := range dc {
		deleteCerts = append(deleteCerts, c.(*Certificate))
	}
	addCerts := []*Certificate{}
	for _, c := range ac {
		addCerts = append(addCerts, c.(*Certificate))
	}
	addM, deleteM, err := valueObjectChanges(ctx, origAm.PublicId, AccountAttributeMapsVO, am.AccountAttributeMaps, origAm.AccountAttributeMaps, dbMask, nullFields)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update account attribute maps"))
	}
	addMaps := []*AccountAttributeMap{}
	for _, m := range addM {
		addMaps = append(addMaps, m.(*AccountAttributeMap))
	}
	deleteMaps := []*AccountAttributeMap{}
	for _, m := range deleteM {
		deleteMaps = append(deleteMaps, m.(*AccountAttributeMap))
	}

	combinedMasks := append(dbMask, nullFields...)

	var addUserSearchConf, deleteUserSearchConf any
	if strListContainsOneOf(combinedMasks, UserDnField, UserAttrField, UserFilterField) {
		if !isEmpty(origAm.UserDn, origAm.UserAttr, origAm.UserFilter) {
			usc := allocUserEntrySearchConf()
			usc.LdapMethodId = am.PublicId
			deleteUserSearchConf = usc
		}
		userDn := origAm.UserDn
		switch {
		case strutil.StrListContains(dbMask, UserDnField):
			userDn = am.UserDn
		case strutil.StrListContains(nullFields, UserDnField):
			userDn = ""
		}
		userAttr := origAm.UserAttr
		switch {
		case strutil.StrListContains(dbMask, UserAttrField):
			userAttr = am.UserAttr
		case strutil.StrListContains(nullFields, UserAttrField):
			userAttr = ""
		}
		userFilter := origAm.UserFilter
		switch {
		case strutil.StrListContains(dbMask, UserFilterField):
			userFilter = am.UserFilter
		case strutil.StrListContains(nullFields, UserFilterField):
			userFilter = ""
		}
		if !isEmpty(userDn, userAttr, userFilter) {
			addUserSearchConf, err = NewUserEntrySearchConf(ctx, am.PublicId, WithUserDn(ctx, userDn), WithUserAttr(ctx, userAttr), WithUserFilter(ctx, userFilter))
			if err != nil {
				return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update user search configuration"))
			}
		}
	}

	var addGroupSearchConf, deleteGroupSearchConf any
	if strListContainsOneOf(combinedMasks, GroupDnField, GroupAttrField, GroupFilterField) {
		if !isEmpty(origAm.GroupDn, origAm.GroupAttr, origAm.GroupFilter) {
			gsc := allocGroupEntrySearchConf()
			gsc.LdapMethodId = am.PublicId
			deleteGroupSearchConf = gsc
		}
		groupDn := origAm.GroupDn
		switch {
		case strutil.StrListContains(dbMask, GroupDnField):
			groupDn = am.GroupDn
		case strutil.StrListContains(nullFields, GroupDnField):
			groupDn = ""
		}
		groupAttr := origAm.GroupAttr
		switch {
		case strutil.StrListContains(dbMask, GroupAttrField):
			groupAttr = am.GroupAttr
		case strutil.StrListContains(nullFields, GroupAttrField):
			groupAttr = ""
		}
		groupFilter := origAm.GroupFilter
		switch {
		case strutil.StrListContains(dbMask, GroupFilterField):
			groupFilter = am.GroupFilter
		case strutil.StrListContains(nullFields, GroupFilterField):
			groupFilter = ""
		}
		if !isEmpty(groupDn, groupAttr, groupFilter) {
			addGroupSearchConf, err = NewGroupEntrySearchConf(ctx, am.PublicId, WithGroupDn(ctx, groupDn), WithGroupAttr(ctx, groupAttr), WithGroupFilter(ctx, groupFilter))
			if err != nil {
				return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update group search configuration"))
			}
		}
	}

	var addClientCert, deleteClientCert any
	if strListContainsOneOf(combinedMasks, ClientCertificateField, ClientCertificateKeyField) {
		if !isEmpty(origAm.ClientCertificate, origAm.ClientCertificateKey) {
			cc := allocClientCertificate()
			cc.LdapMethodId = am.PublicId
			deleteClientCert = cc
		}
		clientCertificate := origAm.ClientCertificate
		switch {
		case strutil.StrListContains(dbMask, ClientCertificateField):
			clientCertificate = am.ClientCertificate
		case strutil.StrListContains(nullFields, ClientCertificateField):
			clientCertificate = ""
		}
		clientCertificateKey := origAm.ClientCertificateKey
		switch {
		case strutil.StrListContains(dbMask, ClientCertificateKeyField):
			clientCertificateKey = am.ClientCertificateKey
		case strutil.StrListContains(nullFields, ClientCertificateKeyField):
			clientCertificateKey = nil
		}
		if !isEmpty(clientCertificate, clientCertificateKey) {
			cc, err := NewClientCertificate(ctx, am.PublicId, clientCertificateKey, clientCertificate)
			if err != nil {
				return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
			}
			if err := cc.encrypt(ctx, dbWrapper); err != nil {
				return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
			}
			addClientCert = cc
		}
	}

	var addBindCred, deleteBindCred any
	if strListContainsOneOf(combinedMasks, BindDnField, BindPasswordField) {
		if !isEmpty(origAm.BindDn, origAm.BindPassword) {
			bc := allocBindCredential()
			bc.LdapMethodId = am.PublicId
			deleteBindCred = bc
		}
		bindDn := origAm.BindDn
		switch {
		case strutil.StrListContains(dbMask, BindDnField):
			bindDn = am.BindDn
		case strutil.StrListContains(nullFields, BindDnField):
			bindDn = ""
		}
		bindPassword := origAm.BindPassword
		switch {
		case strutil.StrListContains(dbMask, BindPasswordField):
			bindPassword = am.BindPassword
		case strutil.StrListContains(nullFields, BindPasswordField):
			bindPassword = ""
		}
		if !isEmpty(bindDn, bindPassword) {
			bc, err := NewBindCredential(ctx, am.PublicId, bindDn, []byte(bindPassword))
			if err != nil {
				return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
			}
			if err := bc.encrypt(ctx, dbWrapper); err != nil {
				return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("error wrapping updated bind credential"))
			}
			addBindCred = bc
		}
	}

	var addDerefAliases, deleteDerefAliases any
	if strListContainsOneOf(combinedMasks, DerefAliasesField) {
		if !isEmpty(origAm.DereferenceAliases) {
			d := allocDerefAliases()
			d.LdapMethodId = am.PublicId
			deleteDerefAliases = d
		}
		derefAliases := origAm.DereferenceAliases
		switch {
		case strutil.StrListContains(dbMask, DerefAliasesField):
			derefAliases = am.DereferenceAliases
		case strutil.StrListContains(nullFields, DerefAliasesField):
			derefAliases = ""
		}
		if !isEmpty(derefAliases) {
			d, err := NewDerefAliases(ctx, am.PublicId, DerefAliasType(derefAliases))
			if err != nil {
				return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
			}
			addDerefAliases = d
		}
	}

	var filteredDbMask, filteredNullFields []string
	for _, f := range dbMask {
		switch f {
		case
			UrlsField,
			CertificatesField,
			AccountAttributeMapsField,
			UserDnField, UserAttrField, UserFilterField,
			GroupDnField, GroupAttrField, GroupFilterField,
			ClientCertificateField, ClientCertificateKeyField,
			BindDnField, BindPasswordField,
			DerefAliasesField:
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
			AccountAttributeMapsField,
			UserDnField, UserAttrField, UserFilterField,
			GroupDnField, GroupAttrField, GroupFilterField,
			ClientCertificateField, ClientCertificateKeyField,
			BindDnField, BindPasswordField,
			DerefAliasesField:
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
		deleteBindCred == nil &&
		len(addMaps) == 0 &&
		len(deleteMaps) == 0 &&
		addDerefAliases == nil &&
		deleteDerefAliases == nil {
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
			if len(deleteMaps) > 0 {
				deleteMapsOplogMsgs := make([]*oplog.Message, 0, len(deleteMaps))
				rowsDeleted, err := w.DeleteItems(ctx, deleteMaps, db.NewOplogMsgs(&deleteMapsOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete account attribute maps"))
				}
				if rowsDeleted != len(deleteMaps) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("account attribute maps deleted %d did not match request for %d", rowsDeleted, len(deleteMaps)))
				}
				msgs = append(msgs, deleteMapsOplogMsgs...)
			}
			if len(addMaps) > 0 {
				addMapsOplogMsgs := make([]*oplog.Message, 0, len(addMaps))
				if err := w.CreateItems(ctx, addMaps, db.NewOplogMsgs(&addMapsOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add account attribute maps"))
				}
				msgs = append(msgs, addMapsOplogMsgs...)
			}
			if deleteDerefAliases != nil {
				var deleteDerefMsg oplog.Message
				rowsDeleted, err := w.Delete(ctx, deleteDerefAliases, db.NewOplogMsg(&deleteDerefMsg))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete deref aliases"))
				}
				if rowsDeleted != 1 {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("deref aliases deleted %d did not match request for 1", rowsDeleted))
				}
				msgs = append(msgs, &deleteDerefMsg)
			}
			if addDerefAliases != nil {
				var addDerefOplogMsg oplog.Message
				if err := w.Create(ctx, addDerefAliases, db.NewOplogMsg(&addDerefOplogMsg)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add deref aliases"))
				}
				msgs = append(msgs, &addDerefOplogMsg)
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
		case strings.EqualFold(OperationalStateField, f):
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
		case strings.EqualFold(AccountAttributeMapsField, f):
		case strings.EqualFold(DerefAliasesField, f):
		case strings.EqualFold(MaximumPageSizeField, f):
		default:
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid field mask: %q", f))
		}
	}
	return nil
}

// voName represents the names of auth method value objects
type voName string

const (
	CertificateVO          voName = "Certificates"
	UrlVO                  voName = "Urls"
	AccountAttributeMapsVO voName = "AccountAttributeMaps"
)

// validVoName decides if the name is valid
func validVoName(name voName) bool {
	switch name {
	case CertificateVO, UrlVO, AccountAttributeMapsVO:
		return true
	default:
		return false
	}
}

// factoryFunc defines a func type for value object factories
type factoryFunc func(ctx context.Context, publicId string, idx int, s string) (any, error)

// supportedFactories are the currently supported factoryFunc for value objects
var supportedFactories = map[voName]factoryFunc{
	CertificateVO: func(ctx context.Context, publicId string, idx int, s string) (any, error) {
		return NewCertificate(ctx, publicId, s)
	},
	UrlVO: func(ctx context.Context, publicId string, idx int, s string) (any, error) {
		u, err := url.Parse(s)
		if err != nil {
			return nil, errors.Wrap(ctx, err, "ldap.urlFactory")
		}
		return NewUrl(ctx, publicId, idx+1, u)
	},
	AccountAttributeMapsVO: func(ctx context.Context, publicId string, idx int, s string) (any, error) {
		const op = "ldap.AccountAttributeMapsFactory"
		acm, err := ParseAccountAttributeMaps(ctx, s)
		if err != nil {
			return nil, err
		}
		if len(acm) > 1 {
			return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unable to parse account attribute map %s", s))
		}
		var m AttributeMap
		for _, m = range acm {
		}
		to, err := ConvertToAccountToAttribute(ctx, m.To)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		return NewAccountAttributeMap(ctx, publicId, m.From, to)
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
