// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-secure-stdlib/strutil"
)

const (
	OperationalStateField                  = "OperationalState"
	DisableDiscoveredConfigValidationField = "DisableDiscoveredConfigValidation"
	VersionField                           = "Version"
	NameField                              = "Name"
	DescriptionField                       = "Description"
	FilterField                            = "Filter"
	IssuerField                            = "Issuer"
	ClientIdField                          = "ClientId"
	ClientSecretField                      = "ClientSecret"
	CtClientSecretField                    = "CtClientSecret"
	ClientSecretHmacField                  = "ClientSecretHmac"
	MaxAgeField                            = "MaxAge"
	SigningAlgsField                       = "SigningAlgs"
	ApiUrlField                            = "ApiUrl"
	AudClaimsField                         = "AudClaims"
	CertificatesField                      = "Certificates"
	ClaimsScopesField                      = "ClaimsScopes"
	AccountClaimMapsField                  = "AccountClaimMaps"
	TokenClaimsField                       = "TokenClaims"
	UserinfoClaimsField                    = "UserinfoClaims"
	KeyIdField                             = "KeyId"
	PromptsField                           = "Prompts"
)

// UpdateAuthMethod will retrieve the auth method from the repository,
// and update it based on the field masks provided.
//
// The auth method will not be persisted in the repository if the auth
// method's OperationalStatus is currently ActivePublic or ActivePrivate
// and the update would have resulted in an incomplete/non-operational
// auth method.
//
// During update, the auth method will be tested/validated against its
// provider's published OIDC discovery document. If this validation
// succeeds, the auth method is persisted in the repository, and the
// written auth method is returned.
//
// fieldMaskPaths provides field_mask.proto paths for fields that should
// be updated.  Fields will be set to NULL if the field is a
// zero value and included in fieldMask. Name, Description, Issuer,
// ClientId, ClientSecret, MaxAge are all updatable fields.  The AuthMethod's
// Value Objects of SigningAlgs, Prompts, CallbackUrls, AudClaims and Certificates are
// also updatable. if no updatable fields are included in the fieldMaskPaths,
// then an error is returned.
//
// Options supported:
//
// * WithDryRun: when this option is provided, the auth method is retrieved from
// the repo, updated based on the fieldMask, tested via Repository.ValidateDiscoveryInfo,
// the results of the update are returned, and and any errors reported.  The
// updates are not peristed to the repository.
//
// * WithForce: when this option is provided, the auth method is persisted in
// the repository without testing it's validity against its provider's published
// OIDC discovery document. Even if this option is provided, the auth method will
// not be persisted in the repository when the update would have resulted in
// an incomplete/non-operational auth method and it's OperationalStatus is
// currently ActivePublic or ActivePrivate.
//
// Also, a successful update will invalidate (delete) the Repository's
// cache of the oidc.Provider for the AuthMethod.
func (r *Repository) UpdateAuthMethod(ctx context.Context, am *AuthMethod, version uint32, fieldMaskPaths []string, opt ...Option) (*AuthMethod, int, error) {
	const op = "oidc.(Repository).UpdateAuthMethod"
	if am == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing auth method")
	}
	if am.AuthMethod == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing auth method store")
	}
	if am.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}

	if err := validateFieldMask(ctx, fieldMaskPaths); err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}

	dbMask, nullFields := dbw.BuildUpdatePaths(
		map[string]any{
			NameField:             am.Name,
			DescriptionField:      am.Description,
			IssuerField:           am.Issuer,
			ClientIdField:         am.ClientId,
			ClientSecretField:     am.ClientSecret,
			MaxAgeField:           am.MaxAge,
			SigningAlgsField:      am.SigningAlgs,
			ApiUrlField:           am.ApiUrl,
			AudClaimsField:        am.AudClaims,
			CertificatesField:     am.Certificates,
			ClaimsScopesField:     am.ClaimsScopes,
			AccountClaimMapsField: am.AccountClaimMaps,
			PromptsField:          am.Prompts,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "empty field mask")
	}

	origAm, err := r.lookupAuthMethod(ctx, am.PublicId)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	if origAm == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("auth method %s", am.PublicId))
	}
	// there's no reason to continue if another controller has already updated this auth method.
	if origAm.Version != version {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.VersionMismatch, op, fmt.Sprintf("update version %d doesn't match db version %d", version, origAm.Version))
	}

	opts := getOpts(opt...)
	if opts.withDryRun {
		updated := applyUpdate(am, origAm, fieldMaskPaths)
		if err := updated.isComplete(ctx); err != nil {
			return updated, db.NoRowsAffected, err
		}
		err := r.ValidateDiscoveryInfo(ctx, WithAuthMethod(updated))
		return updated, db.NoRowsAffected, err
	}

	// prevent an "active" auth method from being updated in a manner that would create
	// an incomplete and unusable auth method.
	if origAm.OperationalState != string(InactiveState) {
		if err := applyUpdate(am, origAm, fieldMaskPaths).isComplete(ctx); err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("update would result in an incomplete auth method"))
		}
	}

	if !opts.withForce {
		if err := r.ValidateDiscoveryInfo(ctx, WithAuthMethod(applyUpdate(am, origAm, fieldMaskPaths))); err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
	}

	aa, ad, err := valueObjectChanges(ctx, origAm.PublicId, SigningAlgVO, am.SigningAlgs, origAm.SigningAlgs, dbMask, nullFields)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	addAlgs := []*SigningAlg{}
	for _, a := range aa {
		addAlgs = append(addAlgs, a.(*SigningAlg))
	}
	deleteAlgs := []*SigningAlg{}
	for _, a := range ad {
		deleteAlgs = append(deleteAlgs, a.(*SigningAlg))
	}

	ac, dc, err := valueObjectChanges(ctx, origAm.PublicId, CertificateVO, am.Certificates, origAm.Certificates, dbMask, nullFields)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	addCerts := []*Certificate{}
	for _, c := range ac {
		addCerts = append(addCerts, c.(*Certificate))
	}
	deleteCerts := []*Certificate{}
	for _, c := range dc {
		deleteCerts = append(deleteCerts, c.(*Certificate))
	}

	aa, ad, err = valueObjectChanges(ctx, origAm.PublicId, AudClaimVO, am.AudClaims, origAm.AudClaims, dbMask, nullFields)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	addAuds := []*AudClaim{}
	for _, a := range aa {
		addAuds = append(addAuds, a.(*AudClaim))
	}
	deleteAuds := []*AudClaim{}
	for _, a := range ad {
		deleteAuds = append(deleteAuds, a.(*AudClaim))
	}

	as, ds, err := valueObjectChanges(ctx, origAm.PublicId, ClaimsScopesVO, am.ClaimsScopes, origAm.ClaimsScopes, dbMask, nullFields)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	addScopes := []*ClaimsScope{}
	for _, s := range as {
		addScopes = append(addScopes, s.(*ClaimsScope))
	}
	deleteScopes := []*ClaimsScope{}
	for _, s := range ds {
		deleteScopes = append(deleteScopes, s.(*ClaimsScope))
	}

	aacm, dacm, err := valueObjectChanges(ctx, origAm.PublicId, AccountClaimMapsVO, am.AccountClaimMaps, origAm.AccountClaimMaps, dbMask, nullFields)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	addMaps := []*AccountClaimMap{}
	for _, m := range aacm {
		addMaps = append(addMaps, m.(*AccountClaimMap))
	}
	deleteMaps := []*AccountClaimMap{}
	for _, m := range dacm {
		deleteMaps = append(deleteMaps, m.(*AccountClaimMap))
	}

	ap, dp, err := valueObjectChanges(ctx, origAm.PublicId, PromptsVO, am.Prompts, origAm.Prompts, dbMask, nullFields)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	addPrompts := []*Prompt{}
	for _, p := range ap {
		addPrompts = append(addPrompts, p.(*Prompt))
	}
	deletePrompts := []*Prompt{}
	for _, p := range dp {
		deletePrompts = append(deletePrompts, p.(*Prompt))
	}

	// we don't allow updates for "sub" claim maps, because we have no way to
	// determine if the updated "from" claim in the map might create collisions
	// with any existing account's subject.
	for _, cm := range addMaps {
		if cm.ToClaim == string(ToSubClaim) {
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("you cannot update account claim map %s=%s for the \"sub\" claim", cm.FromClaim, cm.ToClaim))
		}
	}
	for _, cm := range deleteMaps {
		if cm.ToClaim == string(ToSubClaim) {
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("you cannot update account claim map %s=%s for the \"sub\" claim", cm.FromClaim, cm.ToClaim))
		}
	}

	var filteredDbMask, filteredNullFields []string
	for _, f := range dbMask {
		switch f {
		case SigningAlgsField, AudClaimsField, CertificatesField, ClaimsScopesField, AccountClaimMapsField, PromptsField:
			continue
		default:
			filteredDbMask = append(filteredDbMask, f)
		}
	}
	for _, f := range nullFields {
		switch f {
		case SigningAlgsField, AudClaimsField, CertificatesField, ClaimsScopesField, AccountClaimMapsField, PromptsField:
			continue
		default:
			filteredNullFields = append(filteredNullFields, f)
		}
	}

	// handle no changes...
	if len(filteredDbMask) == 0 &&
		len(filteredNullFields) == 0 &&
		len(addAlgs) == 0 &&
		len(deleteAlgs) == 0 &&
		len(addCerts) == 0 &&
		len(deleteCerts) == 0 &&
		len(addAuds) == 0 &&
		len(deleteAuds) == 0 &&
		len(addScopes) == 0 &&
		len(deleteScopes) == 0 &&
		len(addMaps) == 0 &&
		len(deleteMaps) == 0 &&
		len(addPrompts) == 0 &&
		len(deletePrompts) == 0 {
		return origAm, db.NoRowsAffected, nil
	}

	// ClientSecret is a bit odd, because it uses the Struct wrapping, we need
	// to add the encrypted fields to the dbMask or nullFields
	if strutil.StrListContains(filteredDbMask, ClientSecretField) {
		filteredDbMask = append(filteredDbMask, CtClientSecretField, ClientSecretHmacField, KeyIdField)
	}
	if strutil.StrListContains(filteredNullFields, ClientSecretField) {
		filteredNullFields = append(filteredNullFields, CtClientSecretField, ClientSecretHmacField, KeyIdField)
	}

	databaseWrapper, err := r.kms.GetWrapper(ctx, origAm.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}
	if err := am.encrypt(ctx, databaseWrapper); err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, origAm.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	// we always set this to the current value of opts.withForce
	am.DisableDiscoveredConfigValidation = opts.withForce

	var updatedAm *AuthMethod
	var rowsUpdated int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 9) // AuthMethod, Algs*2, Certs*2, Audiences*2, Prompts*2
			ticket, err := w.GetTicket(ctx, am)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			var authMethodOplogMsg oplog.Message
			switch {
			case len(filteredDbMask) == 0 && len(filteredNullFields) == 0:
				// the auth method's fields are not being updated, just it's value objects, so we need to just update the auth
				// method's version.
				updatedAm = am.Clone()
				updatedAm.Version = uint32(version) + 1
				rowsUpdated, err = w.Update(ctx, updatedAm, []string{VersionField, DisableDiscoveredConfigValidationField}, nil, db.NewOplogMsg(&authMethodOplogMsg), db.WithVersion(&version))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update auth method version"))
				}
				if rowsUpdated != 1 {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated auth method version and %d rows updated", rowsUpdated))
				}
			default:
				filteredDbMask = append(filteredDbMask, DisableDiscoveredConfigValidationField)
				updatedAm = am.Clone()
				rowsUpdated, err = w.Update(ctx, updatedAm, filteredDbMask, filteredNullFields, db.NewOplogMsg(&authMethodOplogMsg), db.WithVersion(&version))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update auth method"))
				}
				if rowsUpdated != 1 {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated auth method and %d rows updated", rowsUpdated))
				}
			}
			msgs = append(msgs, &authMethodOplogMsg)

			if len(deleteAlgs) > 0 {
				deleteAlgOplogMsgs := make([]*oplog.Message, 0, len(deleteAlgs))
				rowsDeleted, err := w.DeleteItems(ctx, deleteAlgs, db.NewOplogMsgs(&deleteAlgOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete signing algorithms"))
				}
				if rowsDeleted != len(deleteAlgs) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("signing algorithms deleted %d did not match request for %d", rowsDeleted, len(deleteAlgs)))
				}
				msgs = append(msgs, deleteAlgOplogMsgs...)
			}
			if len(addAlgs) > 0 {
				addAlgsOplogMsgs := make([]*oplog.Message, 0, len(addAlgs))
				if err := w.CreateItems(ctx, addAlgs, db.NewOplogMsgs(&addAlgsOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add signing algorithms"))
				}
				msgs = append(msgs, addAlgsOplogMsgs...)
			}

			if len(deletePrompts) > 0 {
				deletePromptOplogMsgs := make([]*oplog.Message, 0, len(deletePrompts))
				rowsDeleted, err := w.DeleteItems(ctx, deletePrompts, db.NewOplogMsgs(&deletePromptOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete prompts"))
				}
				if rowsDeleted != len(deletePrompts) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("prompts deleted %d did not match request for %d", rowsDeleted, len(deletePrompts)))
				}
				msgs = append(msgs, deletePromptOplogMsgs...)
			}
			if len(addPrompts) > 0 {
				addPromptsOplogMsgs := make([]*oplog.Message, 0, len(addPrompts))
				if err := w.CreateItems(ctx, addPrompts, db.NewOplogMsgs(&addPromptsOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add prompts"))
				}
				msgs = append(msgs, addPromptsOplogMsgs...)
			}

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

			if len(deleteAuds) > 0 {
				deleteAudsOplogMsgs := make([]*oplog.Message, 0, len(deleteAuds))
				rowsDeleted, err := w.DeleteItems(ctx, deleteAuds, db.NewOplogMsgs(&deleteAudsOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete audiences URLs"))
				}
				if rowsDeleted != len(deleteAuds) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("audiences deleted %d did not match request for %d", rowsDeleted, len(deleteAuds)))
				}
				msgs = append(msgs, deleteAudsOplogMsgs...)
			}
			if len(addAuds) > 0 {
				addAudsOplogMsgs := make([]*oplog.Message, 0, len(addAuds))
				if err := w.CreateItems(ctx, addAuds, db.NewOplogMsgs(&addAudsOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add audiences URLs"))
				}
				msgs = append(msgs, addAudsOplogMsgs...)
			}

			if len(deleteScopes) > 0 {
				deleteScopesOplogMsgs := make([]*oplog.Message, 0, len(deleteScopes))
				rowsDeleted, err := w.DeleteItems(ctx, deleteScopes, db.NewOplogMsgs(&deleteScopesOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete claims scopes"))
				}
				if rowsDeleted != len(deleteScopes) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("claims scopes deleted %d did not match request for %d", rowsDeleted, len(deleteScopes)))
				}
				msgs = append(msgs, deleteScopesOplogMsgs...)
			}
			if len(addScopes) > 0 {
				addScopesOplogMsgs := make([]*oplog.Message, 0, len(addScopes))
				if err := w.CreateItems(ctx, addScopes, db.NewOplogMsgs(&addScopesOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add claims scopes"))
				}
				msgs = append(msgs, addScopesOplogMsgs...)
			}

			if len(deleteMaps) > 0 {
				deleteMapsOplogMsgs := make([]*oplog.Message, 0, len(deleteMaps))
				rowsDeleted, err := w.DeleteItems(ctx, deleteMaps, db.NewOplogMsgs(&deleteMapsOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete account claim maps"))
				}
				if rowsDeleted != len(deleteMaps) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("account claim maps deleted %d did not match request for %d", rowsDeleted, len(deleteMaps)))
				}
				msgs = append(msgs, deleteMapsOplogMsgs...)
			}
			if len(addMaps) > 0 {
				addMapsOplogMsgs := make([]*oplog.Message, 0, len(addMaps))
				if err := w.CreateItems(ctx, addMaps, db.NewOplogMsgs(&addMapsOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add account claim maps"))
				}
				msgs = append(msgs, addMapsOplogMsgs...)
			}

			metadata := updatedAm.oplog(oplog.OpType_OP_TYPE_UPDATE)
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

	providerCache().delete(ctx, updatedAm.PublicId)

	return updatedAm, rowsUpdated, nil
}

// voName represents the names of auth method value objects
type voName string

const (
	SigningAlgVO       voName = "SigningAlgs"
	CertificateVO      voName = "Certificates"
	AudClaimVO         voName = "AudClaims"
	ClaimsScopesVO     voName = "ClaimsScopes"
	AccountClaimMapsVO voName = "AccountClaimMaps"
	PromptsVO          voName = "Prompts"
)

// validVoName decides if the name is valid
func validVoName(name voName) bool {
	switch name {
	case SigningAlgVO, CertificateVO, AudClaimVO, ClaimsScopesVO, AccountClaimMapsVO, PromptsVO:
		return true
	default:
		return false
	}
}

// factoryFunc defines a func type for value object factories
type factoryFunc func(ctx context.Context, publicId string, i any) (any, error)

// supportedFactories are the currently supported factoryFunc for value objects
var supportedFactories = map[voName]factoryFunc{
	SigningAlgVO: func(ctx context.Context, publicId string, i any) (any, error) {
		str := fmt.Sprintf("%s", i)
		return NewSigningAlg(ctx, publicId, Alg(str))
	},
	CertificateVO: func(ctx context.Context, publicId string, i any) (any, error) {
		str := fmt.Sprintf("%s", i)
		return NewCertificate(ctx, publicId, str)
	},
	AudClaimVO: func(ctx context.Context, publicId string, i any) (any, error) {
		str := fmt.Sprintf("%s", i)
		return NewAudClaim(ctx, publicId, str)
	},
	ClaimsScopesVO: func(ctx context.Context, publicId string, i any) (any, error) {
		str := fmt.Sprintf("%s", i)
		return NewClaimsScope(ctx, publicId, str)
	},
	AccountClaimMapsVO: func(ctx context.Context, publicId string, i any) (any, error) {
		const op = "oidc.AccountClaimMapsFactory"
		str := fmt.Sprintf("%s", i)
		acm, err := ParseAccountClaimMaps(ctx, str)
		if err != nil {
			return nil, err
		}
		if len(acm) > 1 {
			return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unable to parse account claim map %s", str))
		}
		var m ClaimMap
		for _, m = range acm {
		}
		to, err := ConvertToAccountToClaim(ctx, m.To)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		return NewAccountClaimMap(ctx, publicId, m.From, to)
	},
	PromptsVO: func(ctx context.Context, publicId string, i any) (any, error) {
		str := fmt.Sprintf("%s", i)
		return NewPrompt(ctx, publicId, PromptParam(str))
	},
}

// valueObjectChanges takes the new and old list of VOs (value objects) and
// using the dbMasks/nullFields it will return lists of VOs where need to be
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
	const op = "valueObjectChanges"
	if publicId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if !validVoName(valueObjectName) {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid value object name: %s", valueObjectName))
	}
	if !strutil.StrListContains(dbMask, string(valueObjectName)) && !strutil.StrListContains(nullFields, string(valueObjectName)) {
		return nil, nil, nil
	}
	if len(strutil.RemoveDuplicates(newVOs, false)) != len(newVOs) {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("duplicate new %s", valueObjectName))
	}
	if len(strutil.RemoveDuplicates(oldVOs, false)) != len(oldVOs) {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("duplicate old %s", valueObjectName))
	}

	factory, ok := supportedFactories[valueObjectName]
	if !ok {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unsupported factory for value object: %s", valueObjectName))
	}

	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, nil, nil
	}

	foundVOs := map[string]bool{}
	for _, a := range oldVOs {
		foundVOs[a] = true
	}
	var adds []any
	var deletes []any
	if strutil.StrListContains(nullFields, string(valueObjectName)) {
		deletes = make([]any, 0, len(oldVOs))
		for _, v := range oldVOs {
			deleteObj, err := factory(ctx, publicId, v)
			if err != nil {
				return nil, nil, errors.Wrap(ctx, err, op)
			}
			deletes = append(deletes, deleteObj)
			delete(foundVOs, v)
		}
	}
	if strutil.StrListContains(dbMask, string(valueObjectName)) {
		adds = make([]any, 0, len(newVOs))
		for _, v := range newVOs {
			if _, ok := foundVOs[v]; ok {
				delete(foundVOs, v)
				continue
			}
			obj, err := factory(ctx, publicId, v)
			if err != nil {
				return nil, nil, errors.Wrap(ctx, err, op)
			}
			adds = append(adds, obj)
			delete(foundVOs, v)
		}
	}
	if len(foundVOs) > 0 {
		for v := range foundVOs {
			obj, err := factory(ctx, publicId, v)
			if err != nil {
				return nil, nil, errors.Wrap(ctx, err, op)
			}
			deletes = append(deletes, obj)
			delete(foundVOs, v)
		}
	}
	return adds, deletes, nil
}

// validateFieldMask check the field mask to ensure all the fields are updatable
func validateFieldMask(ctx context.Context, fieldMaskPaths []string) error {
	const op = "validateFieldMask"
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold(NameField, f):
		case strings.EqualFold(DescriptionField, f):
		case strings.EqualFold(IssuerField, f):
		case strings.EqualFold(ClientIdField, f):
		case strings.EqualFold(ClientSecretField, f):
		case strings.EqualFold(MaxAgeField, f):
		case strings.EqualFold(SigningAlgsField, f):
		case strings.EqualFold(ApiUrlField, f):
		case strings.EqualFold(AudClaimsField, f):
		case strings.EqualFold(CertificatesField, f):
		case strings.EqualFold(ClaimsScopesField, f):
		case strings.EqualFold(AccountClaimMapsField, f):
		case strings.EqualFold(PromptsField, f):
		default:
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid field mask: %s", f))
		}
	}
	return nil
}

// applyUpdate takes the new and applies it to the orig using the field masks
func applyUpdate(new, orig *AuthMethod, fieldMaskPaths []string) *AuthMethod {
	cp := orig.Clone()
	for _, f := range fieldMaskPaths {
		switch f {
		case NameField:
			cp.Name = new.Name
		case DescriptionField:
			cp.Description = new.Description
		case IssuerField:
			cp.Issuer = new.Issuer
		case ClientIdField:
			cp.ClientId = new.ClientId
		case ClientSecretField:
			cp.ClientSecret = new.ClientSecret
		case MaxAgeField:
			cp.MaxAge = new.MaxAge
		case ApiUrlField:
			cp.ApiUrl = new.ApiUrl
		case SigningAlgsField:
			switch {
			case len(new.SigningAlgs) == 0:
				cp.SigningAlgs = nil
			default:
				cp.SigningAlgs = make([]string, 0, len(new.SigningAlgs))
				cp.SigningAlgs = append(cp.SigningAlgs, new.SigningAlgs...)
			}
		case AudClaimsField:
			switch {
			case len(new.AudClaims) == 0:
				cp.AudClaims = nil
			default:
				cp.AudClaims = make([]string, 0, len(new.AudClaims))
				cp.AudClaims = append(cp.AudClaims, new.AudClaims...)
			}
		case CertificatesField:
			switch {
			case len(new.Certificates) == 0:
				cp.Certificates = nil
			default:
				cp.Certificates = make([]string, 0, len(new.Certificates))
				cp.Certificates = append(cp.Certificates, new.Certificates...)
			}
		case ClaimsScopesField:
			switch {
			case len(new.ClaimsScopes) == 0:
				cp.ClaimsScopes = nil
			default:
				cp.ClaimsScopes = make([]string, 0, len(new.ClaimsScopes))
				cp.ClaimsScopes = append(cp.ClaimsScopes, new.ClaimsScopes...)
			}
		case AccountClaimMapsField:
			switch {
			case len(new.AccountClaimMaps) == 0:
				cp.AccountClaimMaps = nil
			default:
				cp.AccountClaimMaps = make([]string, 0, len(new.AccountClaimMaps))
				cp.AccountClaimMaps = append(cp.AccountClaimMaps, new.AccountClaimMaps...)
			}
		case PromptsField:
			switch {
			case len(new.Prompts) == 0:
				cp.Prompts = nil
			default:
				cp.Prompts = make([]string, 0, len(new.Prompts))
				cp.Prompts = append(cp.Prompts, new.Prompts...)
			}
		}
	}
	return cp
}

// ValidateDiscoveryInfo will test/validate the provided AuthMethod against
// the info from it's discovery URL.
//
// It will verify that all required fields for a working AuthMethod have values.
//
// If the AuthMethod is complete, ValidateDiscoveryInfo retrieves the auth
// method's OpenID Configuration document. The values in the AuthMethod
// (and associated data) are validated with the retrieved document. The issuer and
// id token signing algorithm in the configuration are validated with the
// retrieved document. ValidateDiscoveryInfo also verifies the authorization, token,
// and userinfo endpoints by connecting to each and uses any certificates in the
// configuration as trust anchors to confirm connectivity.
//
// Options supported are: WithPublicId, WithAuthMethod
func (r *Repository) ValidateDiscoveryInfo(ctx context.Context, opt ...Option) error {
	const op = "oidc.(Repository).ValidateDiscoveryInfo"
	opts := getOpts(opt...)
	var am *AuthMethod
	switch {
	case opts.withPublicId != "":
		var err error
		am, err = r.lookupAuthMethod(ctx, opts.withPublicId)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if am == nil {
			return errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("unable to lookup auth method %s", opts.withPublicId))
		}
	case opts.withAuthMethod != nil:
		am = opts.withAuthMethod
	default:
		return errors.New(ctx, errors.InvalidParameter, op, "neither WithPublicId(...) nor WithAuthMethod(...) options were provided")
	}

	// FYI: once converted to an oidc.Provider, any certs configured will be used as trust anchors for all HTTP requests
	provider, err := convertToProvider(ctx, am)
	if err != nil && am.OperationalState == string(InactiveState) {
		return nil
	}
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	info, err := provider.DiscoveryInfo(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	var result error
	if info.Issuer != am.Issuer {
		result = stderrors.Join(result, errors.New(ctx, errors.InvalidParameter, op,
			fmt.Sprintf("auth method issuer doesn't match discovery issuer: expected %s and got %s", am.Issuer, info.Issuer)))
	}
	for _, a := range am.SigningAlgs {
		if !strutil.StrListContains(info.IdTokenSigningAlgsSupported, a) {
			result = stderrors.Join(result, errors.New(ctx, errors.InvalidParameter, op,
				fmt.Sprintf("auth method signing alg is not in discovered supported algs: expected %s and got %s", a, info.IdTokenSigningAlgsSupported)))
		}
	}
	providerClient, err := provider.HTTPClient()
	if err != nil {
		result = stderrors.Join(result, errors.New(ctx, errors.Unknown, op, "unable to get oidc http client", errors.WithWrap(err)))
		return result
	}

	// we need to prevent redirects during these tests... we don't want to have
	// redirects going to the controller's callback (aka the configured provider's callback)
	providerClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// test JWKs URL
	statusCode, err := pingEndpoint(ctx, providerClient, "JWKs", "GET", info.JWKSURL)
	if err != nil {
		result = stderrors.Join(result, errors.New(ctx, errors.Unknown, op, fmt.Sprintf("unable to verify JWKs endpoint: %s", info.JWKSURL), errors.WithWrap(err)))
	}
	if statusCode != 200 {
		result = stderrors.Join(result, errors.New(ctx, errors.Unknown, op, fmt.Sprintf("non-200 status (%d) from JWKs endpoint: %s", statusCode, info.JWKSURL), errors.WithWrap(err)))
	}

	// test Auth URL
	if _, err := pingEndpoint(ctx, providerClient, "AuthURL", "GET", info.AuthURL); err != nil {
		result = stderrors.Join(result, errors.New(ctx, errors.Unknown, op, fmt.Sprintf("unable to verify authorize endpoint: %s", info.AuthURL), errors.WithWrap(err)))
	}

	// test Token URL
	if _, err := pingEndpoint(ctx, providerClient, "TokenURL", "POST", info.TokenURL); err != nil {
		result = stderrors.Join(result, errors.New(ctx, errors.Unknown, op, fmt.Sprintf("unable to verify token endpoint: %s", info.TokenURL), errors.WithWrap(err)))
	}

	// we're not verifying the UserInfo URL, since it's not a required dependency.

	return result
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// pingEndpoint will make an attempted http request, return status code and errors
func pingEndpoint(ctx context.Context, client HTTPClient, endpointType, method, url string) (int, error) {
	const op = "oidc.pingEndpoint"
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, errors.New(ctx, errors.Unknown, op, fmt.Sprintf("unable to create %s http request", endpointType), errors.WithWrap(err))
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, errors.New(ctx, errors.Unknown, op, fmt.Sprintf("request to %s endpoint failed", endpointType), errors.WithWrap(err))
	}
	if resp.Body != nil {
		resp.Body.Close()
	}
	return resp.StatusCode, nil
}
