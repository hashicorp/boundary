package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/hashicorp/go-multierror"
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
// zero value and included in fieldMask. Name, Description, DiscoveryUrl,
// ClientId, ClientSecret, MaxAge are all updatable fields.  The AuthMethod's
// Value Objects of SigningAlgs, CallbackUrls, AudClaims and Certificates are
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
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing auth method")
	}
	if am.AuthMethod == nil {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing auth method store")
	}
	if am.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing public id")
	}

	if err := validateFieldMask(fieldMaskPaths); err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}

	dbMask, nullFields := dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"Name":         am.Name,
			"Description":  am.Description,
			"DiscoveryUrl": am.DiscoveryUrl,
			"ClientId":     am.ClientId,
			"ClientSecret": am.ClientSecret,
			"MaxAge":       am.MaxAge,
			"SigningAlgs":  am.SigningAlgs,
			"CallbackUrls": am.CallbackUrls,
			"AudClaims":    am.AudClaims,
			"Certificates": am.Certificates,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(errors.EmptyFieldMask, op, "empty field mask")
	}

	origAm, err := r.lookupAuthMethod(ctx, am.PublicId)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}
	if origAm == nil {
		return nil, db.NoRowsAffected, errors.New(errors.RecordNotFound, op, fmt.Sprintf("auth method %s", am.PublicId))
	}
	// there's no reason to continue if another controller has already updated this auth method.
	if origAm.Version != version {
		return nil, db.NoRowsAffected, errors.New(errors.VersionMismatch, op, fmt.Sprintf("update version %d doesn't match db version %d", version, origAm.Version))
	}

	opts := getOpts(opt...)
	if opts.withDryRun {
		updated := applyUpdate(am, origAm, fieldMaskPaths)
		if err := am.isComplete(); err != nil {
			return updated, db.NoRowsAffected, err
		}
		err := r.ValidateDiscoveryInfo(ctx, WithAuthMethod(updated))
		return updated, db.NoRowsAffected, err
	}

	// prevent an "active" auth method from being updated in a manner that would create
	// an incomplete and unusable auth method.
	if origAm.OperationalState != string(InactiveState) {
		if err := applyUpdate(am, origAm, fieldMaskPaths).isComplete(); err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("update would result in an incomplete auth method"))
		}
	}

	if !opts.withForce {
		if err := r.ValidateDiscoveryInfo(ctx, WithAuthMethod(applyUpdate(am, origAm, fieldMaskPaths))); err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(err, op)
		}
	}

	addAlgs, deleteAlgs, err := valueObjectChanges(origAm.PublicId, SigningAlgVO, am.SigningAlgs, origAm.SigningAlgs, dbMask, nullFields)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}

	addCerts, deleteCerts, err := valueObjectChanges(origAm.PublicId, CertificateVO, am.Certificates, origAm.Certificates, dbMask, nullFields)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}

	addCallbacks, deleteCallbacks, err := valueObjectChanges(origAm.PublicId, CallbackUrlVO, am.CallbackUrls, origAm.CallbackUrls, dbMask, nullFields)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}

	addAuds, deleteAuds, err := valueObjectChanges(origAm.PublicId, AudClaimVO, am.AudClaims, origAm.AudClaims, dbMask, nullFields)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}

	var filteredDbMask, filteredNullFields []string
	for _, f := range dbMask {
		switch f {
		case "SigningAlgs", "CallbackUrls", "AudClaims", "Certificates":
			continue
		default:
			filteredDbMask = append(filteredDbMask, f)
		}
	}
	for _, f := range nullFields {
		switch f {
		case "SigningAlgs", "CallbackUrls", "AudClaims", "Certificates":
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
		len(addCallbacks) == 0 &&
		len(deleteCallbacks) == 0 &&
		len(addAuds) == 0 &&
		len(deleteAuds) == 0 {
		return origAm, db.NoRowsAffected, nil
	}

	databaseWrapper, err := r.kms.GetWrapper(ctx, origAm.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get database wrapper"))
	}
	if err := am.encrypt(ctx, databaseWrapper); err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, origAm.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	var updatedAm *AuthMethod
	var rowsUpdated int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 9) // AuthMethod, Algs*2, Certs*2, Callbacks*2, Audiences*2
			ticket, err := w.GetTicket(am)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to get ticket"))
			}
			var authMethodOplogMsg oplog.Message
			switch {
			case len(filteredDbMask) == 0 && len(filteredNullFields) == 0:
				// the auth method's fields are not being updated, just it's value objects, so we need to just update the auth
				// method's version.
				updatedAm = am.Clone()
				updatedAm.Version = uint32(version) + 1
				rowsUpdated, err = w.Update(ctx, updatedAm, []string{"Version"}, nil, db.NewOplogMsg(&authMethodOplogMsg), db.WithVersion(&version))
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to update auth method version"))
				}
				if rowsUpdated != 1 {
					return errors.New(errors.MultipleRecords, op, fmt.Sprintf("updated auth method version and %d rows updated", rowsUpdated))
				}
			default:
				updatedAm = am.Clone()
				rowsUpdated, err = w.Update(ctx, updatedAm, filteredDbMask, filteredNullFields, db.NewOplogMsg(&authMethodOplogMsg), db.WithVersion(&version))
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to update auth method"))
				}
				if rowsUpdated != 1 {
					return errors.New(errors.MultipleRecords, op, fmt.Sprintf("updated auth method and %d rows updated", rowsUpdated))
				}
			}
			msgs = append(msgs, &authMethodOplogMsg)

			if len(deleteAlgs) > 0 {
				deleteAlgOplogMsgs := make([]*oplog.Message, 0, len(deleteAlgs))
				rowsDeleted, err := w.DeleteItems(ctx, deleteAlgs, db.NewOplogMsgs(&deleteAlgOplogMsgs))
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to delete signing algorithms"))
				}
				if rowsDeleted != len(deleteAlgs) {
					return errors.New(errors.MultipleRecords, op, fmt.Sprintf("signing algorithms deleted %d did not match request for %d", rowsDeleted, len(deleteAlgs)))
				}
				msgs = append(msgs, deleteAlgOplogMsgs...)
			}
			if len(addAlgs) > 0 {
				addAlgsOplogMsgs := make([]*oplog.Message, 0, len(addAlgs))
				if err := w.CreateItems(ctx, addAlgs, db.NewOplogMsgs(&addAlgsOplogMsgs)); err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to add signing algorithms"))
				}
				msgs = append(msgs, addAlgsOplogMsgs...)
			}

			if len(deleteCerts) > 0 {
				deleteCertOplogMsgs := make([]*oplog.Message, 0, len(deleteCerts))
				rowsDeleted, err := w.DeleteItems(ctx, deleteCerts, db.NewOplogMsgs(&deleteCertOplogMsgs))
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to delete certificates"))
				}
				if rowsDeleted != len(deleteCerts) {
					return errors.New(errors.MultipleRecords, op, fmt.Sprintf("certificates deleted %d did not match request for %d", rowsDeleted, len(deleteCerts)))
				}
				msgs = append(msgs, deleteCertOplogMsgs...)
			}
			if len(addCerts) > 0 {
				addCertsOplogMsgs := make([]*oplog.Message, 0, len(addCerts))
				if err := w.CreateItems(ctx, addCerts, db.NewOplogMsgs(&addCertsOplogMsgs)); err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to add certificates"))
				}
				msgs = append(msgs, addCertsOplogMsgs...)
			}

			if len(deleteCallbacks) > 0 {
				deleteCallbackOplogMsgs := make([]*oplog.Message, 0, len(deleteCallbacks))
				rowsDeleted, err := w.DeleteItems(ctx, deleteCallbacks, db.NewOplogMsgs(&deleteCallbackOplogMsgs))
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to delete callback URLs"))
				}
				if rowsDeleted != len(deleteCallbacks) {
					return errors.New(errors.MultipleRecords, op, fmt.Sprintf("callback URLs deleted %d did not match request for %d", rowsDeleted, len(deleteCallbacks)))
				}
				msgs = append(msgs, deleteCallbackOplogMsgs...)
			}
			if len(addCallbacks) > 0 {
				addCallbackOplogMsgs := make([]*oplog.Message, 0, len(addCallbacks))
				if err := w.CreateItems(ctx, addCallbacks, db.NewOplogMsgs(&addCallbackOplogMsgs)); err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to add callback URLs"))
				}
				msgs = append(msgs, addCallbackOplogMsgs...)
			}

			if len(deleteAuds) > 0 {
				deleteAudsOplogMsgs := make([]*oplog.Message, 0, len(deleteAuds))
				rowsDeleted, err := w.DeleteItems(ctx, deleteAuds, db.NewOplogMsgs(&deleteAudsOplogMsgs))
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to audiences URLs"))
				}
				if rowsDeleted != len(deleteAuds) {
					return errors.New(errors.MultipleRecords, op, fmt.Sprintf("audiences deleted %d did not match request for %d", rowsDeleted, len(deleteAuds)))
				}
				msgs = append(msgs, deleteAudsOplogMsgs...)
			}
			if len(addAuds) > 0 {
				addAudsOplogMsgs := make([]*oplog.Message, 0, len(addAuds))
				if err := w.CreateItems(ctx, addAuds, db.NewOplogMsgs(&addAudsOplogMsgs)); err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to add audiences URLs"))
				}
				msgs = append(msgs, addAudsOplogMsgs...)
			}

			metadata := updatedAm.oplog(oplog.OpType_OP_TYPE_UPDATE)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to write oplog"))
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
				return errors.Wrap(err, op, errors.WithMsg("unable to lookup auth method after update"))
			}
			if updatedAm == nil {
				return errors.New(errors.RecordNotFound, op, "unable to lookup auth method after update")
			}
			return nil
		},
	)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}

	providerCache().delete(ctx, updatedAm.PublicId)

	return updatedAm, rowsUpdated, nil
}

// voName represents the names of auth method value objects
type voName string

const (
	SigningAlgVO  voName = "SigningAlgs"
	CallbackUrlVO voName = "CallbackUrls"
	CertificateVO voName = "Certificates"
	AudClaimVO    voName = "AudClaims"
)

// validVoName decides if the name is valid
func validVoName(name voName) bool {
	switch name {
	case SigningAlgVO, CallbackUrlVO, CertificateVO, AudClaimVO:
		return true
	default:
		return false
	}
}

// factoryFunc defines a func type for value object factories
type factoryFunc func(publicId string, i interface{}) (interface{}, error)

// supportedFactories are the currently supported factoryFunc for value objects
var supportedFactories = map[voName]factoryFunc{
	SigningAlgVO: func(publicId string, i interface{}) (interface{}, error) {
		str := fmt.Sprintf("%s", i)
		return NewSigningAlg(publicId, Alg(str))
	},
	CertificateVO: func(publicId string, i interface{}) (interface{}, error) {
		str := fmt.Sprintf("%s", i)
		return NewCertificate(publicId, str)
	},
	AudClaimVO: func(publicId string, i interface{}) (interface{}, error) {
		str := fmt.Sprintf("%s", i)
		return NewAudClaim(publicId, str)
	},
	CallbackUrlVO: func(publicId string, i interface{}) (interface{}, error) {
		u, err := url.Parse(fmt.Sprintf("%s", i))
		if err != nil {
			return nil, err
		}
		return NewCallbackUrl(publicId, u)
	},
}

// valueObjectChanges takes the new and old list of VOs (value objects) and
// using the dbMasks/nullFields it will return lists of VOs where need to be
// added and deleted in order to reconcile auth method's value objects.
func valueObjectChanges(
	publicId string,
	valueObjectName voName,
	newVOs,
	oldVOs,
	dbMask,
	nullFields []string,
) (add []interface{}, del []interface{}, e error) {
	const op = "valueObjectChanges"
	if publicId == "" {
		return nil, nil, errors.New(errors.InvalidParameter, op, "missing public id")
	}
	if !validVoName(valueObjectName) {
		return nil, nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("invalid value object name: %s", valueObjectName))
	}
	if !strutil.StrListContains(dbMask, string(valueObjectName)) && !strutil.StrListContains(nullFields, string(valueObjectName)) {
		return nil, nil, nil
	}
	if len(strutil.RemoveDuplicates(newVOs, false)) != len(newVOs) {
		return nil, nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("duplicate new %s", valueObjectName))
	}
	if len(strutil.RemoveDuplicates(oldVOs, false)) != len(oldVOs) {
		return nil, nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("duplicate old %s", valueObjectName))
	}

	factory, ok := supportedFactories[valueObjectName]
	if !ok {
		return nil, nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("unsupported factory for value object: %s", valueObjectName))
	}

	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, nil, nil
	}

	foundVOs := map[string]bool{}
	for _, a := range oldVOs {
		foundVOs[a] = true
	}
	var adds []interface{}
	var deletes []interface{}
	if strutil.StrListContains(nullFields, string(valueObjectName)) {
		deletes = make([]interface{}, 0, len(oldVOs))
		for _, a := range oldVOs {
			alg, err := factory(publicId, a)
			if err != nil {
				return nil, nil, errors.Wrap(err, op)
			}
			deletes = append(deletes, alg)
			delete(foundVOs, a)
		}
	}
	if strutil.StrListContains(dbMask, string(valueObjectName)) {
		adds = make([]interface{}, 0, len(newVOs))
		for _, a := range newVOs {
			if _, ok := foundVOs[a]; ok {
				delete(foundVOs, a)
				continue
			}
			alg, err := factory(publicId, a)
			if err != nil {
				return nil, nil, errors.Wrap(err, op)
			}
			adds = append(adds, alg)
			delete(foundVOs, a)
		}
	}
	if len(foundVOs) > 0 {
		for a := range foundVOs {
			alg, err := factory(publicId, a)
			if err != nil {
				return nil, nil, errors.Wrap(err, op)
			}
			deletes = append(deletes, alg)
			delete(foundVOs, a)
		}
	}
	return adds, deletes, nil
}

// validateFieldMask check the field mask to ensure all the fields are updatable
func validateFieldMask(fieldMaskPaths []string) error {
	const op = "validateFieldMask"
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("Name", f):
		case strings.EqualFold("Description", f):
		case strings.EqualFold("DiscoveryUrl", f):
		case strings.EqualFold("ClientId", f):
		case strings.EqualFold("ClientSecret", f):
		case strings.EqualFold("MaxAge", f):
		case strings.EqualFold("SigningAlgs", f):
		case strings.EqualFold("CallbackUrls", f):
		case strings.EqualFold("AudClaims", f):
		case strings.EqualFold("Certificates", f):
		default:
			return errors.New(errors.InvalidParameter, op, fmt.Sprintf("invalid field mask: %s", f))
		}
	}
	return nil
}

// applyUpdate takes the new and applies it to the orig using the field masks
func applyUpdate(new, orig *AuthMethod, fieldMaskPaths []string) *AuthMethod {
	cp := orig.Clone()
	for _, f := range fieldMaskPaths {
		switch f {
		case "Name":
			cp.Name = new.Name
		case "Description":
			cp.Description = new.Description
		case "DiscoveryUrl":
			cp.DiscoveryUrl = new.DiscoveryUrl
		case "ClientId":
			cp.ClientId = new.ClientId
		case "ClientSecret":
			cp.ClientSecret = new.ClientSecret
		case "MaxAge":
			cp.MaxAge = new.MaxAge
		case "SigningAlgs":
			switch {
			case len(new.SigningAlgs) == 0:
				cp.SigningAlgs = nil
			default:
				cp.SigningAlgs = make([]string, 0, len(new.SigningAlgs))
				cp.SigningAlgs = append(cp.SigningAlgs, new.SigningAlgs...)
			}
		case "CallbackUrls":
			switch {
			case len(new.CallbackUrls) == 0:
				cp.CallbackUrls = nil
			default:
				cp.CallbackUrls = make([]string, 0, len(new.CallbackUrls))
				cp.CallbackUrls = append(cp.CallbackUrls, new.CallbackUrls...)
			}
		case "AudClaims":
			switch {
			case len(new.AudClaims) == 0:
				cp.AudClaims = nil
			default:
				cp.AudClaims = make([]string, 0, len(new.AudClaims))
				cp.AudClaims = append(cp.AudClaims, new.AudClaims...)
			}
		case "Certificates":
			switch {
			case len(new.Certificates) == 0:
				cp.Certificates = nil
			default:
				cp.Certificates = make([]string, 0, len(new.Certificates))
				cp.Certificates = append(cp.Certificates, new.Certificates...)
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
// and user_info endpoints by connecting to each and uses any certificates in the
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
			return errors.Wrap(err, op)
		}
		if am == nil {
			return errors.New(errors.RecordNotFound, op, fmt.Sprintf("unable to lookup auth method %s", opts.withPublicId))
		}
	case opts.withAuthMethod != nil:
		am = opts.withAuthMethod
	default:
		return errors.New(errors.InvalidParameter, op, "neither WithPublicId(...) nor WithAuthMethod(...) options were provided")
	}

	// FYI: once converted to an oidc.Provider, any certs configured will be used as trust anchors for all HTTP requests
	provider, err := convertToProvider(ctx, am)
	if err != nil && am.OperationalState == string(InactiveState) {
		return nil
	}
	if err != nil {
		return errors.Wrap(err, op)
	}

	info, err := provider.DiscoveryInfo(ctx)
	if err != nil {
		return errors.Wrap(err, op)
	}

	var result *multierror.Error
	if info.Issuer != am.DiscoveryUrl {
		result = multierror.Append(result, errors.New(errors.InvalidParameter, op,
			fmt.Sprintf("auth method issuer doesn't match discovery issuer: expected %s and got %s", am.DiscoveryUrl, info.Issuer)))
	}
	for _, a := range am.SigningAlgs {
		if !strutil.StrListContains(info.IdTokenSigningAlgsSupported, a) {
			result = multierror.Append(result, errors.New(errors.InvalidParameter, op,
				fmt.Sprintf("auth method signing alg is not in discovered supported algs: expected %s and got %s", a, info.IdTokenSigningAlgsSupported)))
		}
	}
	providerClient, err := provider.HTTPClient()
	if err != nil {
		result = multierror.Append(result, errors.New(errors.Unknown, op, "unable to get oidc http client", errors.WithWrap(err)))
		return result.ErrorOrNil()
	}

	// we need to prevent redirects during these tests... we don't want to have
	// redirects going to the controller's callback (aka the configured provider's callback)
	providerClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// test JWKs URL
	statusCode, err := pingEndpoint(ctx, providerClient, "JWKs", "GET", info.JWKSURL)
	if err != nil {
		result = multierror.Append(result, errors.New(errors.Unknown, op, fmt.Sprintf("unable to verify JWKs endpoint: %s", info.JWKSURL), errors.WithWrap(err)))
	}
	if statusCode != 200 {
		result = multierror.Append(result, errors.New(errors.Unknown, op, fmt.Sprintf("non-200 status (%d) from JWKs endpoint: %s", statusCode, info.JWKSURL), errors.WithWrap(err)))
	}

	// test Auth URL
	if _, err := pingEndpoint(ctx, providerClient, "AuthURL", "GET", info.AuthURL); err != nil {
		result = multierror.Append(result, errors.New(errors.Unknown, op, fmt.Sprintf("unable to verify authorize endpoint: %s", info.AuthURL), errors.WithWrap(err)))
	}

	// test Token URL
	if _, err := pingEndpoint(ctx, providerClient, "TokenURL", "POST", info.TokenURL); err != nil {
		result = multierror.Append(result, errors.New(errors.Unknown, op, fmt.Sprintf("unable to verify token endpoint: %s", info.TokenURL), errors.WithWrap(err)))
	}

	// we're not verifying the UserInfo URL, since it's not a required dependency.

	return result.ErrorOrNil()
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// pingEndpoint will make an attempted http request, return status code and errors
func pingEndpoint(ctx context.Context, client HTTPClient, endpointType, method, url string) (int, error) {
	const op = "oidc.pingEndpoint"
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, errors.New(errors.Unknown, op, fmt.Sprintf("unable to create %s http request", endpointType), errors.WithWrap(err))
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, errors.New(errors.Unknown, op, fmt.Sprintf("request to %s endpoint failed", endpointType), errors.WithWrap(err))
	}
	return resp.StatusCode, nil
}
