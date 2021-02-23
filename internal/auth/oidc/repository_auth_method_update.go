package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/go-multierror"
)

// UpdateAuthMethod will retrieve the auth method from the repository,
// update it based on the field masks provided, and then validate it using
// Repository.TestAuthMethod(...).  If the test succeeds, the auth method
// is persisted in the repository and the written auth method is returned.
// fieldMaskPaths provides field_mask.proto paths for fields that should
// be updated.  Fields will be set to NULL if the field is a
// zero value and included in fieldMask. Name, Description, OperationalState, DiscoveryUrl,
// ClientId, ClientSecret, MaxAge are all updatable fields.  The AuthMethod's
// Value Objects of SigningAlgs, CallbackUrls, AudClaims and Certificates are
// also updatable. if no updatable fields are included in the fieldMaskPaths,
// then an error is returned.
//
// Options supported:
//
// * WithDryRun: when this option is provided, the auth method is retrieved from
// the repo, updated based on the fieldMask, tested via Repository.TestAuthMethod
// and any errors reported.  The updates are not peristed to the repository.
//
// * WithForce: when this option is provided, the auth method is persistented in
// the repository without testing it fo validity with Repository.TestAuthMethod.
//
// Successful updates must invalidate (delete) the Repository's cache of the
// oidc.Provider for the AuthMethod.
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
	if err := am.validate(op); err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}

	if err := updatableAuthMethodFields(fieldMaskPaths); err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}

	dbMask, nullFields := dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"Name":             am.Name,
			"Description":      am.Description,
			"OperationalState": am.OperationalState,
			"DiscoveryUrl":     am.DiscoveryUrl,
			"ClientId":         am.ClientId,
			"ClientSecret":     am.ClientSecret,
			"MaxAge":           am.MaxAge,
			"SigningAlgs":      am.SigningAlgs,
			"CallbackUrls":     am.CallbackUrls,
			"AudClaims":        am.AudClaims,
			"Certificates":     am.Certificates,
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
	if !opts.withForce {
		if err := r.TestAuthMethod(ctx, WithAuthMethod(applyUpdate(am, origAm, fieldMaskPaths))); err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(err, op)
		}
	}

	fac := func(publicId string, i interface{}) (interface{}, error) {
		str := fmt.Sprintf("%s", i)
		return NewSigningAlg(publicId, Alg(str))
	}
	addAlgs, deleteAlgs, err := valueObjectChanges(fac, origAm.PublicId, "SigningAlgs", am.SigningAlgs, origAm.SigningAlgs, dbMask, nullFields)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}

	fac = func(publicId string, i interface{}) (interface{}, error) {
		pem := fmt.Sprintf("%s", i)
		return NewCertificate(publicId, pem)
	}
	addCerts, deleteCerts, err := valueObjectChanges(fac, origAm.PublicId, "Certificates", am.Certificates, origAm.Certificates, dbMask, nullFields)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}

	fac = func(publicId string, i interface{}) (interface{}, error) {
		u, err := url.Parse(fmt.Sprintf("%s", i))
		if err != nil {
			return nil, err
		}
		return NewCallbackUrl(publicId, u)
	}
	addCallbacks, deleteCallbacks, err := valueObjectChanges(fac, origAm.PublicId, "CallbackUrls", am.CallbackUrls, origAm.CallbackUrls, dbMask, nullFields)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}

	fac = func(publicId string, i interface{}) (interface{}, error) {
		str := fmt.Sprintf("%s", i)
		return NewAudClaim(publicId, str)
	}
	addAuds, deleteAuds, err := valueObjectChanges(fac, origAm.PublicId, "AudClaims", am.AudClaims, origAm.AudClaims, dbMask, nullFields)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}

	// foundAlgs := map[string]bool{}
	// for _, a := range origAm.SigningAlgs {
	// 	foundAlgs[a] = true
	// }
	// var addAlgs []interface{}
	// var deleteAlgs []interface{}
	// if strutil.StrListContains(nullFields, "SigningAlgs") {
	// 	deleteAlgs = make([]interface{}, 0, len(origAm.SigningAlgs))
	// 	for _, a := range origAm.SigningAlgs {
	// 		alg, err := NewSigningAlg(origAm.PublicId, Alg(a))
	// 		if err != nil {
	// 			return nil, db.NoRowsAffected, errors.Wrap(err, op)
	// 		}
	// 		deleteAlgs = append(deleteAlgs, alg)
	// 		delete(foundAlgs, a)
	// 	}
	// }
	// if strutil.StrListContains(dbMask, "SigningAlgs") {
	// 	addAlgs = make([]interface{}, 0, len(am.SigningAlgs))
	// 	for _, a := range am.SigningAlgs {
	// 		if _, ok := foundAlgs[a]; ok {
	// 			delete(foundAlgs, a)
	// 			continue
	// 		}
	// 		alg, err := NewSigningAlg(origAm.PublicId, Alg(a))
	// 		if err != nil {
	// 			return nil, db.NoRowsAffected, errors.Wrap(err, op)
	// 		}
	// 		addAlgs = append(addAlgs, alg)
	// 		delete(foundAlgs, a)
	// 	}
	// }
	// if len(foundAlgs) > 0 {
	// 	for a := range foundAlgs {
	// 		alg, err := NewSigningAlg(origAm.PublicId, Alg(a))
	// 		if err != nil {
	// 			return nil, db.NoRowsAffected, errors.Wrap(err, op)
	// 		}
	// 		deleteAlgs = append(deleteAlgs, alg)
	// 		delete(foundAlgs, a)
	// 	}
	// }

	var filteredDbMask, filteredNullFields []string
	for _, f := range dbMask {
		switch f {
		case "SigningAlgs", "CallbackUrls", "AudClaims", "Certificates":
			continue
		default:
			filteredDbMask = append(filteredDbMask, f)
		}
	}

	databaseWrapper, err := r.kms.GetWrapper(ctx, origAm.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get database wrapper"))
	}
	if err := am.encrypt(ctx, databaseWrapper); err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, origAm.PublicId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	var updatedAm *AuthMethod
	var rowsUpdated int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 9) // AuthMethod, Algs*2, Certs*2, Callbacks*2, Audiences*2
			ticket, err := w.GetTicket(&am)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to get ticket"))
			}
			updatedAm = am.Clone()
			var authMethodOplogMsg oplog.Message
			dbMask = append(dbMask, "Version")
			rowsUpdated, err := w.Update(ctx, updatedAm, filteredDbMask, filteredNullFields, db.NewOplogMsg(&authMethodOplogMsg), db.WithVersion(&version))
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to update auth method"))
			}
			if rowsUpdated != 1 {
				return errors.New(errors.MultipleRecords, op, fmt.Sprintf("updated auth method and %d rows updated", rowsUpdated))
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
			return nil
		},
	)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}
	return updatedAm, rowsUpdated, nil
}

func valueObjectChanges(
	factory func(string, interface{}) (interface{}, error),
	publicId,
	valueObjectName string,
	newVOs,
	origVOs,
	dbMask,
	nullFields []string,
) (add []interface{}, del []interface{}, e error) {
	const op = "valueObjectChanges"
	foundVOs := map[string]bool{}
	for _, a := range origVOs {
		foundVOs[a] = true
	}
	var adds []interface{}
	var deletes []interface{}
	if strutil.StrListContains(nullFields, valueObjectName) {
		deletes = make([]interface{}, 0, len(origVOs))
		for _, a := range origVOs {
			alg, err := factory(publicId, a)
			if err != nil {
				return nil, nil, errors.Wrap(err, op)
			}
			deletes = append(deletes, alg)
			delete(foundVOs, a)
		}
	}
	if strutil.StrListContains(dbMask, valueObjectName) {
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

// updatableAuthMethodFields check the field mask to ensure all the fields are updatable
func updatableAuthMethodFields(fieldMaskPaths []string) error {
	const op = "validateFieldMask"
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("Name", f):
		case strings.EqualFold("Description", f):
		case strings.EqualFold("OperationalState", f):
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

func applyUpdate(new, orig *AuthMethod, fieldMaskPaths []string) *AuthMethod {
	cp := orig.Clone()
	for _, f := range fieldMaskPaths {
		switch f {
		case "Name":
			cp.Name = new.Name
		case "Description":
			cp.Description = new.Description
		case "OperationalState":
			cp.OperationalState = new.OperationalState
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

// TestAuthMethod will test/validate the provided AuthMethod.
//
// It will verify that all required fields for a working AuthMethod have values.
//
// If the AuthMethod contains a DiscoveryUrl for an OIDC provider, TestAuthMethod
// retrieves the OpenID Configuration document. The values in the AuthMethod
// (and associated data) are validated with the retrieved document. The issuer and
// id token signing algorithm in the configuration are validated with the
// retrieved document. TestAuthMethod also verifies the authorization, token,
// and user_info endpoints by connecting to each and uses any certificates in the
// configuration as trust anchors to confirm connectivity.
//
// Options supported are: WithPublicId, WithAuthMethod
func (r *Repository) TestAuthMethod(ctx context.Context, opt ...Option) error {
	const op = "oidc.(Repository).TestAuthMethod"
	opts := getOpts()
	var am *AuthMethod
	switch {
	case opts.withPublicId != "":
		var err error
		am, err = r.lookupAuthMethod(ctx, opts.withPublicId, nil)
		if err != nil {
			return errors.Wrap(err, op)
		}
	case opts.withAuthMethod != nil:
		am = opts.withAuthMethod
	default:
		return errors.New(errors.InvalidParameter, op, "neither WithPublicId(...) nor WithAuthMethod(...) options were provided")
	}

	if err := am.isComplete(); err != nil {
		return errors.Wrap(err, op)
	}

	// FYI: once converted to an oidc.Provider, any certs configured will be used as trust anchors for all HTTP requests
	provider, err := convertToProvider(ctx, am)
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
	oidcRequest, err := oidc.NewRequest(10*time.Second, am.CallbackUrls[0])
	if err != nil {
		result = multierror.Append(result, errors.New(errors.Unknown, op, "unable to create oidc request", errors.WithWrap(err)))
		return result.ErrorOrNil()
	}

	// test JWKs URL
	if err := pingEndpoint(ctx, providerClient, "JWKs", "GET", info.JWKSURL); err != nil {
		result = multierror.Append(result, errors.New(errors.Unknown, op, fmt.Sprintf("unable to verify JWKs endpoint: %s", info.JWKSURL), errors.WithWrap(err)))
		return result.ErrorOrNil()
	}

	// test oidc auth URL
	authUrl, err := provider.AuthURL(ctx, oidcRequest)
	if err != nil {
		result = multierror.Append(result, errors.New(errors.Unknown, op, "unable to create oidc auth URL", errors.WithWrap(err)))
		return result.ErrorOrNil()
	}
	if err := pingEndpoint(ctx, providerClient, "AuthURL", "GET", authUrl); err != nil {
		result = multierror.Append(result, errors.New(errors.Unknown, op, fmt.Sprintf("unable to verify authorize endpoint: %s", info.AuthURL), errors.WithWrap(err)))
	}

	// test Token URL
	if err := pingEndpoint(ctx, providerClient, "TokenURL", "POST", info.TokenURL); err != nil {
		result = multierror.Append(result, errors.New(errors.Unknown, op, fmt.Sprintf("unable to verify token endpoint: %s", info.TokenURL), errors.WithWrap(err)))
	}

	// we're not verifying the UserInfo URL, since it's not a required dependency.

	return result.ErrorOrNil()
}

func pingEndpoint(ctx context.Context, client *http.Client, endpointType, method, url string) error {
	const op = "oidc.pingEndpoint"
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return errors.New(errors.Unknown, op, fmt.Sprintf("unable to create %s http request", endpointType), errors.WithWrap(err))
	}
	_, err = client.Do(req)
	if err != nil {
		return errors.New(errors.Unknown, op, fmt.Sprintf("request to %s endpoint failed", endpointType), errors.WithWrap(err))
	}
	return nil
}
