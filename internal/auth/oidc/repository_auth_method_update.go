package oidc

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
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
// zero value and included in fieldMask. Name, Description, State, DiscoveryUrl,
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
func (r *Repository) UpdateAuthMethod(ctx context.Context, m *AuthMethod, version uint32, fieldMaskPaths []string, _ ...Option) (*AuthMethod, int, error) {
	const op = "oidc.(Repository).UpdateAuthMethod"
	if m == nil {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing auth method")
	}
	if m.AuthMethod == nil {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing auth method store")
	}
	if m.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing public id")
	}
	if err := m.validate(op); err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("Name", f):
		case strings.EqualFold("Description", f):
		case strings.EqualFold("State", f):
		case strings.EqualFold("DiscoveryUrl", f):
		case strings.EqualFold("ClientId", f):
		case strings.EqualFold("ClientSecret", f):
		case strings.EqualFold("MaxAge", f):
		case strings.EqualFold("SigningAlgs", f):
		case strings.EqualFold("CallbackUrls", f):
		case strings.EqualFold("AudClaims", f):
		case strings.EqualFold("Certificates", f):
		default:
			return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, fmt.Sprintf("invalid field mask: %s", f))
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"Name":             m.Name,
			"Description":      m.Description,
			"OperationalState": m.OperationalState,
			"DiscoveryUrl":     m.DiscoveryUrl,
			"ClientId":         m.ClientId,
			"ClientSecret":     m.ClientSecret,
			"MaxAge":           m.MaxAge,
			"SigningAlgs":      m.SigningAlgs,
			"CallbackUrls":     m.CallbackUrls,
			"AudClaims":        m.AudClaims,
			"Certificates":     m.Certificates,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(errors.EmptyFieldMask, op, "empty field mask")
	}

	origAm, err := r.lookupAuthMethod(ctx, m.PublicId)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}

	databaseWrapper, err := r.kms.GetWrapper(ctx, origAm.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get database wrapper"))
	}
	if err := m.encrypt(ctx, databaseWrapper); err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}
	panic("to-do")
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

	panic("to-do")

	// waiting for https://github.com/hashicorp/cap/pull/21 to merge
	// info, err := provider.DiscoveryInfo(ctx)
	// if err != nil {
	// 	return errors.Wrap(err, op)
	// }

	var info *DiscoveryInfo
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

type DiscoveryInfo struct {
	Issuer                      string   `json:"issuer"`
	AuthURL                     string   `json:"authorization_endpoint"`
	TokenURL                    string   `json:"token_endpoint"`
	UserInfoURL                 string   `json:"userinfo_endpoint,omitempty"`
	JWKSURL                     string   `json:"jwks_uri"`
	ScopesSupported             []string `json:"scopes_supported,omitempty"`
	GrantTypesSupported         []string `json:"grant_types_supported,omitempty"`
	IdTokenSigningAlgsSupported []string `json:"id_token_signing_alg_values_supported"`
	DisplayValuesSupported      []string `json:"display_values_supported,omitempty"`
	UILocalesSupported          []string `json:"ui_locales_supported,,omitempty"`
	ClaimsParameterSupported    bool     `json:"claims_supported"`
	AcrValuesSupported          []string `json:"acr_values_supported,omitempty"`
}
