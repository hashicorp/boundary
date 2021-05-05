package oidc

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
	"github.com/hashicorp/go-multierror"
	kvbuilder "github.com/hashicorp/shared-secure-libs/kv-builder"
	"google.golang.org/protobuf/proto"
)

// defaultAuthMethodTableName defines the default table name for an AuthMethod
const defaultAuthMethodTableName = "auth_oidc_method"

// AuthMethod contains an OIDC auth method configuration. It is owned
// by a scope.  AuthMethods can have Accounts, AudClaims,
// CallbackUrls, Certificates, SigningAlgs.  AuthMethods also have one State at
// any given time which determines it's behavior for many its operations.
type AuthMethod struct {
	*store.AuthMethod
	tableName string
}

// NewAuthMethod creates a new in memory AuthMethod assigned to scopeId.
// WithMaxAge, WithName and WithDescription are the only valid options. All
// other options are ignored.
//
// State equals the state of the OIDC auth method.  State is not a supported
// parameter when creating new AuthMethod's since it must be Inactive for all
// new AuthMethods.
//
// Issuer equals a URL that identifies the OIDC provider.
// Boundary will strip off anything beyond scheme, host and port
//
// ClientId equals an OAuth 2.0 Client Identifier valid at the Authorization
// Server.
//
// ClientSecret equals the client's secret which will be encrypted when stored
// in the database and an hmac representation will also be stored when ever the
// secret changes.  The secret is not returned via the API, the hmac is returned
// so callers can determine if it's been updated.
//
// MaxAge equals the Maximum Authentication Age. Specifies the allowable elapsed
// time in seconds since the last time the End-User was actively authenticated
// by the OP. If the elapsed time is greater than this value, the OP MUST
// attempt to actively re-authenticate the End-User. A value -1 basically
// forces the IdP to re-authenticate the End-User.  Zero is not a valid value.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html
//
// Supports the options of WithMaxAge, WithSigningAlgs, WithAudClaims,
// WithApiUrl and WithCertificates and all other options are ignored.
func NewAuthMethod(scopeId string, clientId string, clientSecret ClientSecret, opt ...Option) (*AuthMethod, error) {
	const op = "oidc.NewAuthMethod"

	opts := getOpts(opt...)
	var u string
	switch {
	case opts.withIssuer != nil:
		// trim off anything beyond scheme, host and port
		u = strings.SplitN(opts.withIssuer.String(), ".well-known/", 2)[0]
	}

	a := &AuthMethod{
		AuthMethod: &store.AuthMethod{
			ScopeId:          scopeId,
			Name:             opts.withName,
			Description:      opts.withDescription,
			OperationalState: string(opts.withOperationalState),
			Issuer:           u,
			ClientId:         clientId,
			ClientSecret:     string(clientSecret),
			MaxAge:           int32(opts.withMaxAge),
			ClaimsScopes:     opts.withClaimsScopes,
		},
	}
	if opts.withApiUrl != nil {
		a.ApiUrl = opts.withApiUrl.String()
	}
	if len(opts.withAudClaims) > 0 {
		a.AudClaims = make([]string, 0, len(opts.withAudClaims))
		a.AudClaims = append(a.AudClaims, opts.withAudClaims...)
	}
	if len(opts.withCertificates) > 0 {
		a.Certificates = make([]string, 0, len(opts.withCertificates))
		pem, err := EncodeCertificates(opts.withCertificates...)
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		a.Certificates = append(a.Certificates, pem...)

	}
	if len(opts.withSigningAlgs) > 0 {
		a.SigningAlgs = make([]string, 0, len(opts.withSigningAlgs))
		for _, alg := range opts.withSigningAlgs {
			a.SigningAlgs = append(a.SigningAlgs, string(alg))
		}
	}
	if len(opts.withAccountClaimMap) > 0 {
		a.AccountClaimMaps = make([]string, 0, len(opts.withAccountClaimMap))
		for k, v := range opts.withAccountClaimMap {
			a.AccountClaimMaps = append(a.AccountClaimMaps, fmt.Sprintf("%s=%s", k, v))
		}
	}
	if a.OperationalState != string(InactiveState) {
		if err := a.isComplete(); err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg("new auth method being created with incomplete data but non-inactive state"))
		}
	}

	if err := a.validate(op); err != nil {
		return nil, err // intentionally not wrapped.
	}
	if a.ClientSecretHmac != "" {
		return nil, errors.New(errors.InvalidParameter, op, "client secret hmac should be empty")
	}
	return a, nil
}

// validate the AuthMethod.  On success, it will return nil. Since setting up an
// OIDC auth method requires a dance with the IdP, where you're need X before you
// can configure Y, we allow things like the discovery URL, client ID, client
// secret, etc to be empty until the AuthMethod moves into a PublicActive state.
// That means validate can't completely ensure the data is valid and ultimately
// we must rely on the database constraints/triggers to ensure the AuthMethod's
// data integrity.
//
// Also, you can't enforce that MaxAge can't equal zero, since the zero value ==
// NULL in the database and that's what you want if it's unset.  A db constraint
// will enforce that MaxAge is either -1, NULL or greater than zero.
func (a *AuthMethod) validate(caller errors.Op) error {
	if a.ScopeId == "" {
		return errors.New(errors.InvalidParameter, caller, "missing scope id")
	}
	if !validState(a.OperationalState) {
		return errors.New(errors.InvalidParameter, caller, fmt.Sprintf("invalid state: %s", a.OperationalState))
	}
	if a.Issuer != "" {
		if _, err := url.Parse(a.Issuer); err != nil {
			return errors.New(errors.InvalidParameter, caller, "not a valid issuer", errors.WithWrap(err))
		}
	}
	if a.ApiUrl != "" {
		if _, err := url.Parse(a.ApiUrl); err != nil {
			return errors.New(errors.InvalidParameter, caller, "not a valid api url", errors.WithWrap(err))
		}
	}
	if a.MaxAge < -1 {
		return errors.New(errors.InvalidParameter, caller, "max age cannot be less than -1")
	}
	return nil
}

// AllocAuthMethod makes an empty one in memory
func AllocAuthMethod() AuthMethod {
	return AuthMethod{
		AuthMethod: &store.AuthMethod{},
	}
}

// Clone an AuthMethod.
func (a *AuthMethod) Clone() *AuthMethod {
	cp := proto.Clone(a.AuthMethod)
	return &AuthMethod{
		AuthMethod: cp.(*store.AuthMethod),
	}
}

// TableName returns the table name.
func (a *AuthMethod) TableName() string {
	if a.tableName != "" {
		return a.tableName
	}
	return defaultAuthMethodTableName
}

// SetTableName sets the table name.
func (a *AuthMethod) SetTableName(n string) {
	a.tableName = n
}

// oplog will create oplog metadata for the AuthMethod.
func (a *AuthMethod) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{a.GetPublicId()},
		"resource-type":      []string{"oidc auth method"},
		"op-type":            []string{op.String()},
		"scope-id":           []string{a.ScopeId},
	}
	return metadata
}

// encrypt the auth method before writing it to the db
func (a *AuthMethod) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "oidc.(AuthMethod).encrypt"
	if cipher == nil {
		return errors.New(errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, a.AuthMethod, nil); err != nil {
		return errors.Wrap(err, op, errors.WithCode(errors.Encrypt))
	}
	a.KeyId = cipher.KeyID()
	if err := a.hmacClientSecret(ctx, cipher); err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}

// decrypt the auth method after reading it from the db
func (a *AuthMethod) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "oidc.(AuthMethod).decrypt"
	if cipher == nil {
		return errors.New(errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.UnwrapStruct(ctx, cipher, a.AuthMethod, nil); err != nil {
		return errors.Wrap(err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

// hmacClientSecret before writing it to the db
func (a *AuthMethod) hmacClientSecret(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "oidc.(AuthMethod).hmacClientSecret"
	if cipher == nil {
		return errors.New(errors.InvalidParameter, op, "missing cipher")
	}
	reader, err := kms.NewDerivedReader(cipher, 32, []byte(a.PublicId), nil)
	if err != nil {
		return errors.Wrap(err, op)
	}
	key, _, err := ed25519.GenerateKey(reader)
	if err != nil {
		return errors.New(errors.Encrypt, op, "unable to generate derived key")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(a.ClientSecret))
	a.ClientSecretHmac = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return nil
}

// isComplete() checks the auth method to see if it has all the required
// components of a complete/valid oidc auth method.
func (am *AuthMethod) isComplete() error {
	const op = "oidc.(AuthMethod).isComplete"
	var result *multierror.Error
	if err := am.validate(op); err != nil {
		result = multierror.Append(result, errors.Wrap(err, op))
	}
	if am.Issuer == "" {
		result = multierror.Append(result, errors.New(errors.InvalidParameter, op, "missing issuer"))
	}
	if am.ApiUrl == "" {
		result = multierror.Append(result, errors.New(errors.InvalidParameter, op, "missing api url"))
	}
	if am.ClientId == "" {
		result = multierror.Append(result, errors.New(errors.InvalidParameter, op, "missing client id"))
	}
	if am.ClientSecret == "" {
		result = multierror.Append(result, errors.New(errors.InvalidParameter, op, "missing client secret"))
	}
	if len(am.SigningAlgs) == 0 {
		result = multierror.Append(result, errors.New(errors.InvalidParameter, op, "missing signing algorithms"))
	}
	return result.ErrorOrNil()
}

type convertedValues struct {
	Algs             []interface{}
	Auds             []interface{}
	Certs            []interface{}
	ClaimsScopes     []interface{}
	AccountClaimMaps []interface{}
}

// convertValueObjects converts the embedded value objects. It will return an
// error if the AuthMethod's public id is not set.
func (am *AuthMethod) convertValueObjects() (*convertedValues, error) {
	const op = "oidc.(AuthMethod).valueObjects"
	if am.PublicId == "" {
		return nil, errors.New(errors.InvalidPublicId, op, "missing public id")
	}
	var err error
	var addAlgs, addAuds, addCerts, addScopes, addAccountClaimMaps []interface{}
	if addAlgs, err = am.convertSigningAlgs(); err != nil {
		return nil, errors.Wrap(err, op)
	}
	if addAuds, err = am.convertAudClaims(); err != nil {
		return nil, errors.Wrap(err, op)
	}
	if addCerts, err = am.convertCertificates(); err != nil {
		return nil, errors.Wrap(err, op)
	}
	if addScopes, err = am.convertClaimsScopes(); err != nil {
		return nil, errors.Wrap(err, op)
	}
	if addAccountClaimMaps, err = am.convertAccountClaimMaps(); err != nil {
		return nil, errors.Wrap(err, op)
	}
	return &convertedValues{
		Algs:             addAlgs,
		Auds:             addAuds,
		Certs:            addCerts,
		ClaimsScopes:     addScopes,
		AccountClaimMaps: addAccountClaimMaps,
	}, nil
}

// convertSigningAlgs converts the embedded signing algorithms from []string
// to []interface{} where each slice element is a *SigningAlg. It will return an
// error if the AuthMethod's public id is not set.
func (am *AuthMethod) convertSigningAlgs() ([]interface{}, error) {
	const op = "oidc.(AuthMethod).convertSigningAlgs"
	if am.PublicId == "" {
		return nil, errors.New(errors.InvalidPublicId, op, "missing public id")
	}
	newInterfaces := make([]interface{}, 0, len(am.SigningAlgs))
	for _, a := range am.SigningAlgs {
		obj, err := NewSigningAlg(am.PublicId, Alg(a))
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		newInterfaces = append(newInterfaces, obj)
	}
	return newInterfaces, nil
}

// convertAudClaims converts the embedded audience claims from []string
// to []interface{} where each slice element is a *AudClaim. It will return an
// error if the AuthMethod's public id is not set.
func (am *AuthMethod) convertAudClaims() ([]interface{}, error) {
	const op = "oidc.(AuthMethod).convertAudClaims"
	if am.PublicId == "" {
		return nil, errors.New(errors.InvalidPublicId, op, "missing public id")
	}
	newInterfaces := make([]interface{}, 0, len(am.AudClaims))
	for _, a := range am.AudClaims {
		obj, err := NewAudClaim(am.PublicId, a)
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		newInterfaces = append(newInterfaces, obj)
	}
	return newInterfaces, nil
}

// convertCertificates converts the embedded certificates from []string
// to []interface{} where each slice element is a *Certificate. It will return an
// error if the AuthMethod's public id is not set.
func (am *AuthMethod) convertCertificates() ([]interface{}, error) {
	const op = "oidc.(AuthMethod).convertCertificates"
	if am.PublicId == "" {
		return nil, errors.New(errors.InvalidPublicId, op, "missing public id")
	}
	newInterfaces := make([]interface{}, 0, len(am.Certificates))
	for _, cert := range am.Certificates {
		obj, err := NewCertificate(am.PublicId, cert)
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		newInterfaces = append(newInterfaces, obj)
	}
	return newInterfaces, nil
}

// convertClaimsScopes converts the embedded claims scopes from []string
// to []interface{} where each slice element is a *ClaimsScope. It will return an
// error if the AuthMethod's public id is not set.
func (am *AuthMethod) convertClaimsScopes() ([]interface{}, error) {
	const op = "oidc.(AuthMethod).convertClaimsScopes"
	if am.PublicId == "" {
		return nil, errors.New(errors.InvalidPublicId, op, "missing public id")
	}
	newInterfaces := make([]interface{}, 0, len(am.ClaimsScopes))
	for _, cs := range am.ClaimsScopes {
		obj, err := NewClaimsScope(am.PublicId, cs)
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		newInterfaces = append(newInterfaces, obj)
	}
	return newInterfaces, nil
}

// convertAccountClaimMaps converts the embedded account claim maps from
// []string to []interface{} where each slice element is a *AccountClaimMap. It
// will return an error if the AuthMethod's public id is not set or it can
// convert the account claim maps.
func (am *AuthMethod) convertAccountClaimMaps() ([]interface{}, error) {
	const op = "oidc.(AuthMethod).convertAccountClaimMaps"
	if am.PublicId == "" {
		return nil, errors.New(errors.InvalidPublicId, op, "missing public id")
	}
	newInterfaces := make([]interface{}, 0, len(am.AccountClaimMaps))
	const (
		from = 0
		to   = 1
	)
	acms, err := ParseAccountClaimMaps(am.AccountClaimMaps...)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	for from, to := range acms {
		toClaim, err := ConvertToAccountToClaim(to)
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		obj, err := NewAccountClaimMap(am.PublicId, from, toClaim)
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		newInterfaces = append(newInterfaces, obj)
	}
	return newInterfaces, nil
}

func ParseAccountClaimMaps(m ...string) (map[string]string, error) {
	const op = "oidc.parseAccountClaimMaps"
	var b kvbuilder.Builder
	if err := b.Add(m...); err != nil {
		return nil, errors.New(errors.InvalidParameter, op, "error parsing map", errors.WithWrap(err))
	}
	claimMap := map[string]string{}
	for k, v := range b.Map() {
		var ok bool
		if claimMap[k], ok = v.(string); !ok {
			return nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("account claim map key %s value %q is not a string", k, v))
		}
	}
	return claimMap, nil
}
