// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/libs/crypto"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	kvbuilder "github.com/hashicorp/go-secure-stdlib/kv-builder"
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
func NewAuthMethod(ctx context.Context, scopeId string, clientId string, clientSecret ClientSecret, opt ...Option) (*AuthMethod, error) {
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
		pem, err := EncodeCertificates(ctx, opts.withCertificates...)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		a.Certificates = append(a.Certificates, pem...)

	}
	if len(opts.withSigningAlgs) > 0 {
		a.SigningAlgs = make([]string, 0, len(opts.withSigningAlgs))
		for _, alg := range opts.withSigningAlgs {
			a.SigningAlgs = append(a.SigningAlgs, string(alg))
		}
	}
	if len(opts.withPrompts) > 0 {
		a.Prompts = make([]string, 0, len(opts.withPrompts))
		for _, prompts := range opts.withPrompts {
			a.Prompts = append(a.Prompts, string(prompts))
		}
	}
	if len(opts.withAccountClaimMap) > 0 {
		a.AccountClaimMaps = make([]string, 0, len(opts.withAccountClaimMap))
		for k, v := range opts.withAccountClaimMap {
			a.AccountClaimMaps = append(a.AccountClaimMaps, fmt.Sprintf("%s=%s", k, v))
		}
	}
	if a.OperationalState != string(InactiveState) {
		if err := a.isComplete(ctx); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("new auth method being created with incomplete data but non-inactive state"))
		}
	}

	if err := a.validate(ctx, op); err != nil {
		return nil, err // intentionally not wrapped.
	}
	if a.ClientSecretHmac != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "client secret hmac should be empty")
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
func (am *AuthMethod) validate(ctx context.Context, caller errors.Op) error {
	if am.ScopeId == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing scope id")
	}
	if !validState(am.OperationalState) {
		return errors.New(ctx, errors.InvalidParameter, caller, fmt.Sprintf("invalid state: %s", am.OperationalState))
	}
	if am.Issuer != "" {
		if _, err := url.Parse(am.Issuer); err != nil {
			return errors.New(ctx, errors.InvalidParameter, caller, "not a valid issuer", errors.WithWrap(err))
		}
	}
	if am.ApiUrl != "" {
		if _, err := url.Parse(am.ApiUrl); err != nil {
			return errors.New(ctx, errors.InvalidParameter, caller, "not a valid api url", errors.WithWrap(err))
		}
	}
	if am.MaxAge < -1 {
		return errors.New(ctx, errors.InvalidParameter, caller, "max age cannot be less than -1")
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
func (am *AuthMethod) Clone() *AuthMethod {
	cp := proto.Clone(am.AuthMethod)
	return &AuthMethod{
		AuthMethod: cp.(*store.AuthMethod),
	}
}

// TableName returns the table name.
func (am AuthMethod) TableName() string {
	if am.tableName != "" {
		return am.tableName
	}
	return defaultAuthMethodTableName
}

// SetTableName sets the table name.
func (am *AuthMethod) SetTableName(n string) {
	am.tableName = n
}

// GetResourceType returns the resource type of the AuthMethod
func (am AuthMethod) GetResourceType() resource.Type {
	return resource.AuthMethod
}

// oplog will create oplog metadata for the AuthMethod.
func (am *AuthMethod) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{am.GetPublicId()},
		"resource-type":      []string{"oidc auth method"},
		"op-type":            []string{op.String()},
		"scope-id":           []string{am.ScopeId},
	}
	return metadata
}

// encrypt the auth method before writing it to the db
func (am *AuthMethod) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "oidc.(AuthMethod).encrypt"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, am.AuthMethod, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	keyId, err := cipher.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("failed to read cipher key id"))
	}
	am.KeyId = keyId
	if err := am.hmacClientSecret(ctx, cipher); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// decrypt the auth method after reading it from the db
func (am *AuthMethod) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "oidc.(AuthMethod).decrypt"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.UnwrapStruct(ctx, cipher, am.AuthMethod, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

// hmacClientSecret before writing it to the db
func (am *AuthMethod) hmacClientSecret(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "oidc.(AuthMethod).hmacClientSecret"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	// this operation currently uses the legacy WithEd25519 option for hmac'ing.
	// we should likely deprecate this and introduce a new "crypto version" of
	// this attribute.
	hm, err := crypto.HmacSha256(ctx, []byte(am.ClientSecret), cipher, []byte(am.PublicId), nil, crypto.WithBase64Encoding(), crypto.WithEd25519())
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Code(errors.Encryption)))
	}
	am.ClientSecretHmac = hm
	return nil
}

// isComplete() checks the auth method to see if it has all the required
// components of a complete/valid oidc auth method.
func (am *AuthMethod) isComplete(ctx context.Context) error {
	const op = "oidc.(AuthMethod).isComplete"
	var result error
	if err := am.validate(ctx, op); err != nil {
		result = stderrors.Join(result, errors.Wrap(ctx, err, op))
	}
	if am.Issuer == "" {
		result = stderrors.Join(result, errors.New(ctx, errors.InvalidParameter, op, "missing issuer"))
	}
	if am.ApiUrl == "" {
		result = stderrors.Join(result, errors.New(ctx, errors.InvalidParameter, op, "missing api url"))
	}
	if am.ClientId == "" {
		result = stderrors.Join(result, errors.New(ctx, errors.InvalidParameter, op, "missing client id"))
	}
	if am.ClientSecret == "" {
		result = stderrors.Join(result, errors.New(ctx, errors.InvalidParameter, op, "missing client secret"))
	}
	if len(am.SigningAlgs) == 0 {
		result = stderrors.Join(result, errors.New(ctx, errors.InvalidParameter, op, "missing signing algorithms"))
	}
	return result
}

type convertedValues struct {
	Algs             []*SigningAlg
	Auds             []*AudClaim
	Certs            []*Certificate
	ClaimsScopes     []*ClaimsScope
	AccountClaimMaps []*AccountClaimMap
	Prompts          []*Prompt
}

// convertValueObjects converts the embedded value objects. It will return an
// error if the AuthMethod's public id is not set.
func (am *AuthMethod) convertValueObjects(ctx context.Context) (*convertedValues, error) {
	const op = "oidc.(AuthMethod).valueObjects"
	if am.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	var err error
	converted := &convertedValues{}
	if converted.Algs, err = am.convertSigningAlgs(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if converted.Auds, err = am.convertAudClaims(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if converted.Certs, err = am.convertCertificates(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if converted.ClaimsScopes, err = am.convertClaimsScopes(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if converted.AccountClaimMaps, err = am.convertAccountClaimMaps(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if converted.Prompts, err = am.convertPrompts(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return converted, nil
}

// convertSigningAlgs converts the embedded signing algorithms from []string
// to []*SigningAlg. It will return an error if the AuthMethod's public id is
// not set.
func (am *AuthMethod) convertSigningAlgs(ctx context.Context) ([]*SigningAlg, error) {
	const op = "oidc.(AuthMethod).convertSigningAlgs"
	if am.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	newAlgs := make([]*SigningAlg, 0, len(am.SigningAlgs))
	for _, a := range am.SigningAlgs {
		obj, err := NewSigningAlg(ctx, am.PublicId, Alg(a))
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		newAlgs = append(newAlgs, obj)
	}
	return newAlgs, nil
}

// convertAudClaims converts the embedded audience claims from []string
// to []*AudClaim. It will return an error if the AuthMethod's public id is not
// set.
func (am *AuthMethod) convertAudClaims(ctx context.Context) ([]*AudClaim, error) {
	const op = "oidc.(AuthMethod).convertAudClaims"
	if am.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	newClaims := make([]*AudClaim, 0, len(am.AudClaims))
	for _, a := range am.AudClaims {
		obj, err := NewAudClaim(ctx, am.PublicId, a)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		newClaims = append(newClaims, obj)
	}
	return newClaims, nil
}

// convertCertificates converts the embedded certificates from []string
// to []*Certificate. It will return an error if the AuthMethod's public id is
// not set.
func (am *AuthMethod) convertCertificates(ctx context.Context) ([]*Certificate, error) {
	const op = "oidc.(AuthMethod).convertCertificates"
	if am.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	newCerts := make([]*Certificate, 0, len(am.Certificates))
	for _, cert := range am.Certificates {
		obj, err := NewCertificate(ctx, am.PublicId, cert)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		newCerts = append(newCerts, obj)
	}
	return newCerts, nil
}

// convertClaimsScopes converts the embedded claims scopes from []string
// to []*ClaimsScope. It will return an error if the AuthMethod's public id is
// not set.
func (am *AuthMethod) convertClaimsScopes(ctx context.Context) ([]*ClaimsScope, error) {
	const op = "oidc.(AuthMethod).convertClaimsScopes"
	if am.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	newClaimsScopes := make([]*ClaimsScope, 0, len(am.ClaimsScopes))
	for _, cs := range am.ClaimsScopes {
		obj, err := NewClaimsScope(ctx, am.PublicId, cs)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		newClaimsScopes = append(newClaimsScopes, obj)
	}
	return newClaimsScopes, nil
}

// convertAccountClaimMaps converts the embedded account claim maps from
// []string to []*AccountClaimMap. It will return an error if the AuthMethod's
// public id is not set or it can convert the account claim maps.
func (am *AuthMethod) convertAccountClaimMaps(ctx context.Context) ([]*AccountClaimMap, error) {
	const op = "oidc.(AuthMethod).convertAccountClaimMaps"
	if am.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	newAccountClaimMaps := make([]*AccountClaimMap, 0, len(am.AccountClaimMaps))
	acms, err := ParseAccountClaimMaps(ctx, am.AccountClaimMaps...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	for _, m := range acms {
		toClaim, err := ConvertToAccountToClaim(ctx, m.To)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		obj, err := NewAccountClaimMap(ctx, am.PublicId, m.From, toClaim)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		newAccountClaimMaps = append(newAccountClaimMaps, obj)
	}
	return newAccountClaimMaps, nil
}

// ClaimMap defines the To and From of an oidc claim map
type ClaimMap struct {
	To   string
	From string
}

// ParseAccountClaimMaps will parse the inbound claim maps
func ParseAccountClaimMaps(ctx context.Context, m ...string) ([]ClaimMap, error) {
	const op = "oidc.parseAccountClaimMaps"
	var b kvbuilder.Builder
	if err := b.Add(m...); err != nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "error parsing map", errors.WithWrap(err))
	}
	fromKeys := make([]string, 0, len(m))
	for k := range b.Map() {
		fromKeys = append(fromKeys, k)
	}
	sort.Strings(fromKeys)

	claimMap := make([]ClaimMap, 0, len(fromKeys))
	for _, from := range fromKeys {
		var ok bool
		to, ok := b.Map()[from].(string)
		if !ok {
			return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("account claim map %s value %q is not a string", from, b.Map()[from]))
		}
		claimMap = append(claimMap, ClaimMap{
			To:   to,
			From: from,
		})
	}
	return claimMap, nil
}

// convertPrompts converts the embedded prompts from []string
// to []*Prompt. It will return an error if the AuthMethod's public id is not
// set.
func (am *AuthMethod) convertPrompts(ctx context.Context) ([]*Prompt, error) {
	const op = "oidc.(AuthMethod).convertPrompts"
	if am.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	newPrompts := make([]*Prompt, 0, len(am.Prompts))
	for _, a := range am.Prompts {
		obj, err := NewPrompt(ctx, am.PublicId, PromptParam(a))
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		newPrompts = append(newPrompts, obj)
	}
	return newPrompts, nil
}
