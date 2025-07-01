// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package clientassertion signs JWTs with a Private Key or Client Secret
// for use in OIDC client_assertion requests, A.K.A. private_key_jwt.
// reference: https://oauth.net/private-key-jwt/
package clientassertion

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hashicorp/go-uuid"
)

const (
	// JWTTypeParam is the proper value for client_assertion_type.
	// https://www.rfc-editor.org/rfc/rfc7523.html#section-2.2
	JWTTypeParam = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// NewJWTWithRSAKey creates a new JWT which will be signed with a private key.
//
// alg must be one of:
// * RS256
// * RS384
// * RS512
//
// Supported Options:
// * WithKeyID
// * WithHeaders
func NewJWTWithRSAKey(clientID string, audience []string,
	alg RSAlgorithm, key *rsa.PrivateKey, opts ...Option,
) (*JWT, error) {
	const op = "clientassertion.NewJWTWithRSAKey"

	j := &JWT{
		clientID: clientID,
		audience: audience,
		alg:      jose.SignatureAlgorithm(alg),
		key:      key,
		headers:  make(map[string]string),
		genID:    uuid.GenerateUUID,
		now:      time.Now,
	}

	var errs []error
	if clientID == "" {
		errs = append(errs, ErrMissingClientID)
	}
	if len(audience) == 0 {
		errs = append(errs, ErrMissingAudience)
	}
	if alg == "" {
		errs = append(errs, ErrMissingAlgorithm)
	}

	// rsa-specific
	if key == nil {
		errs = append(errs, ErrMissingKey)
	} else {
		if err := alg.Validate(key); err != nil {
			errs = append(errs, err)
		}
	}

	for _, opt := range opts {
		if err := opt(j); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("%s: %w", op, errors.Join(errs...))
	}

	return j, nil
}

// NewJWTWithHMAC creates a new JWT which will be signed with an HMAC secret.
//
// alg must be one of:
// * HS256 with a >= 32 byte secret
// * HS384 with a >= 48 byte secret
// * HS512 with a >= 64 byte secret
//
// Supported Options:
// * WithKeyID
// * WithHeaders
func NewJWTWithHMAC(clientID string, audience []string,
	alg HSAlgorithm, secret string, opts ...Option,
) (*JWT, error) {
	const op = "clientassertion.NewJWTWithHMAC"
	j := &JWT{
		clientID: clientID,
		audience: audience,
		alg:      jose.SignatureAlgorithm(alg),
		secret:   secret,
		headers:  make(map[string]string),
		genID:    uuid.GenerateUUID,
		now:      time.Now,
	}

	var errs []error
	if clientID == "" {
		errs = append(errs, ErrMissingClientID)
	}
	if len(audience) == 0 {
		errs = append(errs, ErrMissingAudience)
	}
	if alg == "" {
		errs = append(errs, ErrMissingAlgorithm)
	}

	// hmac-specific
	if secret == "" {
		errs = append(errs, ErrMissingSecret)
	} else {
		if err := alg.Validate(secret); err != nil {
			errs = append(errs, err)
		}
	}

	for _, opt := range opts {
		if err := opt(j); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("%s: %w", op, errors.Join(errs...))
	}

	return j, nil
}

// JWT is used to create a client assertion JWT, a special JWT used by an OAuth
// 2.0 or OIDC client to authenticate themselves to an authorization server
type JWT struct {
	// for JWT claims
	clientID string
	audience []string
	headers  map[string]string

	// for signer
	alg jose.SignatureAlgorithm
	// key may be any type that jose.SigningKey accepts for its Key,
	// but today we only support RSA keys.
	key *rsa.PrivateKey
	// secret may be used instead of key
	secret string

	// these are overwritten for testing
	genID func() (string, error)
	now   func() time.Time
}

// Serialize returns client assertion JWT which can be used by an OAuth 2.0 or
// OIDC client to authenticate themselves to an authorization server
func (j *JWT) Serialize() (string, error) {
	const op = "JWT.Serialize"
	signer, err := j.signer()
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	id, err := j.genID()
	if err != nil {
		return "", fmt.Errorf("%s: failed to generate token id: %w", op, err)
	}
	now := j.now().UTC()
	claims := &jwt.Claims{
		Issuer:    j.clientID,
		Subject:   j.clientID,
		Audience:  j.audience,
		Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
		NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Second)),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        id,
	}
	builder := jwt.Signed(signer).Claims(claims)
	token, err := builder.Serialize()
	if err != nil {
		return "", fmt.Errorf("%s: failed to serialize token: %w", op, err)
	}
	return token, nil
}

func (j *JWT) signer() (jose.Signer, error) {
	const op = "signer"
	sKey := jose.SigningKey{
		Algorithm: j.alg,
	}

	// the different New* constructors ensure these are mutually exclusive.
	if j.secret != "" {
		sKey.Key = []byte(j.secret)
	}
	if j.key != nil {
		sKey.Key = j.key
	}

	sOpts := &jose.SignerOptions{
		ExtraHeaders: make(map[jose.HeaderKey]any, len(j.headers)),
	}
	for k, v := range j.headers {
		sOpts.ExtraHeaders[jose.HeaderKey(k)] = v
	}

	signer, err := jose.NewSigner(sKey, sOpts.WithType("JWT"))
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", op, ErrCreatingSigner, err)
	}
	return signer, nil
}

// serializer is the primary interface implemented by JWT.
type serializer interface {
	Serialize() (string, error)
}

// ensure JWT implements Serializer, which is accepted by the oidc option
// oidc.WithClientAssertionJWT.
var _ serializer = &JWT{}
