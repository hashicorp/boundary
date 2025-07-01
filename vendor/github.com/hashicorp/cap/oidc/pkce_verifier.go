// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"

	"github.com/hashicorp/cap/oidc/internal/base62"
)

// ChallengeMethod represents PKCE code challenge methods as defined by RFC
// 7636.
type ChallengeMethod string

const (
	// PKCE code challenge methods as defined by RFC 7636.
	//
	// See: https://tools.ietf.org/html/rfc7636#page-9
	S256 ChallengeMethod = "S256" // SHA-256
)

// CodeVerifier represents an OAuth PKCE code verifier.
//
// See: https://tools.ietf.org/html/rfc7636#section-4.1
type CodeVerifier interface {
	// Verifier returns the code verifier (see:
	// https://tools.ietf.org/html/rfc7636#section-4.1)
	Verifier() string

	// Challenge returns the code verifier's code challenge (see:
	// https://tools.ietf.org/html/rfc7636#section-4.2)
	Challenge() string

	// Method returns the code verifier's challenge method (see
	// https://tools.ietf.org/html/rfc7636#section-4.2)
	Method() ChallengeMethod

	// Copy returns a copy of the verifier
	Copy() CodeVerifier
}

// S256Verifier represents an OAuth PKCE code verifier that uses the S256
// challenge method.  It implements the CodeVerifier interface.
type S256Verifier struct {
	verifier  string
	challenge string
	method    ChallengeMethod
}

// min len of 43 chars per https://tools.ietf.org/html/rfc7636#section-4.1
const (
	// min len of 43 chars per https://tools.ietf.org/html/rfc7636#section-4.1
	minVerifierLen = 43
	// max len of 128 chars per https://tools.ietf.org/html/rfc7636#section-4.1
	maxVerifierLen = 128
)

// NewCodeVerifier creates a new CodeVerifier (*S256Verifier).
// Supported options: WithVerifier
//
// See: https://tools.ietf.org/html/rfc7636#section-4.1
func NewCodeVerifier(opt ...Option) (*S256Verifier, error) {
	const op = "NewCodeVerifier"
	var (
		err          error
		verifierData string
	)
	opts := getPKCEOpts(opt...)
	switch {
	case opts.withVerifier != "":
		verifierData = opts.withVerifier
	default:
		var err error
		verifierData, err = base62.Random(minVerifierLen)
		if err != nil {
			return nil, fmt.Errorf("%s: unable to create verifier data %w", op, err)
		}
	}
	if err := verifierIsValid(verifierData); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	v := &S256Verifier{
		verifier: verifierData, // no need to encode it, since bas62.Random uses a limited set of characters.
		method:   S256,
	}
	if v.challenge, err = CreateCodeChallenge(v); err != nil {
		return nil, fmt.Errorf("%s: unable to create code challenge: %w", op, err)
	}
	return v, nil
}

func verifierIsValid(v string) error {
	const op = "verifierIsValid"
	switch {
	case len(v) < minVerifierLen:
		return fmt.Errorf("%s: verifier length is less than %d", op, minVerifierLen)
	case len(v) > maxVerifierLen:
		return fmt.Errorf("%s: verifier length is greater than %d", op, maxVerifierLen)
	default:
		// check that the verifier is valid based on
		// https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
		// Check for valid characters: A-Z, a-z, 0-9, -, _, ., ~
		validChars := regexp.MustCompile(`^[A-Za-z0-9\-\._~]+$`)
		if !validChars.MatchString(v) {
			return fmt.Errorf("%s: verifier contains invalid characters", op)
		}
	}
	return nil
}

func (v *S256Verifier) Verifier() string        { return v.verifier }  // Verifier implements the CodeVerifier.Verifier() interface function.
func (v *S256Verifier) Challenge() string       { return v.challenge } // Challenge implements the CodeVerifier.Challenge() interface function.
func (v *S256Verifier) Method() ChallengeMethod { return v.method }    // Method implements the CodeVerifier.Method() interface function.

// Copy returns a copy of the verifier.
func (v *S256Verifier) Copy() CodeVerifier {
	return &S256Verifier{
		verifier:  v.verifier,
		challenge: v.challenge,
		method:    v.method,
	}
}

// CreateCodeChallenge creates a code challenge from the verifier. Supported
// ChallengeMethods: S256
//
// See: https://tools.ietf.org/html/rfc7636#section-4.2
func CreateCodeChallenge(v CodeVerifier) (string, error) {
	// currently, we only support S256
	if v.Method() != S256 {
		return "", fmt.Errorf("CreateCodeChallenge: %s is invalid: %w", v.Method(), ErrUnsupportedChallengeMethod)
	}
	h := sha256.New()
	_, _ = h.Write([]byte(v.Verifier())) // hash documents that Write will never return an Error
	sum := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// pkceOptions is the set of available options.
type pkceOptions struct {
	withVerifier string
}

// pkceDefaults is a handy way to get the defaults at runtime and
// during unit tests.
func pkceDefaults() pkceOptions {
	return pkceOptions{}
}

// getPKCEOpts gets the defaults and applies the opt overrides passed in.
func getPKCEOpts(opt ...Option) pkceOptions {
	opts := pkceDefaults()
	ApplyOpts(&opts, opt...)
	return opts
}

// WithVerifier provides an optional verifier for the code verifier.  When this
// option is provided, NewCodeVerifier will use the provided verifier. Note the
// verifier must use the base62 character set.
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
//
// Valid for: NewVerifier
func WithVerifier(verifier string) Option {
	return func(o interface{}) {
		if o, ok := o.(*pkceOptions); ok {
			o.withVerifier = verifier
		}
	}
}
