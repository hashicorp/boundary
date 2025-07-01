// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package nodeenrollment

import (
	"errors"
	"time"
)

type KnownId string

const (
	MissingId KnownId = ""

	// CurrentId is a const for when we are fetching the "current" value for
	// various purposes
	CurrentId KnownId = "current"

	// NextId is a const for when we are fetching the "next" value for various
	// purposes
	NextId KnownId = "next"
)

const (
	// DefaultNotBeforeClockSkewDuration is the time to subtract from NotBefore to account for
	// some clock skew
	DefaultNotBeforeClockSkewDuration = -5 * time.Minute

	// DefaultNotAfterClockSkewDuration is the time to subtract from NotBefore to account for
	// some clock skew
	DefaultNotAfterClockSkewDuration = 5 * time.Minute

	// DefaultCertificateLifetime is the default duration of a certificate, set
	// to two weeks. Rotations should happen at roughly half this.
	DefaultCertificateLifetime = time.Hour * 24 * 14

	// This is the default time that an server-led activation token is alive
	DefaultMaximumServerLedActivationTokenLifetime = time.Hour * 24 * 14

	// CommonDnsName is a name we can use in the absence of anything more
	// specific. In most cases we actually do not care about common name or DNS
	// SAN verification, and when we do we have an explicit test for it. In all
	// other cases using this allows us to not fail due to name validity checks.
	// Derived loosely from the Wizard in The Wizard of Oz.
	CommonDnsName = "pay-no-attention-to-that-pers-on-behind-the-curt-on"

	// FetchNodeCredsNextProtoV1Prefix is the ALPN NextProto used when a node is
	// trying to fetch credentials
	FetchNodeCredsNextProtoV1Prefix = "v1-nodee-fetch-node-creds-"

	// AuthenticateNodeNextProtoV1Prefix is the ALPN NextProto used when a node
	// is trying to authenticate
	AuthenticateNodeNextProtoV1Prefix = "v1-nodee-authenticate-node-"

	// CertificatePreferenceV1Prefix is the ALPN NextProto used by a node to
	// indicate a certificate preference, since we can't use ServerName
	CertificatePreferenceV1Prefix = "v1-nodee-certificate-preference-"

	// NonceSize is our defined nonce size, in bytes
	NonceSize = 32

	// KeyIdNumWords is the number of words to generate from a hash of the
	// public key to serve as the key ID
	KeyIdNumWords = 8

	// The ID that will always be used for storing root certificate messages
	RootsMessageId = "roots"

	// The default amount of time for a signed fetch request validity period
	DefaultFetchCredentialsLifetime = time.Hour * 24

	// ServerLedActivationTokenPrefix is used to identify an incoming nonce at
	// activation time that should trigger a lookup for a server-generated token
	ServerLedActivationTokenPrefix = "neslat_" // NodeEnrollment Server-Led Activation Token
)

// ErrNotFound is a common error to use when a value is not found in storage.
// Depending on the storage implementation it may be a different underlying
// error, so this ensures we can use errors.Is as a check.
var ErrNotFound = errors.New("value not found in storage")

// ErrNotAuthorized is a common error that we can return to indicate that a node
// is still awaiting authentication after attempting to fetch credentials
var ErrNotAuthorized = errors.New("node is not yet authorized")
