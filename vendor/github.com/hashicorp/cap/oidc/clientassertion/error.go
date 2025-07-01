// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package clientassertion

import "errors"

var (
	// these may happen due to user error

	ErrMissingClientID  = errors.New("missing client ID")
	ErrMissingAudience  = errors.New("missing audience")
	ErrMissingAlgorithm = errors.New("missing signing algorithm")
	ErrMissingKeyID     = errors.New("missing key ID")
	ErrMissingKey       = errors.New("missing private key")
	ErrMissingSecret    = errors.New("missing client secret")
	ErrKidHeader        = errors.New(`"kid" not allowed in WithHeaders; use WithKeyID instead`)
	ErrCreatingSigner   = errors.New("error creating jwt signer")

	// algorithm errors

	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
	ErrInvalidSecretLength  = errors.New("invalid secret length for algorithm")
	ErrNilPrivateKey        = errors.New("nil private key")
)
