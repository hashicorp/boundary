// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/proto"
)

// Alg represents asymmetric signing algorithms
type Alg string

const (
	// JOSE asymmetric signing algorithm values as defined by RFC 7518.
	//
	// See: https://tools.ietf.org/html/rfc7518#section-3.1
	RS256 Alg = "RS256" // RSASSA-PKCS-v1.5 using SHA-256
	RS384 Alg = "RS384" // RSASSA-PKCS-v1.5 using SHA-384
	RS512 Alg = "RS512" // RSASSA-PKCS-v1.5 using SHA-512
	ES256 Alg = "ES256" // ECDSA using P-256 and SHA-256
	ES384 Alg = "ES384" // ECDSA using P-384 and SHA-384
	ES512 Alg = "ES512" // ECDSA using P-521 and SHA-512
	PS256 Alg = "PS256" // RSASSA-PSS using SHA256 and MGF1-SHA256
	PS384 Alg = "PS384" // RSASSA-PSS using SHA384 and MGF1-SHA384
	PS512 Alg = "PS512" // RSASSA-PSS using SHA512 and MGF1-SHA512
	EdDSA Alg = "EdDSA"
)

var supportedAlgorithms = map[Alg]bool{
	RS256: true,
	RS384: true,
	RS512: true,
	ES256: true,
	ES384: true,
	ES512: true,
	PS256: true,
	PS384: true,
	PS512: true,
	EdDSA: true,
}

// defaultSigningAlgTableName defines the default table name for a SigningAlg
const defaultSigningAlgTableName = "auth_oidc_signing_alg"

// SigningAlg defines an signing algorithm supported by an OIDC auth method.
// It is assigned to an OIDC AuthMethod and updates/deletes to that AuthMethod
// are cascaded to its SigningAlgs. SigningAlgs are value objects of an AuthMethod,
// therefore there's no need for oplog metadata, since only the AuthMethod will have
// metadata because it's the root aggregate.
type SigningAlg struct {
	*store.SigningAlg
	tableName string
}

// NewSigningAlg creates a new in memory signing alg assigned to an OIDC
// AuthMethod. It supports no options.
func NewSigningAlg(ctx context.Context, authMethodId string, alg Alg) (*SigningAlg, error) {
	const op = "oidc.NewSigningAlg"
	s := &SigningAlg{
		SigningAlg: &store.SigningAlg{
			OidcMethodId: authMethodId,
			Alg:          string(alg),
		},
	}
	if err := s.validate(ctx, op); err != nil {
		return nil, err // intentionally not wrapped
	}
	return s, nil
}

// SupportedAlgorithm returns true iff the provided algorithm is supported
// by boundary.
func SupportedAlgorithm(a Alg) bool {
	return supportedAlgorithms[a]
}

// validate the SigningAlg.  On success, it will return nil.
func (s *SigningAlg) validate(ctx context.Context, caller errors.Op) error {
	if s.OidcMethodId == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing oidc auth method id")
	}
	if _, ok := supportedAlgorithms[Alg(s.Alg)]; !ok {
		return errors.New(ctx, errors.InvalidParameter, caller, fmt.Sprintf("unsupported signing algorithm: %s", s.Alg))
	}
	return nil
}

// AllocSigningAlg makes an empty one in memory
func AllocSigningAlg() SigningAlg {
	return SigningAlg{
		SigningAlg: &store.SigningAlg{},
	}
}

// Clone a SigningAlg
func (s *SigningAlg) Clone() *SigningAlg {
	cp := proto.Clone(s.SigningAlg)
	return &SigningAlg{
		SigningAlg: cp.(*store.SigningAlg),
	}
}

// TableName returns the table name.
func (s *SigningAlg) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return defaultSigningAlgTableName
}

// SetTableName sets the table name.
func (s *SigningAlg) SetTableName(n string) {
	s.tableName = n
}
