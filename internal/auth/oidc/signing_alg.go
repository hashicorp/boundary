package oidc

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
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

// DefaultSigningAlgTableName defines the default table name for a SigningAlg
const DefaultSigningAlgTableName = "auth_oidc_signing_alg"

// SigningAlg defines an signing algorithm supported by an OIDC auth method.
// It is assigned to an OIDC AuthMethod and updates/deletes to that AuthMethod
// are cascaded to its SigningAlgs.
type SigningAlg struct {
	*store.SigningAlg
	tableName string
}

// NewSigningAlg creates a new in memory signing alg assigned to an OIDC
// AuthMethod. It supports no options.
func NewSigningAlg(authMethodId string, alg Alg) (*SigningAlg, error) {
	const op = "oidc.NewSigningAlg"
	s := &SigningAlg{
		SigningAlg: &store.SigningAlg{
			OidcMethodId: authMethodId,
			Alg:          string(alg),
		},
	}
	if err := s.validate(op); err != nil {
		return nil, err // intentionally not wrapped
	}
	return s, nil
}

// validate the SigningAlg.  On success, it will return nil.
func (s *SigningAlg) validate(caller errors.Op) error {
	if s.OidcMethodId == "" {
		return errors.New(errors.InvalidParameter, caller, "missing oidc auth method id")
	}
	if _, ok := supportedAlgorithms[Alg(s.Alg)]; !ok {
		return errors.New(errors.InvalidParameter, caller, fmt.Sprintf("unsupported signing algorithm: %s", s.Alg))
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
	return DefaultSigningAlgTableName
}

// SetTableName sets the table name.
func (s *SigningAlg) SetTableName(n string) {
	s.tableName = n
}

// oplog will create oplog metadata for the SigningAlg.
func (s *SigningAlg) oplog(op oplog.OpType, authMethodScopeId string) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{s.OidcMethodId}, // the auth method is the root aggregate
		"resource-type":      []string{"oidc auth signing alg"},
		"op-type":            []string{op.String()},
	}
	if authMethodScopeId != "" {
		metadata["scope-id"] = []string{authMethodScopeId}
	}
	return metadata
}
