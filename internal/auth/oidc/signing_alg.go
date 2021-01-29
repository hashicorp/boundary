package oidc

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

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

type SigningAlg struct {
	*store.SigningAlg
	tableName string
}

func NewSigningAlg(authMethodId string, alg Alg) (*SigningAlg, error) {
	const op = "oidc.NewSigningAlg"
	a := &SigningAlg{
		SigningAlg: &store.SigningAlg{
			OidcMethodId: authMethodId,
			Alg:          string(alg),
		},
	}
	if err := a.validate(op); err != nil {
		return nil, err // intentionally not wrapped
	}
	return a, nil
}

func (a *SigningAlg) validate(caller errors.Op) error {
	if _, ok := supportedAlgorithms[Alg(a.Alg)]; !ok {
		return errors.New(errors.InvalidParameter, caller, fmt.Sprintf("unsupported signing algorithm: %s", a.Alg))
	}
	return nil
}
func allocSigningAlg() SigningAlg {
	return SigningAlg{
		SigningAlg: &store.SigningAlg{},
	}
}

func (a *SigningAlg) clone() *SigningAlg {
	cp := proto.Clone(a.SigningAlg)
	return &SigningAlg{
		SigningAlg: cp.(*store.SigningAlg),
	}
}

// TableName returns the table name.
func (a *SigningAlg) TableName() string {
	if a.tableName != "" {
		return a.tableName
	}
	return "auth_oidc_signing_alg"
}

// SetTableName sets the table name.
func (a *SigningAlg) SetTableName(n string) {
	a.tableName = n
}

func (a *SigningAlg) oplog(op oplog.OpType, authMethodScopeId string) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{a.OidcMethodId}, // the auth method is the root aggregate
		"resource-type":      []string{"oidc auth signing alg"},
		"op-type":            []string{op.String()},
	}
	if authMethodScopeId != "" {
		metadata["scope-id"] = []string{authMethodScopeId}
	}
	return metadata
}
