package oidc

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// DefaultCertificateTableName defines the default table name for a certificate
const DefaultCertificateTableName = "auth_oidc_certificate"

// Certificate defines a certificate to use as part of a trust root when
// connecting to the auth method's OIDC Provider.
type Certificate struct {
	*store.Certificate
	tableName string
}

// NewCertificate creates a new in memory certificate for an OIDC auth method.
// Certificates are "owned" by their coresponding OIDC auth method.
func NewCertificate(authMethodId string, cert string) (*Certificate, error) {
	const op = "oidc.NewCallbackUrl"

	c := &Certificate{
		Certificate: &store.Certificate{
			OidcMethodId: authMethodId,
			Cert:         cert,
		},
	}
	if err := c.validate(op); err != nil {
		return nil, err // intentionally not wrapped
	}
	return c, nil
}

// validate the Certifcate and on success return nil
func (c *Certificate) validate(caller errors.Op) error {
	if c.OidcMethodId == "" {
		return errors.New(errors.InvalidParameter, caller, "missing oidc auth method id")
	}
	if c.Cert == "" {
		return errors.New(errors.InvalidParameter, caller, "empty cert")
	}
	block, _ := pem.Decode([]byte(c.Cert))
	if block == nil {
		return errors.New(errors.InvalidParameter, caller, "failed to parse certificate PEM")
	}
	_, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New(errors.InvalidParameter, caller, fmt.Sprintf("failed to parse certificate: %s"+err.Error()), errors.WithWrap(err))
	}
	return nil
}

// AllocCertificate makes an empty one in memory
func AllocCertificate() Certificate {
	return Certificate{
		Certificate: &store.Certificate{},
	}
}

// Clone a Certificate
func (c *Certificate) Clone() *Certificate {
	cp := proto.Clone(c.Certificate)
	return &Certificate{
		Certificate: cp.(*store.Certificate),
	}
}

// TableName returns the table name.
func (c *Certificate) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return DefaultCertificateTableName
}

// SetTableName sets the table name.
func (c *Certificate) SetTableName(n string) {
	c.tableName = n
}

// oplog will create oplog metadata for the Certificate.
func (c *Certificate) oplog(op oplog.OpType, authMethodScopeId string) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.OidcMethodId}, // the auth method is the root aggregate
		"resource-type":      []string{"oidc auth certificate"},
		"op-type":            []string{op.String()},
	}
	if authMethodScopeId != "" {
		metadata["scope-id"] = []string{authMethodScopeId}
	}
	return metadata
}
