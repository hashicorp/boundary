// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/proto"
)

// defaultCertificateTableName defines the default table name for a certificate
const defaultCertificateTableName = "auth_oidc_certificate"

// Certificate defines a certificate to use as part of a trust root when
// connecting to the auth method's OIDC Provider.  It is assigned to an OIDC
// AuthMethod and updates/deletes to that AuthMethod are cascaded to its
// Certificates. Certificates are value objects of an AuthMethod, therefore
// there's no need for oplog metadata, since only the AuthMethod will have
// metadata because it's the root aggregate.
type Certificate struct {
	*store.Certificate
	tableName string
}

// NewCertificate creates a new in memory certificate assigned to and OIDC auth
// method.
func NewCertificate(ctx context.Context, authMethodId string, certificatePem string) (*Certificate, error) {
	const op = "oidc.NewCertificate"

	c := &Certificate{
		Certificate: &store.Certificate{
			OidcMethodId: authMethodId,
			Cert:         certificatePem,
		},
	}
	if err := c.validate(ctx, op); err != nil {
		return nil, err // intentionally not wrapped
	}
	return c, nil
}

// validate the Certifcate and on success return nil
func (c *Certificate) validate(ctx context.Context, caller errors.Op) error {
	if c.OidcMethodId == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing oidc auth method id")
	}
	if c.Cert == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "empty cert")
	}
	block, _ := pem.Decode([]byte(c.Cert))
	if block == nil {
		return errors.New(ctx, errors.InvalidParameter, caller, "failed to parse certificate PEM")
	}
	_, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New(ctx, errors.InvalidParameter, caller, fmt.Sprintf("failed to parse certificate: %s", err.Error()), errors.WithWrap(err))
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
	return defaultCertificateTableName
}

// SetTableName sets the table name.
func (c *Certificate) SetTableName(n string) {
	c.tableName = n
}
