// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/proto"
)

const certificateTableName = "auth_ldap_certificate"

// Certificate defines a certificate to use as part of a trust root when
// connecting to an auth method's LDAP server.  It is assigned to an LDAP
// AuthMethod and updates/deletes to that AuthMethod are cascaded to its
// Certificates. Certificates are value objects of an AuthMethod, therefore
// there's no need for oplog metadata, since only the AuthMethod will have
// metadata because it's the root aggregate.
type Certificate struct {
	*store.Certificate
	tableName string
}

// NewCertificate creates a new in memory certificate assigned to and LDAP auth
// method.
func NewCertificate(ctx context.Context, authMethodId string, certificatePem string) (*Certificate, error) {
	const op = "ldap.NewCertificate"
	// validate() will check the parameters.
	c := &Certificate{
		Certificate: &store.Certificate{
			LdapMethodId: authMethodId,
			Cert:         certificatePem,
		},
	}
	if err := c.validate(ctx, op); err != nil {
		return nil, err // intentionally, not wrapping err
	}
	return c, nil
}

// validate the Certificate and on success return nil
func (c *Certificate) validate(ctx context.Context, caller errors.Op) error {
	switch {
	case c.LdapMethodId == "":
		return errors.New(ctx, errors.InvalidParameter, caller, "missing ldap auth method id")
	case c.Cert == "":
		return errors.New(ctx, errors.InvalidParameter, caller, "missing certificate")
	default:
		blk, _ := pem.Decode([]byte(c.Cert))
		if blk == nil {
			return errors.New(ctx, errors.InvalidParameter, caller, "failed to parse certificate: invalid PEM encoding")
		}
		if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
			return errors.New(ctx, errors.InvalidParameter, caller, fmt.Sprintf("failed to parse certificate: invalid block: %s", err.Error()), errors.WithWrap(err))
		}
		return nil
	}
}

// allocCertificate makes an empty one in memory
func allocCertificate() Certificate {
	return Certificate{
		Certificate: &store.Certificate{},
	}
}

// clone a Certificate
func (c *Certificate) clone() *Certificate {
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
	return certificateTableName
}

// SetTableName sets the table name.
func (c *Certificate) SetTableName(n string) {
	c.tableName = n
}
