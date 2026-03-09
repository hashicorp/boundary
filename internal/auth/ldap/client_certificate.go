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
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	"google.golang.org/protobuf/proto"
)

const clientCertificateTableName = "auth_ldap_client_certificate"

// ClientCertificate represents a set of optional configuration fields used for
// specifying a mTLS client cert for LDAP connections. ClientCertificates are
// value objects of an AuthMethod, therefore there's no need for oplog metadata,
// since only the AuthMethod will have metadata because it's the root aggregate.
type ClientCertificate struct {
	*store.ClientCertificate
	tableName string
}

// NewClientCertificate creates a new in memory ClientCertificate. No options
// are currently supported.  PrivKey must be in PKCS #8, ASN.1 DER form. certPem
// must be in ASN.1 DER form encoded as PEM.
func NewClientCertificate(ctx context.Context, authMethodId string, privKey []byte, certPem string, _ ...Option) (*ClientCertificate, error) {
	const op = "ldap.NewClientCertificate"
	switch {
	case authMethodId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	case len(privKey) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing key")
	case certPem == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing certificate")
	}
	if _, err := x509.ParsePKCS8PrivateKey(privKey); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to parse key in PKCS #8, ASN.1 DER form"), errors.WithCode(errors.InvalidParameter))
	}
	blk, _ := pem.Decode([]byte(certPem))
	if blk == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "failed to parse certificate: invalid PEM encoding")
	}
	if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("failed to parse certificate: invalid block: %s", err.Error()), errors.WithWrap(err))
	}
	return &ClientCertificate{
		ClientCertificate: &store.ClientCertificate{
			LdapMethodId:   authMethodId,
			CertificateKey: privKey,
			Certificate:    []byte(certPem),
		},
	}, nil
}

// allocClientCertificate makes an empty one in memory
func allocClientCertificate() *ClientCertificate {
	return &ClientCertificate{
		ClientCertificate: &store.ClientCertificate{},
	}
}

// clone a ClientCertificate
func (cc *ClientCertificate) clone() *ClientCertificate {
	cp := proto.Clone(cc.ClientCertificate)
	return &ClientCertificate{
		ClientCertificate: cp.(*store.ClientCertificate),
	}
}

// TableName returns the table name
func (cc *ClientCertificate) TableName() string {
	if cc.tableName != "" {
		return cc.tableName
	}
	return clientCertificateTableName
}

// SetTableName sets the table name.
func (cc *ClientCertificate) SetTableName(n string) {
	cc.tableName = n
}

// encrypt the client certificate before writing it to the database
func (cc *ClientCertificate) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "ldap.(ClientCertificate).encrypt"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, cc.ClientCertificate); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	var err error
	if cc.KeyId, err = cipher.KeyId(ctx); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("failed to read cipher key id"))
	}
	if cc.CertificateKeyHmac, err = hmacField(ctx, cipher, cc.CertificateKey, cc.LdapMethodId); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("failed to hmac client certificate"))
	}

	return nil
}

// decrypt the client certificate after reading it from the database
func (cc *ClientCertificate) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "ldap.(ClientCertificate).decrypt"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.UnwrapStruct(ctx, cipher, cc.ClientCertificate); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}
