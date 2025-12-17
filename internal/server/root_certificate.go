// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"

	timestamp "github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/server/store"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	"google.golang.org/protobuf/proto"
)

// The CertificateAuthority id will always be set to "roots".
// The const CaId contains this value
const CaId = "roots"

// CertificateAuthority is a versioned entity used to lock the database when rotation RootCertificates
type CertificateAuthority struct {
	*store.CertificateAuthority
	tableName string `gorm:"-"`
}

func newCertificateAuthority() *CertificateAuthority {
	ca := &CertificateAuthority{
		CertificateAuthority: &store.CertificateAuthority{
			PrivateId: CaId,
		},
	}
	return ca
}

// TableName returns the table name.
func (r *CertificateAuthority) TableName() string {
	if r.tableName != "" {
		return r.tableName
	}
	return "worker_auth_ca"
}

// SetTableName sets the table name.
func (r *CertificateAuthority) SetTableName(n string) {
	r.tableName = n
}

// RootCertificate contains fields related to a RootCertificate resource
// This includes public/ private keys, the PEM encoded certificate, and the certificate validity period
type RootCertificate struct {
	*store.RootCertificate
	tableName string `gorm:"-"`
}

func (r *RootCertificate) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "server.(RootCertificate).encrypt"
	if len(r.PrivateKey) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "no private key provided")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, r.RootCertificate, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	keyId, err := cipher.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("error reading cipher key id"))
	}
	r.KeyId = keyId
	return nil
}

func (r *RootCertificate) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "server.(RootCertificate).decrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, r.RootCertificate, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

// RootCertificateKeys contains the public and private keys for use in constructing a RootCertificate
type RootCertificateKeys struct {
	publicKey  []byte
	privateKey []byte
}

func newRootCertificate(ctx context.Context, serialNumber uint64, certificate []byte, notValidBefore, notValidAfter *timestamp.Timestamp,
	rootCertificateKeys RootCertificateKeys, keyId string, state CertificateState,
) (*RootCertificate, error) {
	const op = "server.newRootCertificate"

	if serialNumber == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no serialNumber")
	}
	if certificate == nil || len(certificate) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "empty certificate")
	}
	if notValidAfter == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no notValidAfter")
	}
	if notValidBefore == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no notValidBefore")
	}
	if rootCertificateKeys.publicKey == nil || len(rootCertificateKeys.publicKey) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "empty publicKey")
	}
	if rootCertificateKeys.privateKey == nil || len(rootCertificateKeys.privateKey) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "empty privateKey")
	}
	if keyId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no keyId")
	}
	if !validState(state) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s is not a valid certificate state", state))
	}

	l := &RootCertificate{
		RootCertificate: &store.RootCertificate{
			SerialNumber:   serialNumber,
			Certificate:    certificate,
			NotValidAfter:  notValidAfter,
			NotValidBefore: notValidBefore,
			PublicKey:      rootCertificateKeys.publicKey,
			CtPrivateKey:   rootCertificateKeys.privateKey,
			KeyId:          keyId,
			State:          string(state),
			IssuingCa:      CaId,
		},
	}
	return l, nil
}

func allocRootCertificate() *RootCertificate {
	return &RootCertificate{
		RootCertificate: &store.RootCertificate{},
	}
}

func (r *RootCertificate) clone() *RootCertificate {
	cp := proto.Clone(r.RootCertificate)
	return &RootCertificate{
		RootCertificate: cp.(*store.RootCertificate),
	}
}

// Validate the RootCertificate. On success, return nil
func (r *RootCertificate) ValidateNewRootCertificate(ctx context.Context) error {
	const op = "server.(RootCertificate).ValidateNewRootCertificate"
	if r.SerialNumber == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "missing SerialNumber")
	}
	if r.Certificate == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing Certificate")
	}
	if r.NotValidBefore.GetTimestamp().AsTime().IsZero() {
		return errors.New(ctx, errors.InvalidParameter, op, "missing not valid before timestamp")
	}
	if r.NotValidAfter.GetTimestamp().AsTime().IsZero() {
		return errors.New(ctx, errors.InvalidParameter, op, "missing not valid after timestamp")
	}
	if r.PublicKey == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing public key")
	}
	if r.CtPrivateKey == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing encrypted private key")
	}
	if r.KeyId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing key id")
	}
	if r.State == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing state")
	}

	return nil
}

// TableName returns the table name.
func (r *RootCertificate) TableName() string {
	if r.tableName != "" {
		return r.tableName
	}
	return "worker_auth_ca_certificate"
}

// SetTableName sets the table name.
func (r *RootCertificate) SetTableName(n string) {
	r.tableName = n
}
