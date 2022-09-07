package server

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"

	timestamp "github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/server/store"
	"google.golang.org/protobuf/proto"
)

// The CertificateAuthority id will always be set to "roots".
// The const ca_id contains this value
const ca_id = "roots"

// CertificateAuthority is a versioned entity used to lock the database when rotation RootCertificates
type CertificateAuthority struct {
	*store.CertificateAuthority
	tableName string `gorm:"-"`
}

func newCertificateAuthority() *CertificateAuthority {
	ca := &CertificateAuthority{
		CertificateAuthority: &store.CertificateAuthority{
			PrivateId: ca_id,
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

// RootCertificateKeys contains the public and private keys for use in constructing a RootCertificate
type RootCertificateKeys struct {
	publicKey  []byte
	privateKey []byte
}

func newRootCertificate(ctx context.Context, serialNumber uint64, certificate []byte, notValidBefore, notValidAfter *timestamp.Timestamp,
	rootCertificateKeys RootCertificateKeys, keyVersionId string, state CertificateState,
) (*RootCertificate, error) {
	const op = "server.newRootCertificate"

	if &serialNumber == nil {
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
	if keyVersionId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no keyVersionId")
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
			PrivateKey:     rootCertificateKeys.privateKey,
			KeyVersionId:   keyVersionId,
			State:          string(state),
			IssuingCa:      ca_id,
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
	if &r.SerialNumber == nil {
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
	if r.PrivateKey == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing private key")
	}
	if r.KeyVersionId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing key version id")
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
