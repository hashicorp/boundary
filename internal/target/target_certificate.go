// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	mathrand "math/rand"
	"net"
	"time"

	talias "github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/hashicorp/boundary/internal/util"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	"google.golang.org/protobuf/proto"
)

func generatePrivAndPubKeys(ctx context.Context) (privKeyBytes []byte, pubKeyBytes []byte, err error) {
	const op = "target.generatePrivAndPubKeys"
	// Generate a private key using the P521 curve
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "failed to generate ECDSA key")
	}

	privKeyBytes, err = x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("error marshalling private key"))
	}

	pubKeyBytes, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("error marshalling public key"))
	}
	return privKeyBytes, pubKeyBytes, nil
}

// generateTargetCert generates a self-signed certificate for the target for localhost with the localhost addresses for ipv4 and ipv6.
// Supports the option withAlias to pass an alias for use in the cert DNS names field
func generateTargetCert(ctx context.Context, privKey *ecdsa.PrivateKey, exp time.Time, opt ...Option) ([]byte, error) {
	const op = "target.generateTargetCert"
	switch {
	case util.IsNil(privKey):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing private key")
	case exp.IsZero():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing expiry")
	case exp.Before(time.Now()):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "expiration time must be in the future")
	}

	opts := GetOpts(opt...)

	template := &x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		SerialNumber:          big.NewInt(mathrand.Int63()),
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              exp,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	if opts.withAlias != nil {
		template.DNSNames = append(template.DNSNames, opts.withAlias.Value)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.GenCert))
	}
	return certBytes, nil
}

// TargetProxyCertificate represents a proxy certificate for a target
type TargetProxyCertificate struct {
	*store.TargetProxyCertificate
	tableName string `gorm:"-"`
}

// newTargetProxyCertificate creates a new in memory TargetProxyCertificate
// Supports the options withTargetId to set the target ID
// If this is not provided, the TargetId will need to be set before storing the certificate
func NewTargetProxyCertificate(ctx context.Context, opt ...Option) (*TargetProxyCertificate, error) {
	const op = "target.NewTargetProxyCertificate"

	opts := GetOpts(opt...)

	privKey, pubKey, err := generatePrivAndPubKeys(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error generating target proxy certificate key"))
	}

	notValidAfter := time.Now().AddDate(1, 0, 0) // 1 year from now
	parsedKey, err := x509.ParseECPrivateKey(privKey)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error parsing target proxy certificate key"))
	}
	certBytes, err := generateTargetCert(ctx, parsedKey, notValidAfter)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error generating target certificate"))
	}

	return &TargetProxyCertificate{
		TargetProxyCertificate: &store.TargetProxyCertificate{
			PrivateKey:    privKey,
			PublicKey:     pubKey,
			Certificate:   certBytes,
			NotValidAfter: timestamp.New(notValidAfter),
			TargetId:      opts.withTargetId,
		},
	}, nil
}

// encrypt the target cert key before writing it to the db
func (t *TargetProxyCertificate) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "target.(TargetProxyCertificate).encrypt"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, t.TargetProxyCertificate, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	keyId, err := cipher.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("failed to read cipher key id"))
	}
	t.KeyId = keyId
	return nil
}

// decrypt the target cert key after reading it from the db
func (t *TargetProxyCertificate) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "target.(TargetProxyCertificate).decrypt"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.UnwrapStruct(ctx, cipher, t.TargetProxyCertificate, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

func allocTargetProxyCertificate() *TargetProxyCertificate {
	return &TargetProxyCertificate{
		TargetProxyCertificate: &store.TargetProxyCertificate{},
	}
}

// Clone creates a clone of the TargetProxyCertificate
func (t *TargetProxyCertificate) Clone() *TargetProxyCertificate {
	cp := proto.Clone(t.TargetProxyCertificate)
	return &TargetProxyCertificate{
		TargetProxyCertificate: cp.(*store.TargetProxyCertificate),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates a target certificate
func (t *TargetProxyCertificate) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "target.(TargetProxyCertificate).VetForWrite"
	switch {
	case t.PrivateKeyEncrypted == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing private key")
	case t.PublicKey == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing public key")
	case t.KeyId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing key id")
	case t.TargetId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	case len(t.Certificate) == 0:
		return errors.New(ctx, errors.InvalidParameter, op, "missing certificate")
	case t.NotValidAfter == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing not valid after")
	}

	return nil
}

// TableName returns the table name.
func (t *TargetProxyCertificate) TableName() string {
	return "target_proxy_certificate"
}

// TargetAliasProxyCertificate represents a certificate for a target accessed with an alias
type TargetAliasProxyCertificate struct {
	*store.TargetAliasProxyCertificate
	tableName string `gorm:"-"`
}

// NewTargetAliasProxyCertificate creates a new in memory TargetAliasProxyCertificate
func NewTargetAliasProxyCertificate(ctx context.Context, targetId string, alias *talias.Alias) (*TargetAliasProxyCertificate, error) {
	const op = "target.NewTargetAliasProxyCertificate"
	switch {
	case targetId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	case alias == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing target alias")
	}

	privKey, pubKey, err := generatePrivAndPubKeys(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error generating target proxy certificate key"))
	}
	notValidAfter := time.Now().AddDate(1, 0, 0) // 1 year from now
	parsedKey, err := x509.ParseECPrivateKey(privKey)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error parsing target proxy certificate key"))
	}
	certBytes, err := generateTargetCert(ctx, parsedKey, notValidAfter, WithAlias(alias))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error generating target certificate"))
	}

	return &TargetAliasProxyCertificate{
		TargetAliasProxyCertificate: &store.TargetAliasProxyCertificate{
			TargetId:      targetId,
			PrivateKey:    privKey,
			PublicKey:     pubKey,
			AliasId:       alias.PublicId,
			Certificate:   certBytes,
			NotValidAfter: timestamp.New(notValidAfter),
		},
	}, nil
}

// encrypt the target cert key before writing it to the db
func (t *TargetAliasProxyCertificate) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "target.(TargetAliasProxyCertificate).encrypt"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, t.TargetAliasProxyCertificate, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	keyId, err := cipher.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("failed to read cipher key id"))
	}
	t.KeyId = keyId
	return nil
}

// decrypt the target cert key after reading it from the db
func (t *TargetAliasProxyCertificate) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "target.(TargetAliasProxyCertificate).decrypt"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.UnwrapStruct(ctx, cipher, t.TargetAliasProxyCertificate, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

func allocTargetAliasProxyCertificate() *TargetAliasProxyCertificate {
	return &TargetAliasProxyCertificate{
		TargetAliasProxyCertificate: &store.TargetAliasProxyCertificate{},
	}
}

// Clone creates a clone of the TargetAliasProxyCertificate
func (t *TargetAliasProxyCertificate) Clone() *TargetAliasProxyCertificate {
	cp := proto.Clone(t.TargetAliasProxyCertificate)
	return &TargetAliasProxyCertificate{
		TargetAliasProxyCertificate: cp.(*store.TargetAliasProxyCertificate),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the target alias certificate
func (t *TargetAliasProxyCertificate) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "target.(TargetAliasProxyCertificate).VetForWrite"
	switch {
	case t.PrivateKeyEncrypted == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing private key")
	case t.PublicKey == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing public key")
	case t.KeyId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing key id")
	case t.TargetId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	case t.AliasId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing alias id")
	case len(t.Certificate) == 0:
		return errors.New(ctx, errors.InvalidParameter, op, "missing certificate")
	case t.NotValidAfter == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing not valid after")
	}

	return nil
}

// TableName returns the table name.
func (t *TargetAliasProxyCertificate) TableName() string {
	return "target_alias_proxy_certificate"
}
