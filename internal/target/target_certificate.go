// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math"
	"math/big"
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

func generatePrivAndPubKeys(ctx context.Context, randomReader io.Reader) (privKeyBytes []byte, pubKeyBytes []byte, err error) {
	const op = "target.generatePrivAndPubKeys"
	// Generate a private key using the P521 curve
	key, err := ecdsa.GenerateKey(elliptic.P521(), randomReader)
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
// Supports the option WithAlias to pass an alias for use in the cert DNS names field
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

	randomSerialNumber, err := rand.Int(opts.withRandomReader, big.NewInt(int64(math.MaxInt64)))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error generating random serial number"))
	}

	template := &x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		SerialNumber:          randomSerialNumber,
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              exp,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	if opts.WithAlias != nil {
		template.DNSNames = append(template.DNSNames, opts.WithAlias.Value)
	}

	certBytes, err := x509.CreateCertificate(opts.withRandomReader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.GenCert))
	}
	return certBytes, nil
}

func generateKeysAndCert(ctx context.Context, notValidAfter time.Time, opt ...Option) (privKey []byte, pubKey []byte, cert []byte, err error) {
	const op = "target.generateKeysAndCert"

	opts := GetOpts(opt...)

	privKey, pubKey, err = generatePrivAndPubKeys(ctx, opts.withRandomReader)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op)
	}
	parsedKey, err := x509.ParseECPrivateKey(privKey)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op)
	}
	cert, err = generateTargetCert(ctx, parsedKey, notValidAfter, opt...)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op)
	}

	return privKey, pubKey, cert, nil
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

	notValidAfter := time.Now().AddDate(1, 0, 0) // 1 year from now
	privKey, pubKey, cert, err := generateKeysAndCert(ctx, notValidAfter, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error generating target proxy cert and keys"))
	}

	return &TargetProxyCertificate{
		TargetProxyCertificate: &store.TargetProxyCertificate{
			PrivateKey:    privKey,
			PublicKey:     pubKey,
			Certificate:   cert,
			NotValidAfter: timestamp.New(notValidAfter),
			TargetId:      opts.withTargetId,
		},
	}, nil
}

// Encrypt the target cert key before writing it to the db
func (t *TargetProxyCertificate) Encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "target.(TargetProxyCertificate).Encrypt"
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

// Decrypt the target cert key after reading it from the db
func (t *TargetProxyCertificate) Decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "target.(TargetProxyCertificate).Decrypt"
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

// SetTableName sets the table name
func (t *TargetProxyCertificate) SetTableName(name string) {
	t.tableName = name
}

func (t *TargetProxyCertificate) GetNotValidAfter() *timestamp.Timestamp {
	return t.NotValidAfter
}

func (t *TargetProxyCertificate) SetPrivateKey(privKeyBytes []byte) {
	t.PrivateKey = privKeyBytes
}

func (t *TargetProxyCertificate) SetPublicKey(pubKeyBytes []byte) {
	t.PublicKey = pubKeyBytes
}

func (t *TargetProxyCertificate) SetCertificate(certBytes []byte) {
	t.Certificate = certBytes
}

func (t *TargetProxyCertificate) SetNotValidAfter(timestamp *timestamp.Timestamp) {
	t.NotValidAfter = timestamp
}

// TargetAliasProxyCertificate represents a certificate for a target accessed with an alias
type TargetAliasProxyCertificate struct {
	*store.TargetAliasProxyCertificate
	tableName string `gorm:"-"`
}

// NewTargetAliasProxyCertificate creates a new in memory TargetAliasProxyCertificate
func NewTargetAliasProxyCertificate(ctx context.Context, targetId string, alias *talias.Alias, opt ...Option) (*TargetAliasProxyCertificate, error) {
	const op = "target.NewTargetAliasProxyCertificate"
	switch {
	case targetId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	case alias == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing target alias")
	}

	notValidAfter := time.Now().AddDate(1, 0, 0) // 1 year from now

	opt = append(opt, WithAlias(alias))
	privKey, pubKey, cert, err := generateKeysAndCert(ctx, notValidAfter, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error generating target proxy cert and keys"))
	}

	return &TargetAliasProxyCertificate{
		TargetAliasProxyCertificate: &store.TargetAliasProxyCertificate{
			TargetId:      targetId,
			PrivateKey:    privKey,
			PublicKey:     pubKey,
			AliasId:       alias.PublicId,
			Certificate:   cert,
			NotValidAfter: timestamp.New(notValidAfter),
		},
	}, nil
}

// Encrypt the target cert key before writing it to the db
func (t *TargetAliasProxyCertificate) Encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "target.(TargetAliasProxyCertificate).Encrypt"
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
func (t *TargetAliasProxyCertificate) Decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "target.(TargetAliasProxyCertificate).Decrypt"
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

// SetTableName sets the table name
func (t *TargetAliasProxyCertificate) SetTableName(name string) {
	t.tableName = name
}

func (t *TargetAliasProxyCertificate) GetNotValidAfter() *timestamp.Timestamp {
	return t.NotValidAfter
}

func (t *TargetAliasProxyCertificate) SetPrivateKey(privKeyBytes []byte) {
	t.PrivateKey = privKeyBytes
}

func (t *TargetAliasProxyCertificate) SetPublicKey(pubKeyBytes []byte) {
	t.PublicKey = pubKeyBytes
}

func (t *TargetAliasProxyCertificate) SetCertificate(certBytes []byte) {
	t.Certificate = certBytes
}

func (t *TargetAliasProxyCertificate) SetNotValidAfter(timestamp *timestamp.Timestamp) {
	t.NotValidAfter = timestamp
}

func pemsToServerCertificate(ctx context.Context, certPem, keyPem []byte) (*ServerCertificate, error) {
	const op = "target.pemsToServerCertificate"
	switch {
	case certPem == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing certificate PEM")
	case keyPem == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing private key PEM")
	}

	cPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certPem,
	})
	if certPem == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "error encoding certificate to PEM")
	}

	kPem := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyPem,
	})
	if keyPem == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "error encoding private key to PEM")
	}

	return &ServerCertificate{
		CertificatePem: cPem,
		PrivateKeyPem:  kPem,
	}, nil
}

func (t *TargetProxyCertificate) fromServerCertificate(ctx context.Context, serverCert *ServerCertificate) error {
	const op = "target.(TargetProxyCertificate).fromServerCertificate"
	switch {
	case serverCert == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing server certificate")
	case len(serverCert.CertificatePem) == 0:
		return errors.New(ctx, errors.InvalidParameter, op, "missing certificate PEM data")
	case len(serverCert.PrivateKeyPem) == 0:
		return errors.New(ctx, errors.InvalidParameter, op, "missing private key PEM data")
	}

	decodedBlock, _ := pem.Decode(serverCert.CertificatePem)
	if decodedBlock == nil || decodedBlock.Type != "CERTIFICATE" {
		return errors.New(ctx, errors.InvalidParameter, op, "invalid PEM data for certificate")
	}

	cert, err := x509.ParseCertificate(decodedBlock.Bytes)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("error parsing PEM data"))
	}
	t.Certificate = cert.Raw
	t.NotValidAfter = timestamp.New(cert.NotAfter)

	decodedKeyBlock, _ := pem.Decode(serverCert.PrivateKeyPem)
	if decodedKeyBlock == nil || decodedKeyBlock.Type != "EC PRIVATE KEY" {
		return errors.New(ctx, errors.InvalidParameter, op, "invalid PEM data for EC private key")
	}

	t.PrivateKey = decodedKeyBlock.Bytes
	privKey, err := x509.ParseECPrivateKey(t.PrivateKey)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("error parsing decoded private key"))
	}
	t.PublicKey, err = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("error marshalling public key"))
	}
	return nil
}

// ToServerCertificate converts the target proxy certificate to a server certificate
func (t *TargetProxyCertificate) ToServerCertificate(ctx context.Context) (*ServerCertificate, error) {
	const op = "target.(TargetProxyCertificate).ToServerCertificate"
	switch {
	case len(t.PrivateKey) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing private key")
	case len(t.Certificate) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing certificate")
	}

	return pemsToServerCertificate(ctx, t.Certificate, t.PrivateKey)
}

func (t *TargetAliasProxyCertificate) fromServerCertificate(ctx context.Context, serverCert *ServerCertificate) error {
	const op = "target.(TargetAliasProxyCertificate).fromServerCertificate"
	switch {
	case serverCert == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing server certificate")
	case len(serverCert.CertificatePem) == 0:
		return errors.New(ctx, errors.InvalidParameter, op, "missing certificate PEM data")
	case len(serverCert.PrivateKeyPem) == 0:
		return errors.New(ctx, errors.InvalidParameter, op, "missing private keyPEM data")
	}

	decodedBlock, _ := pem.Decode(serverCert.CertificatePem)
	if decodedBlock == nil || decodedBlock.Type != "CERTIFICATE" {
		return errors.New(ctx, errors.InvalidParameter, op, "invalid PEM data for certificate")
	}

	cert, err := x509.ParseCertificate(decodedBlock.Bytes)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("error parsing PEM data"))
	}
	t.Certificate = cert.Raw
	t.NotValidAfter = timestamp.New(cert.NotAfter)

	decodedKeyBlock, _ := pem.Decode(serverCert.PrivateKeyPem)
	if decodedKeyBlock == nil || decodedKeyBlock.Type != "EC PRIVATE KEY" {
		return errors.New(ctx, errors.InvalidParameter, op, "invalid PEM data for EC private key")
	}

	t.PrivateKey = decodedKeyBlock.Bytes
	privKey, err := x509.ParseECPrivateKey(t.PrivateKey)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("error parsing decoded private key"))
	}
	t.PublicKey, err = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("error marshalling public key"))
	}
	return nil
}

// ToServerCertificate converts the target alias proxy certificate to a server certificate
func (t *TargetAliasProxyCertificate) ToServerCertificate(ctx context.Context) (*ServerCertificate, error) {
	const op = "target.(TargetAliasProxyCertificate).ToServerCertificate"
	switch {
	case len(t.PrivateKey) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing private key")
	case len(t.Certificate) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing certificate")

	}

	return pemsToServerCertificate(ctx, t.Certificate, t.PrivateKey)
}
