package vault

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"

	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/structwrapping"
	"google.golang.org/protobuf/proto"
)

// ClientCertificate contains a client certificate and a private key for
// the certificate. It is owned by a credential store.
type ClientCertificate struct {
	*store.ClientCertificate
	tableName string `gorm:"-"`
}

// NewClientCertificate creates a new in memory ClientCertificate.
func NewClientCertificate(certificate []byte, key KeySecret) (*ClientCertificate, error) {
	const op = "vault.NewClientCertificate"
	if len(certificate) == 0 {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "no certificate")
	}

	certificateCopy := make([]byte, len(certificate))
	copy(certificateCopy, certificate)

	var keyCopy KeySecret
	if len(key) > 0 {
		keyCopy = make(KeySecret, len(key))
		copy(keyCopy, key)
	}

	c := &ClientCertificate{
		ClientCertificate: &store.ClientCertificate{
			Certificate:    certificateCopy,
			CertificateKey: keyCopy,
		},
	}
	return c, nil
}

func allocClientCertificate() *ClientCertificate {
	return &ClientCertificate{
		ClientCertificate: &store.ClientCertificate{},
	}
}

func (c *ClientCertificate) clone() *ClientCertificate {
	cp := proto.Clone(c.ClientCertificate)
	return &ClientCertificate{
		ClientCertificate: cp.(*store.ClientCertificate),
	}
}

// TableName returns the table name.
func (c *ClientCertificate) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "credential_vault_client_certificate"
}

// SetTableName sets the table name.
func (c *ClientCertificate) SetTableName(n string) {
	c.tableName = n
}

func (c *ClientCertificate) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "vault.(ClientCertificate).encrypt"
	if len(c.CertificateKey) == 0 {
		errors.New(ctx, errors.InvalidParameter, op, "no certificate key defined")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, c.ClientCertificate, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	keyId, err := cipher.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("error reading cipher key id"))
	}
	c.KeyId = keyId
	if err := c.hmacCertificateKey(ctx, cipher); err != nil {
		errors.Wrap(ctx, err, op)
	}
	return nil
}

func (c *ClientCertificate) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "vault.(ClientCertificate).decrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, c.ClientCertificate, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

func (c *ClientCertificate) hmacCertificateKey(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "vault.(ClientCertificate).hmacCertificateKey"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	reader, err := kms.NewDerivedReader(cipher, 32, []byte(c.StoreId), nil)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	key, _, err := ed25519.GenerateKey(reader)
	if err != nil {
		return errors.New(ctx, errors.Encrypt, op, "unable to generate derived key")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(c.CertificateKey)
	c.CertificateKeyHmac = mac.Sum(nil)
	return nil
}

func (c *ClientCertificate) insertQuery() (query string, queryValues []interface{}) {
	query = upsertClientCertQuery
	queryValues = []interface{}{
		sql.Named("store_id", c.StoreId),
		sql.Named("certificate", c.Certificate),
		sql.Named("certificate_key", c.CtCertificateKey),
		sql.Named("certificate_key_hmac", c.CertificateKeyHmac),
		sql.Named("key_id", c.KeyId),
	}
	return
}

func (c *ClientCertificate) deleteQuery() (query string, queryValues []interface{}) {
	query = deleteClientCertQuery
	queryValues = []interface{}{
		c.StoreId,
	}
	return
}

func (c *ClientCertificate) oplogMessage(opType db.OpType) *oplog.Message {
	msg := oplog.Message{
		Message:  c.clone(),
		TypeName: c.TableName(),
	}
	switch opType {
	case db.CreateOp, db.UpdateOp:
		msg.OpType = oplog.OpType_OP_TYPE_CREATE
	case db.DeleteOp:
		msg.OpType = oplog.OpType_OP_TYPE_DELETE
	}
	return &msg
}
