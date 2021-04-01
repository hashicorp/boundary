package vault

import (
	"context"

	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
	"google.golang.org/protobuf/proto"
)

// ClientCertificate contains a client certificate and a private key for
// the certificate. It is owned by a credential store.
type ClientCertificate struct {
	*store.ClientCertificate
	tableName string `gorm:"-"`
}

func newClientCertificate(storeId string, certificate []byte, key []byte) (*ClientCertificate, error) {
	const op = "vault.newClientCertificate"
	if storeId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no store id")
	}
	if len(certificate) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "no certificate")
	}
	if len(key) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "no certificate key")
	}

	certificateCopy := make([]byte, len(certificate))
	copy(certificateCopy, certificate)

	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	c := &ClientCertificate{
		ClientCertificate: &store.ClientCertificate{
			StoreId:        storeId,
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

func (c *ClientCertificate) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-type": []string{"client-certificate"},
		"op-type":       []string{op.String()},
	}
	if c.StoreId != "" {
		metadata["store-id"] = []string{c.StoreId}
	}
	return metadata
}

func (c *ClientCertificate) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "vault.(ClientCertificate).encrypt"
	if err := structwrapping.WrapStruct(ctx, cipher, c.ClientCertificate, nil); err != nil {
		return errors.Wrap(err, op, errors.WithCode(errors.Encrypt))
	}
	c.KeyId = cipher.KeyID()
	return nil
}

func (c *ClientCertificate) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "vault.(ClientCertificate).decrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, c.ClientCertificate, nil); err != nil {
		return errors.Wrap(err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}
