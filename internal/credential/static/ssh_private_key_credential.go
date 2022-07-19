package static

import (
	"context"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/libs/crypto"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

var _ credential.Static = (*SshPrivateKeyCredential)(nil)

// A SshPrivateKeyCredential contains the credential with a username and private key.
// It is owned by a credential store.
type SshPrivateKeyCredential struct {
	*store.SshPrivateKeyCredential
	tableName string `gorm:"-"`
}

// NewSshPrivateKeyCredential creates a new in memory static Credential containing a
// username and private key that is assigned to storeId. Name and description are the only
// valid options. All other options are ignored.
func NewSshPrivateKeyCredential(
	ctx context.Context,
	storeId string,
	username string,
	privateKey credential.PrivateKey,
	opt ...Option,
) (*SshPrivateKeyCredential, error) {
	const op = "static.NewSshPrivateKeyCredential"

	if len(privateKey) != 0 {
		_, err := ssh.ParsePrivateKey(privateKey)
		switch {
		case err == nil:
		case err.Error() == (&ssh.PassphraseMissingError{}).Error():
			// This is okay, if it's brokered and the client can use it, no worries
		default:
			return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
		}
	}

	opts := getOpts(opt...)
	l := &SshPrivateKeyCredential{
		SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
			StoreId:     storeId,
			Name:        opts.withName,
			Description: opts.withDescription,
			Username:    username,
			PrivateKey:  privateKey,
		},
	}
	return l, nil
}

func allocSshPrivateKeyCredential() *SshPrivateKeyCredential {
	return &SshPrivateKeyCredential{
		SshPrivateKeyCredential: &store.SshPrivateKeyCredential{},
	}
}

func (c *SshPrivateKeyCredential) clone() *SshPrivateKeyCredential {
	cp := proto.Clone(c.SshPrivateKeyCredential)
	return &SshPrivateKeyCredential{
		SshPrivateKeyCredential: cp.(*store.SshPrivateKeyCredential),
	}
}

// TableName returns the table name.
func (c *SshPrivateKeyCredential) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "credential_static_ssh_private_key_credential"
}

// SetTableName sets the table name.
func (c *SshPrivateKeyCredential) SetTableName(n string) {
	c.tableName = n
}

func (c *SshPrivateKeyCredential) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.PublicId},
		"resource-type":      []string{"credential-static-ssh-private-key"},
		"op-type":            []string{op.String()},
	}
	if c.StoreId != "" {
		metadata["store-id"] = []string{c.StoreId}
	}
	return metadata
}

func (c *SshPrivateKeyCredential) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(SshPrivateKeyCredential).encrypt"
	if len(c.PrivateKey) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "no private key defined")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, c.SshPrivateKeyCredential, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	keyId, err := cipher.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("error reading cipher key id"))
	}
	c.KeyId = keyId
	if err := c.hmacPrivateKey(ctx, cipher); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (c *SshPrivateKeyCredential) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(SshPrivateKeyCredential).decrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, c.SshPrivateKeyCredential, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

func (c *SshPrivateKeyCredential) hmacPrivateKey(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(SshPrivateKeyCredential).hmacPrivateKey"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	hm, err := crypto.HmacSha256(ctx, c.PrivateKey, cipher, []byte(c.StoreId), nil)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	c.PrivateKeyHmac = []byte(hm)
	return nil
}
