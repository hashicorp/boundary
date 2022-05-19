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
	"google.golang.org/protobuf/proto"
)

// A UserPasswordCredential contains the credential with a username and password.
// It is owned by a credential store.
type UserPasswordCredential struct {
	*store.UserPasswordCredential
	tableName string `gorm:"-"`
}

// NewUserPasswordCredential creates a new in memory static Credential containing a
// username and password that is assigned to storeId. Name and description are the only
// valid options. All other options are ignored.
func NewUserPasswordCredential(
	storeId string,
	username string,
	password credential.Password,
	opt ...Option,
) (*UserPasswordCredential, error) {
	opts := getOpts(opt...)
	l := &UserPasswordCredential{
		UserPasswordCredential: &store.UserPasswordCredential{
			StoreId:     storeId,
			Name:        opts.withName,
			Description: opts.withDescription,
			Username:    username,
			Password:    []byte(password),
		},
	}
	return l, nil
}

func allocUserPasswordCredential() *UserPasswordCredential {
	return &UserPasswordCredential{
		UserPasswordCredential: &store.UserPasswordCredential{},
	}
}

func (c *UserPasswordCredential) clone() *UserPasswordCredential {
	cp := proto.Clone(c.UserPasswordCredential)
	return &UserPasswordCredential{
		UserPasswordCredential: cp.(*store.UserPasswordCredential),
	}
}

// TableName returns the table name.
func (c *UserPasswordCredential) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "credential_static_username_password_credential"
}

// SetTableName sets the table name.
func (c *UserPasswordCredential) SetTableName(n string) {
	c.tableName = n
}

func (c *UserPasswordCredential) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.PublicId},
		"resource-type":      []string{"credential-static-username-password"},
		"op-type":            []string{op.String()},
	}
	if c.StoreId != "" {
		metadata["store-id"] = []string{c.StoreId}
	}
	return metadata
}

func (c *UserPasswordCredential) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(UserPasswordCredential).encrypt"
	if len(c.Password) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "no password defined")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, c.UserPasswordCredential, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	keyId, err := cipher.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("error reading cipher key id"))
	}
	c.KeyId = keyId
	if err := c.hmacPassword(ctx, cipher); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (c *UserPasswordCredential) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(UserPasswordCredential).decrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, c.UserPasswordCredential, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

func (c *UserPasswordCredential) hmacPassword(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(UserPasswordCredential).hmacPassword"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	hm, err := crypto.HmacSha256(ctx, c.Password, cipher, []byte(c.StoreId), nil, crypto.WithEd25519())
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	c.PasswordHmac = []byte(hm)
	return nil
}
