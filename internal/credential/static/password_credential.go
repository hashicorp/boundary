// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static/store"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/libs/crypto"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	"google.golang.org/protobuf/proto"
)

var _ credential.Static = (*PasswordCredential)(nil)

// PasswordCredential contains the credential with a password.
// It is owned by a credential store.
type PasswordCredential struct {
	*store.PasswordCredential
	tableName string `gorm:"-"`
}

// NewPasswordCredential creates a new in memory static Credential containing a
// password that is assigned to storeId. Name and description are the only
// valid options. All other options are ignored.
func NewPasswordCredential(
	storeId string,
	password credential.Password,
	opt ...Option,
) (*PasswordCredential, error) {
	opts := getOpts(opt...)
	l := &PasswordCredential{
		PasswordCredential: &store.PasswordCredential{
			StoreId:     storeId,
			Name:        opts.withName,
			Description: opts.withDescription,
			Password:    []byte(password),
		},
	}
	return l, nil
}

func allocPasswordCredential() *PasswordCredential {
	return &PasswordCredential{
		PasswordCredential: &store.PasswordCredential{},
	}
}

func (c *PasswordCredential) clone() *PasswordCredential {
	cp := proto.Clone(c.PasswordCredential)
	return &PasswordCredential{
		PasswordCredential: cp.(*store.PasswordCredential),
	}
}

// TableName returns the table name.
func (c *PasswordCredential) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "credential_static_password_credential"
}

// SetTableName sets the table name.
func (c *PasswordCredential) SetTableName(n string) {
	c.tableName = n
}

// GetResourceType returns the resource type of the Credential
func (c *PasswordCredential) GetResourceType() resource.Type {
	return resource.Credential
}

func (c *PasswordCredential) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.PublicId},
		"resource-type":      []string{"credential-static-password"},
		"op-type":            []string{op.String()},
	}
	if c.StoreId != "" {
		metadata["store-id"] = []string{c.StoreId}
	}
	return metadata
}

func (c *PasswordCredential) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(PasswordCredential).encrypt"
	if len(c.Password) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "no password defined")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, c.PasswordCredential, nil); err != nil {
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

func (c *PasswordCredential) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(PasswordCredential).decrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, c.PasswordCredential, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

func (c *PasswordCredential) hmacPassword(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(PasswordCredential).hmacPassword"
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

type deletedPasswordCredential struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedPasswordCredential) TableName() string {
	return "credential_static_password_credential_deleted"
}
