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

var _ credential.Static = (*UsernamePasswordDomainCredential)(nil)

// A UsernamePasswordDomainCredential contains the credential with a username, password, and domain.
// It is owned by a credential store.
type UsernamePasswordDomainCredential struct {
	*store.UsernamePasswordDomainCredential
	tableName string `gorm:"-"`
}

// NewUsernamePasswordDomainCredential creates a new in memory static Credential containing a
// username, password, and domain that is assigned to storeId. Name and description are the only
// valid options. All other options are ignored.
func NewUsernamePasswordDomainCredential(
	storeId string,
	username string,
	password credential.Password,
	domain string,

	opt ...Option,
) (*UsernamePasswordDomainCredential, error) {
	opts := getOpts(opt...)
	l := &UsernamePasswordDomainCredential{
		UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
			StoreId:     storeId,
			Name:        opts.withName,
			Description: opts.withDescription,
			Username:    username,
			Password:    []byte(password),
			Domain:      domain,
		},
	}
	return l, nil
}

func allocUsernamePasswordDomainCredential() *UsernamePasswordDomainCredential {
	return &UsernamePasswordDomainCredential{
		UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{},
	}
}

func (c *UsernamePasswordDomainCredential) clone() *UsernamePasswordDomainCredential {
	cp := proto.Clone(c.UsernamePasswordDomainCredential)
	return &UsernamePasswordDomainCredential{
		UsernamePasswordDomainCredential: cp.(*store.UsernamePasswordDomainCredential),
	}
}

// TableName returns the table name.
func (c *UsernamePasswordDomainCredential) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "credential_static_username_password_domain_credential"
}

// SetTableName sets the table name.
func (c *UsernamePasswordDomainCredential) SetTableName(n string) {
	c.tableName = n
}

// GetResourceType returns the resource type of the Credential
func (c *UsernamePasswordDomainCredential) GetResourceType() resource.Type {
	return resource.Credential
}

func (c *UsernamePasswordDomainCredential) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.PublicId},
		"resource-type":      []string{"credential-static-username-password-domain"},
		"op-type":            []string{op.String()},
	}
	if c.StoreId != "" {
		metadata["store-id"] = []string{c.StoreId}
	}
	return metadata
}

func (c *UsernamePasswordDomainCredential) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(UsernamePasswordDomainCredential).encrypt"
	if len(c.Password) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "no password defined")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, c.UsernamePasswordDomainCredential, nil); err != nil {
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

func (c *UsernamePasswordDomainCredential) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(UsernamePasswordDomainCredential).decrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, c.UsernamePasswordDomainCredential, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

func (c *UsernamePasswordDomainCredential) hmacPassword(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(UsernamePasswordDomainCredential).hmacPassword"
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

type deletedUsernamePasswordDomainCredential struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedUsernamePasswordDomainCredential) TableName() string {
	return "credential_static_username_password_domain_credential_deleted"
}
