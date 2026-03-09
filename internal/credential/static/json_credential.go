// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"
	"encoding/json"

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

var _ credential.Static = (*JsonCredential)(nil)

// A JsonCredential contains the credential with a json secret.
// It is owned by a credential store.
type JsonCredential struct {
	*store.JsonCredential
	tableName string `gorm:"-"`
}

// NewJsonCredential creates a new in memory static Credential containing a
// json secret that is assigned to storeId. Name and description are the only
// valid options. All other options are ignored.
func NewJsonCredential(
	ctx context.Context,
	storeId string,
	object credential.JsonObject,
	opt ...Option,
) (*JsonCredential, error) {
	const op = "static.NewJsonCredential"
	var objectB []byte
	var err error

	// Since the secret is an unordered map of dynamically typed values, the hmac value will not be consistent.
	// In order to calculate a consistent hmac value, the input must be deterministic,
	// which is done by marshalling the secret.
	if len(object.AsMap()) > 0 {
		objectB, err = json.Marshal(object.AsMap())
		if err != nil {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "invalid secret")
		}
	}

	opts := getOpts(opt...)
	jsonCred := &JsonCredential{
		JsonCredential: &store.JsonCredential{
			StoreId:     storeId,
			Name:        opts.withName,
			Description: opts.withDescription,
			Object:      objectB,
		},
	}

	return jsonCred, nil
}

func allocJsonCredential() *JsonCredential {
	return &JsonCredential{
		JsonCredential: &store.JsonCredential{},
	}
}

func (c *JsonCredential) clone() *JsonCredential {
	cp := proto.Clone(c.JsonCredential)
	return &JsonCredential{
		JsonCredential: cp.(*store.JsonCredential),
	}
}

// TableName returns the table name.
func (c *JsonCredential) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "credential_static_json_credential"
}

// SetTableName sets the table name.
func (c *JsonCredential) SetTableName(n string) {
	c.tableName = n
}

// GetResourceType returns the resource type of the Credential
func (c *JsonCredential) GetResourceType() resource.Type {
	return resource.Credential
}

func (c *JsonCredential) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.PublicId},
		"resource-type":      []string{"credential-static-json"},
		"op-type":            []string{op.String()},
	}
	if c.StoreId != "" {
		metadata["store-id"] = []string{c.StoreId}
	}
	return metadata
}

func (c *JsonCredential) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(JsonCredential).encrypt"
	if len(c.Object) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "no object defined")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, c.JsonCredential, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	keyId, err := cipher.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("error reading cipher key id"))
	}
	c.KeyId = keyId
	if err := c.hmacObject(ctx, cipher); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (c *JsonCredential) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(JsonCredential).decrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, c.JsonCredential, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

func (c *JsonCredential) hmacObject(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(JsonCredential).hmacObject"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	hm, err := crypto.HmacSha256(ctx, c.Object, cipher, []byte(c.StoreId), nil)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	c.ObjectHmac = []byte(hm)
	return nil
}

type deletedJSONCredential struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedJSONCredential) TableName() string {
	return "credential_static_json_credential_deleted"
}
