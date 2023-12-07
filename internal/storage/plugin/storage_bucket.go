// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package plugin

import (
	"context"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/libs/crypto"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/storage/plugin/store"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// StorageBucket represents a bucket within an external object store. It contains secret
// data needed to create and read objects within the external object store.
type StorageBucket struct {
	*store.StorageBucket
	tableName string `gorm:"-"`

	Secrets *structpb.Struct `gorm:"-"`
}

func allocStorageBucket() *StorageBucket {
	return &StorageBucket{
		StorageBucket: &store.StorageBucket{},
	}
}

// clone provides a deep copy of the storage bucket with the exception of the
// secret. The secret shallow copied.
func (s *StorageBucket) clone() *StorageBucket {
	cp := proto.Clone(s.StorageBucket)
	newSecret := proto.Clone(s.Secrets)

	sb := &StorageBucket{
		StorageBucket: cp.(*store.StorageBucket),
		Secrets:       newSecret.(*structpb.Struct),
	}
	// proto.Clone will convert slices with length and capacity of 0 to nil.
	// Fix this since gorm treats empty slices differently than nil.
	if s.Attributes != nil && len(s.Attributes) == 0 && sb.Attributes == nil {
		sb.Attributes = []byte{}
	}
	return sb
}

// TableName returns the table name for the storage bucket.
func (s *StorageBucket) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return "storage_plugin_storage_bucket"
}

// SetTableName sets the table name.
func (s *StorageBucket) SetTableName(n string) {
	s.tableName = n
}

func (s *StorageBucket) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{s.PublicId},
		"resource-type":      []string{"plugin-storage-bucket"},
		"op-type":            []string{op.String()},
	}
	if s.ScopeId != "" {
		metadata["scope-id"] = []string{s.ScopeId}
	}
	return metadata
}

type StorageBucketSecret struct {
	*store.StorageBucketSecret
	tableName string `gorm:"-"`
}

func allocStorageBucketSecret() *StorageBucketSecret {
	return &StorageBucketSecret{
		StorageBucketSecret: &store.StorageBucketSecret{},
	}
}

// newStorageBucketSecret creates an in memory storage bucket secret from a json
// formatted generic struct.
func newStorageBucketSecret(ctx context.Context, storageBucketId string, secret *structpb.Struct) (*StorageBucketSecret, error) {
	const op = "plugin.newStorageBucketSecret"
	s := &StorageBucketSecret{
		StorageBucketSecret: &store.StorageBucketSecret{
			StorageBucketId: storageBucketId,
		},
	}

	if secret != nil {
		sec, err := proto.Marshal(secret)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
		}
		s.Secrets = sec
	}
	return s, nil
}

func (sbs *StorageBucketSecret) clone() *StorageBucketSecret {
	cp := proto.Clone(sbs.StorageBucketSecret)
	return &StorageBucketSecret{
		StorageBucketSecret: cp.(*store.StorageBucketSecret),
	}
}

// TableName returns the table name for the storage bucket secrets.
func (sbs *StorageBucketSecret) TableName() string {
	if sbs.tableName != "" {
		return sbs.tableName
	}
	return "storage_plugin_storage_bucket_secret"
}

// SetTableName sets the table name.
func (sbs *StorageBucketSecret) SetTableName(n string) {
	sbs.tableName = n
}

// hmacField simply hmac's a field in a consistent manner for this pkg
func hmacField(ctx context.Context, cipher wrapping.Wrapper, field []byte, publicId string) ([]byte, error) {
	const op = "plugin.hmacField"
	hm, err := crypto.HmacSha256(ctx, field, cipher, []byte(publicId), nil)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return []byte(hm), nil
}

// only hmac's the secret's value. does not modify the underlying secret
// returns nil on failure
func (sbs *StorageBucketSecret) hmacSecrets(ctx context.Context, cipher wrapping.Wrapper) ([]byte, error) {
	const op = "plugin.(StorageBucketSecret).hmacSecrets"
	if cipher == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	var err error
	if _, err = cipher.KeyId(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("failed to read cipher key id"))
	}
	var hmac []byte
	if hmac, err = hmacField(ctx, cipher, sbs.Secrets, sbs.StorageBucketId); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("failed to hmac secrets"))
	}

	return hmac, nil
}

// encrypt the bind credential before writing it to the database
func (sbs *StorageBucketSecret) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "plugin.(StorageBucketSecret).encrypt"
	if util.IsNil(cipher) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, sbs.StorageBucketSecret); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	var err error
	if sbs.KeyId, err = cipher.KeyId(ctx); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("failed to read cipher key id"))
	}

	return nil
}

func (sbs *StorageBucketSecret) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "plugin.(StorageBucketSecret).decrypt"
	if util.IsNil(cipher) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.UnwrapStruct(ctx, cipher, sbs.StorageBucketSecret, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	sbs.CtSecrets = nil
	return nil
}

func (sbs *StorageBucketSecret) toPersisted(ctx context.Context) (*storagebuckets.StorageBucketPersisted, error) {
	const op = "plugin.(StorageBucketSecret).toPersisted"
	if sbs.Secrets == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "secret data not populated")
	}
	sec := &storagebuckets.StorageBucketPersisted{
		Data: &structpb.Struct{},
	}
	if err := proto.Unmarshal(sbs.Secrets, sec.Data); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
	}
	return sec, nil
}

type storageBucketAgg struct {
	PublicId         string `gorm:"primary_key"`
	ScopeId          string
	Name             string
	Description      string
	CreateTime       *timestamp.Timestamp
	UpdateTime       *timestamp.Timestamp
	Version          uint32
	PluginId         string
	BucketName       string
	BucketPrefix     string
	WorkerFilter     string
	Attributes       []byte
	SecretsEncrypted []byte
	SecretsHmac      []byte
	KeyId            string
}

// TableName returns the table name for gorm
func (sba *storageBucketAgg) TableName() string {
	return "storage_plugin_storage_bucket_with_secret"
}

func (sba *storageBucketAgg) GetPublicId() string {
	return sba.PublicId
}

func (sba *storageBucketAgg) toStorageBucketAndSecret() (*StorageBucket, *StorageBucketSecret) {
	sb := allocStorageBucket()
	sb.PublicId = sba.PublicId
	sb.ScopeId = sba.ScopeId
	sb.Name = sba.Name
	sb.Description = sba.Description
	sb.CreateTime = sba.CreateTime
	sb.UpdateTime = sba.UpdateTime
	sb.Version = sba.Version
	sb.PluginId = sba.PluginId
	sb.BucketName = sba.BucketName
	sb.BucketPrefix = sba.BucketPrefix
	sb.WorkerFilter = sba.WorkerFilter
	sb.Attributes = sba.Attributes
	sb.SecretsHmac = sba.SecretsHmac

	var sbs *StorageBucketSecret
	if len(sba.SecretsEncrypted) > 0 {
		sbs = allocStorageBucketSecret()
		sbs.StorageBucketId = sba.PublicId
		sbs.CtSecrets = sba.SecretsEncrypted
		sbs.KeyId = sba.KeyId
	}
	return sb, sbs
}
