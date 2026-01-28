// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package managedsecret provides a SBC subtype for a Managed Secret SBC.
// Importing this package will register it with the SBC package and
// allow the sbc.Repository to support managedsecret.StorageBucketCredential.
package managedsecret

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/libs/crypto"
	"github.com/hashicorp/boundary/internal/storage/plugin/store"
	"github.com/hashicorp/boundary/internal/storage/storagebucketcredential"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	defaultTableName = "storage_bucket_credential_managed_secret"
)

// StorageBucketCredential is a resources that represents an Managed Secret SBC
// It is a subtype of storagebucketcredential.StorageBucketCredential.
type StorageBucketCredential struct {
	*store.StorageBucketCredentialManagedSecret
	tableName string `gorm:"-"`
}

// Ensure StorageBucketCredential implements interfaces
var (
	_ storagebucketcredential.StorageBucketCredential = (*StorageBucketCredential)(nil)
	_ db.VetForWriter                                 = (*StorageBucketCredential)(nil)
)

// NewStorageBucketCredential creates a new in memory managed secret SBC.
func (h sbcHooks) NewStorageBucketCredential(
	ctx context.Context,
	storageBucketId string,
	opt ...storagebucketcredential.Option,
) (storagebucketcredential.StorageBucketCredential, error) {
	const op = "managedsecret.NewStorageBucketCredential"
	opts := storagebucketcredential.GetOpts(opt...)
	if storageBucketId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing storage bucket id")
	}
	if opts.WithSecret == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing secret")
	}
	var secrets []byte
	if opts.WithSecret != nil {
		var err error
		secrets, err = proto.Marshal(opts.WithSecret)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to marshal secrets"))
		}
		if len(secrets) == 0 {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "empty secret")
		}
	}

	sbc := &StorageBucketCredential{
		StorageBucketCredentialManagedSecret: &store.StorageBucketCredentialManagedSecret{
			StorageBucketId: storageBucketId,
			Secrets:         secrets,
			KeyId:           opts.WithKeyId,
		},
	}
	return sbc, nil
}

// AllocStorageBucketCredential will allocate a new StorageBucketCredential
func (h sbcHooks) AllocStorageBucketCredential() storagebucketcredential.StorageBucketCredential {
	return &StorageBucketCredential{
		StorageBucketCredentialManagedSecret: &store.StorageBucketCredentialManagedSecret{},
	}
}

// Clone creates a clone of the StorageBucketCredential
func (sbc *StorageBucketCredential) Clone() storagebucketcredential.StorageBucketCredential {
	cp := proto.Clone(sbc.StorageBucketCredentialManagedSecret)
	return &StorageBucketCredential{
		StorageBucketCredentialManagedSecret: cp.(*store.StorageBucketCredentialManagedSecret),
	}
}

func (sbc *StorageBucketCredential) CreateDBQuery() string {
	return CreateStorageBucketCredentialManagedSecretQuery
}

// VetForWrite implements db.VetForWrite() interface and validates the managed secret SBC
// before it's written.
func (sbc *StorageBucketCredential) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "managedsecret.(StorageBucketCredential).VetForWrite"
	if sbc.StorageBucketId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing storage bucket id")
	}
	return nil
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
func (sbc *StorageBucketCredential) HmacSecrets(ctx context.Context, cipher wrapping.Wrapper) ([]byte, error) {
	const op = "managedsecret.(StorageBucketCredential).hmacSecrets"
	if cipher == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	var err error
	if _, err = cipher.KeyId(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("failed to read cipher key id"))
	}
	var hmac []byte
	if hmac, err = hmacField(ctx, cipher, sbc.Secrets, sbc.StorageBucketId); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("failed to hmac secrets"))
	}

	return hmac, nil
}

// encrypt the bind credential before writing it to the database
func (sbc *StorageBucketCredential) Encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "managedsecret.(StorageBucketCredential)).encrypt"
	if util.IsNil(cipher) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, sbc.StorageBucketCredentialManagedSecret); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	var err error
	if sbc.KeyId, err = cipher.KeyId(ctx); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("failed to read cipher key id"))
	}

	return nil
}

func (sbc *StorageBucketCredential) Decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "managedsecret.(StorageBucketCredential).decrypt"
	if util.IsNil(cipher) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.UnwrapStruct(ctx, cipher, sbc.StorageBucketCredentialManagedSecret, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	sbc.CtSecrets = nil
	return nil
}

func (sbc *StorageBucketCredential) ToPersisted(ctx context.Context) (*storagebuckets.StorageBucketPersisted, error) {
	const op = "plugin.(StorageBucketCredentialManagedSecret).toPersisted"
	if sbc.Secrets == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "secret data not populated")
	}
	sec := &storagebuckets.StorageBucketPersisted{
		Data: &structpb.Struct{},
	}
	if err := proto.Unmarshal(sbc.Secrets, sec.Data); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
	}
	return sec, nil
}

// TableName returns the tablename to override the default gorm table name
func (sbc *StorageBucketCredential) TableName() string {
	if sbc.tableName != "" {
		return sbc.tableName
	}
	return defaultTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (sbc *StorageBucketCredential) SetTableName(n string) {
	sbc.tableName = n
}

func (sbc *StorageBucketCredential) SetPrivateId(privateId string) {
	sbc.PrivateId = privateId
}

func (sbc *StorageBucketCredential) SetStorageBucketId(storageBucketId string) {
	sbc.StorageBucketId = storageBucketId
}

func (sbc *StorageBucketCredential) SetCtSecrets(s []byte) {
	sbc.CtSecrets = s
}

func (sbc *StorageBucketCredential) SetSecrets(s []byte) {
	sbc.Secrets = s
}

func (sbc *StorageBucketCredential) SetKeyId(s string) {
	sbc.KeyId = s
}

func (sbc *StorageBucketCredential) GetPrivateId() string {
	return sbc.PrivateId
}

func (sbc *StorageBucketCredential) GetType() storagebucketcredential.Subtype {
	return storagebucketcredential.ManagedSecretSubtype
}

func (sbc *StorageBucketCredential) GetCtSecrets() []byte {
	return sbc.CtSecrets
}

func (sbc *StorageBucketCredential) GetSecrets() []byte {
	return sbc.Secrets
}

func (sbc *StorageBucketCredential) GetKeyId() string {
	return sbc.KeyId
}
