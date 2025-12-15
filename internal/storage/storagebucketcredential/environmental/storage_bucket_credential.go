// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package environmental provides a SBC subtype for a Environmental SBC.
// Importing this package will register it with the SBC package and
// allow the sbc.Repository to support environmental.StorageBucketCredential.
package environmental

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/storage/plugin/store"
	"github.com/hashicorp/boundary/internal/storage/storagebucketcredential"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"google.golang.org/protobuf/proto"
)

const (
	defaultTableName = "storage_bucket_credential_environmental"
)

// StorageBucketCredential is a resources that represents an Environmental SBC
// It is a subtype of storagebucketcredential.StorageBucketCredential.
type StorageBucketCredential struct {
	*store.StorageBucketCredentialEnvironmental
	tableName string `gorm:"-"`
}

// Ensure StorageBucketCredential implements interfaces
var (
	_ storagebucketcredential.StorageBucketCredential = (*StorageBucketCredential)(nil)
	_ db.VetForWriter                                 = (*StorageBucketCredential)(nil)
)

// NewStorageBucketCredential creates a new in memory environmental SBC.
func (h sbcHooks) NewStorageBucketCredential(
	ctx context.Context,
	storageBucketId string,
	_ ...storagebucketcredential.Option,
) (storagebucketcredential.StorageBucketCredential, error) {
	const op = "environmental.NewStorageBucketCredential"
	if storageBucketId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing storage bucket id")
	}
	sbc := &StorageBucketCredential{
		StorageBucketCredentialEnvironmental: &store.StorageBucketCredentialEnvironmental{
			StorageBucketId: storageBucketId,
		},
	}
	return sbc, nil
}

// AllocStorageBucketCredential will allocate a new StorageBucketCredential
func (h sbcHooks) AllocStorageBucketCredential() storagebucketcredential.StorageBucketCredential {
	return &StorageBucketCredential{
		StorageBucketCredentialEnvironmental: &store.StorageBucketCredentialEnvironmental{},
	}
}

// Clone creates a clone of the StorageBucketCredential
func (sbc *StorageBucketCredential) Clone() storagebucketcredential.StorageBucketCredential {
	cp := proto.Clone(sbc.StorageBucketCredentialEnvironmental)
	return &StorageBucketCredential{
		StorageBucketCredentialEnvironmental: cp.(*store.StorageBucketCredentialEnvironmental),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the environmental SBC
// before it's written.
func (sbc *StorageBucketCredential) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "environmental.(StorageBucketCredential).VetForWrite"
	if sbc.StorageBucketId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing storage bucket id")
	}
	return nil
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

func (sbc *StorageBucketCredential) SetCtSecrets(_ []byte) {}

func (sbc *StorageBucketCredential) SetSecrets(_ []byte) {}

func (sbc *StorageBucketCredential) SetKeyId(_ string) {}

func (sbc *StorageBucketCredential) GetPrivateId() string {
	return sbc.PrivateId
}

func (sbc *StorageBucketCredential) GetType() storagebucketcredential.Subtype {
	return storagebucketcredential.EnvironmentalSubtype
}

func (sbc *StorageBucketCredential) GetCtSecrets() []byte {
	return nil
}

func (sbc *StorageBucketCredential) GetSecrets() []byte {
	return nil
}

func (sbc *StorageBucketCredential) GetKeyId() string {
	return ""
}

func (sbc *StorageBucketCredential) CreateDBQuery() string {
	return CreateStorageBucketCredentialEnvironmentalQuery
}

func (sbc *StorageBucketCredential) HmacSecrets(ctx context.Context, _ wrapping.Wrapper) ([]byte, error) {
	const op = "environmental.(StorageBucketCredential).HmacSecrets"
	return nil, errors.New(ctx, errors.Unknown, op, "HmacSecrets not implemented")
}

func (sbc *StorageBucketCredential) Encrypt(ctx context.Context, _ wrapping.Wrapper) error {
	const op = "environmental.(StorageBucketCredential).Encrypt"
	return errors.New(ctx, errors.Unknown, op, "Encrypt not implemented")
}

func (sbc *StorageBucketCredential) Decrypt(ctx context.Context, _ wrapping.Wrapper) error {
	const op = "environmental.(StorageBucketCredential).Decrypt"
	return errors.New(ctx, errors.Unknown, op, "Decrypt not implemented")
}

func (sbc *StorageBucketCredential) ToPersisted(ctx context.Context) (*storagebuckets.StorageBucketPersisted, error) {
	const op = "environmental.(StorageBucketCredential).ToPersisted"
	return nil, errors.New(ctx, errors.Unknown, op, "ToPersisted not implemented")
}
