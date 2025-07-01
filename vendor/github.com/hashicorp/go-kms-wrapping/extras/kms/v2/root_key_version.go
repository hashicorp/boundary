// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
)

// rootKeyVersion represents a version of a RootKey
type rootKeyVersion struct {
	// PrivateId is used to access the root key
	PrivateId string `gorm:"primary_key"`
	// RootKeyId is the root_key_id for this version
	RootKeyId string `gorm:"default:null"`
	// plain-text of the key data.  we are NOT storing this plain-text key
	// in the db.
	Key []byte `json:"key,omitempty" gorm:"-" wrapping:"pt,key_data"`
	// ciphertext key data stored in the database
	// @inject_tag: `gorm:"column:key;not_null" wrapping:"ct,key_data"`
	CtKey []byte `json:"ct_key,omitempty" gorm:"column:key;not_null" wrapping:"ct,key_data"`
	// version of the key data.  This is not used for optimistic locking, since
	// key versions are immutable.  It's just the version of the key.
	// @inject_tag: `gorm:"default:null"`
	Version uint32 `json:"version,omitempty" gorm:"default:null"`
	// CreateTime from the db
	CreateTime time.Time `json:"create_time,omitempty" gorm:"default:current_timestamp"`

	// tableNamePrefix defines the prefix to use before the table name and
	// allows us to support custom prefixes as well as multi KMSs within a
	// single schema.
	tableNamePrefix string `gorm:"-"`
}

// newRootKeyVersion creates a new in memory root key. No options are currently
// supported.
func newRootKeyVersion(rootKeyId string, key []byte, _ ...Option) (*rootKeyVersion, error) {
	const op = "kms.newRootKeyVersion"
	if rootKeyId == "" {
		return nil, fmt.Errorf("%s: missing root key id: %w", op, ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("%s: missing key id: %w", op, ErrInvalidParameter)
	}

	k := &rootKeyVersion{
		RootKeyId: rootKeyId,
		Key:       key,
	}
	return k, nil
}

// TableName returns the table name
func (k *rootKeyVersion) TableName() string {
	const tableName = "root_key_version"
	return fmt.Sprintf("%s_%s", k.tableNamePrefix, tableName)
}

// Clone creates a clone of the RootKeyVersion
func (k *rootKeyVersion) Clone() *rootKeyVersion {
	clone := &rootKeyVersion{
		PrivateId:       k.PrivateId,
		RootKeyId:       k.RootKeyId,
		CreateTime:      k.CreateTime,
		tableNamePrefix: k.tableNamePrefix,
	}
	clone.Key = make([]byte, len(k.Key))
	copy(clone.Key, k.Key)

	clone.CtKey = make([]byte, len(k.CtKey))
	copy(clone.CtKey, k.CtKey)
	return clone
}

// vetForWrite validates the root key version before it's written.
func (k *rootKeyVersion) vetForWrite(ctx context.Context, opType dbw.OpType) error {
	const op = "kms.(rootKeyVersion).vetForWrite"
	if k.PrivateId == "" {
		return fmt.Errorf("%s: missing private id: %w", op, ErrInvalidParameter)
	}
	switch opType {
	case dbw.CreateOp:
		if k.CtKey == nil {
			return fmt.Errorf("%s: missing key: %w", op, ErrInvalidParameter)
		}
		if k.RootKeyId == "" {
			return fmt.Errorf("%s: missing root key id: %w", op, ErrInvalidParameter)
		}
	case dbw.UpdateOp:
		return fmt.Errorf("%s: key is immutable: %w", op, ErrInvalidParameter)
	}
	return nil
}

// Encrypt will encrypt the root key version's key
func (k *rootKeyVersion) Encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "kms.(rootKeyVersion).Encrypt"
	if cipher == nil {
		return fmt.Errorf("%s: missing cipher: %w", op, ErrInvalidParameter)
	}
	if err := structwrapping.WrapStruct(ctx, cipher, k, nil); err != nil {
		return fmt.Errorf("%s: unable to encrypt: %w", op, err)
	}
	return nil
}

// Decrypt will decrypt the root key version's key
func (k *rootKeyVersion) Decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "kms.(rootKeyVersion).Decrypt"
	if cipher == nil {
		return fmt.Errorf("%s: missing cipher: %w", op, ErrInvalidParameter)
	}
	if err := structwrapping.UnwrapStruct(ctx, cipher, k, nil); err != nil {
		return fmt.Errorf("%s: unable to decrypt: %w", op, err)
	}
	return nil
}

// GetPrivateId returns the key's private id
func (k *rootKeyVersion) GetPrivateId() string { return k.PrivateId }
