// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package storagebucketcredential

import (
	"context"
	goerrs "errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// StorageBucketCredential is a commmon interface for all storage bucket credential subtypes
type StorageBucketCredential interface {
	HmacSecrets(context.Context, wrapping.Wrapper) ([]byte, error)
	Encrypt(context.Context, wrapping.Wrapper) error
	Decrypt(context.Context, wrapping.Wrapper) error
	ToPersisted(context.Context) (*storagebuckets.StorageBucketPersisted, error)
	Clone() StorageBucketCredential
	CreateDBQuery() string
	GetPrivateId() string
	GetStorageBucketId() string
	GetType() Subtype
	GetSecrets() []byte
	GetCtSecrets() []byte
	GetKeyId() string
	SetPrivateId(string)
	SetStorageBucketId(string)
	SetSecrets([]byte)
	SetCtSecrets([]byte)
	SetKeyId(string)
}

const (
	sbcDefaultTable = "storage_bucket_credential_all_subtypes"
)

type Subtype string

const (
	UnknownSubtype       Subtype = "unknown"
	ManagedSecretSubtype Subtype = "managed_secret"
	EnvironmentalSubtype Subtype = "environmental"
)

var errSBCSubtypeNotFound = goerrs.New("storage bucket credential subtype not found")

// storageBucketCredential provides a common way to return storage bucket credentials
// regardless of their underlying type.
type storageBucketCredential struct {
	// tableName is the name of the table in the database
	tableName string `gorm:"-"`
	// PrivateId is a surrogate key suitable for use via API.
	PrivateId string `gorm:"primary_key"`
	// StorageBucketId is the public id of the storage bucket.
	StorageBucketId string `gorm:"not_null"`
	// Secrets is the plain-text of the secret data. We are not storing this plain-text
	// value in the database.
	Secrets []byte `gorm:"-" wrapping:"pt,secrets_data"`
	// CtSecrets is the ciphertext of the secret data stored in the db.
	CtSecrets []byte `gorm:"column:secrets_encrypted;not_null" wrapping:"ct,secrets_data"`
	// The KeyId of the kms database key used for encrypting this entry.
	// It must be set.
	KeyId string `gorm:"not_null"`
	// Type represents the type of the Storage Bucket Credential
	Type string `gorm:"default:null"`
}

// AllocStorageBucketCredential will allocate a storage bucket credential
func AllocStorageBucketCredential() *storageBucketCredential {
	return &storageBucketCredential{}
}

// TableName provides an overridden gorm table name for storage bucket credentials.
func (sbc *storageBucketCredential) TableName() string {
	if sbc.tableName != "" {
		return sbc.tableName
	}
	return sbcDefaultTable
}

// SetTableName sets the table name for the resource.  If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (sbc *storageBucketCredential) SetTableName(n string) {
	switch n {
	case "":
		sbc.tableName = sbcDefaultTable
	default:
		sbc.tableName = n
	}
}

func (sbc *storageBucketCredential) Subtype() Subtype {
	return Subtype(sbc.Type)
}

// SBCSubtype converts the storage bucket credential to the concrete subtype
func (sbc *storageBucketCredential) SBCSubtype(ctx context.Context) (StorageBucketCredential, error) {
	const op = "storagebucketcredential.storageBucketCredential.sbcSubtype"

	alloc, ok := SubtypeRegistry.AllocFunc(sbc.Subtype())
	if !ok {
		return nil, errors.Wrap(ctx,
			errSBCSubtypeNotFound,
			op,
			errors.WithCode(errors.InvalidParameter),
			errors.WithMsg(fmt.Sprintf("%s is an unknown sbc subtype of %s", sbc.PrivateId, sbc.Type)),
		)
	}

	aSBC := alloc()
	aSBC.SetPrivateId(sbc.PrivateId)
	aSBC.SetStorageBucketId(sbc.StorageBucketId)
	if sbc.Subtype() == ManagedSecretSubtype {
		secrets := &structpb.Struct{}
		if err := proto.Unmarshal(sbc.Secrets, secrets); err != nil {
			return nil, err
		}
		aSBC.SetSecrets(sbc.Secrets)
		aSBC.SetCtSecrets(sbc.CtSecrets)
	}
	return aSBC, nil
}
