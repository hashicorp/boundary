// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/storage/plugin/store"
	"github.com/hashicorp/boundary/internal/types/resource"
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

// GetResourceType implements the boundary.Resource interface.
func (s *StorageBucket) GetResourceType() resource.Type {
	return resource.StorageBucket
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

type storageBucketAgg struct {
	PublicId                  string `gorm:"primary_key"`
	ScopeId                   string
	Name                      string
	Description               string
	CreateTime                *timestamp.Timestamp
	UpdateTime                *timestamp.Timestamp
	Version                   uint32
	PluginId                  string
	BucketName                string
	BucketPrefix              string
	WorkerFilter              string
	Attributes                []byte
	SecretsEncrypted          []byte
	SecretsHmac               []byte
	KeyId                     string
	StorageBucketCredentialId string
}

// TableName returns the table name for gorm
func (sba *storageBucketAgg) TableName() string {
	return "storage_plugin_storage_bucket_with_secret"
}

func (sba *storageBucketAgg) GetPublicId() string {
	return sba.PublicId
}

func (sba *storageBucketAgg) toStorageBucketAndSBC() (*StorageBucket, error) {
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
	sb.StorageBucketCredentialId = sba.StorageBucketCredentialId

	return sb, nil
}

type deletedStorageBucket struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedStorageBucket) TableName() string {
	return "storage_plugin_storage_bucket_deleted"
}
