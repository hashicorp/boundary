// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/storage/storagebucketcredential"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/plugins"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const UpsertWorkerStorageBucketJobName = "upsert_worker_storage_bucket"

type WorkerStorageBucket struct {
	WorkerId string
	Buckets  []*storagebuckets.StorageBucket
}

type UpdateStorageBucketCredential struct {
	PublicId                  string `gorm:"primary_key"`
	StorageBucketCredentialId string
	ScopeId                   string
	Name                      string
	Description               string
	BucketName                string
	BucketPrefix              string
	WorkerFilter              string
	Attributes                []byte
	PluginId                  string
	PluginName                string
	PluginDescription         string
	KeyId                     string
	CtSecrets                 []byte
	Version                   uint32
}

// TableName returns the table name for gorm
func (owsbc *UpdateStorageBucketCredential) TableName() string {
	return "update_worker_storage_bucket_credential"
}

// ToPluginStorageBucket re-formats an storage bucket into the proto used for storage plugin requests
func ToPluginStorageBucket(ctx context.Context, usb *UpdateStorageBucketCredential, wrapper wrapping.Wrapper) (*storagebuckets.StorageBucket, error) {
	const op = "server.ToPluginStorageBucket"
	switch {
	case usb == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil update storage bucket credential")
	}

	sb := &storagebuckets.StorageBucket{
		Id:                        usb.PublicId,
		StorageBucketCredentialId: usb.StorageBucketCredentialId,
		ScopeId:                   usb.ScopeId,
		PluginId:                  usb.PluginId,
		Description:               wrapperspb.String(usb.Description),
		BucketName:                usb.BucketName,
		BucketPrefix:              usb.BucketPrefix,
		WorkerFilter:              usb.WorkerFilter,
		Plugin: &plugins.PluginInfo{
			Id:          usb.PluginId,
			Name:        usb.PluginName,
			Description: usb.PluginDescription,
		},
		Version: usb.Version,
	}
	if usb.Attributes != nil {
		attrs := &structpb.Struct{}
		if err := proto.Unmarshal(usb.Attributes, attrs); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to unmarshal attributes"))
		}
		sb.Attributes = attrs
	}
	if usb.CtSecrets != nil {
		allocFn, ok := storagebucketcredential.SubtypeRegistry.AllocFunc(storagebucketcredential.ManagedSecretSubtype)
		if !ok {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "unable to allocate storage bucket credential")
		}
		sbc := allocFn()

		sbc.SetKeyId(usb.KeyId)
		sbc.SetStorageBucketId(usb.PublicId)
		sbc.SetCtSecrets(usb.CtSecrets)

		if sbc.Decrypt(ctx, wrapper) != nil {
			return nil, errors.New(ctx, errors.Decrypt, op, "error decrypting secrets")
		}

		secrets := &structpb.Struct{}
		if err := proto.Unmarshal(sbc.GetSecrets(), secrets); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to unmarshal secrets"))
		}

		sb.Secrets = secrets
	}
	return sb, nil
}
