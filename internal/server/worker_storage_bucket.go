// Copyright (c) HashiCorp, Inc.
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

type UpdateStorageBucketCredential struct {
	StorageBucketId           string `gorm:"primary_key"`
	Version                   int32
	CtSecrets                 []byte
	KeyId                     string
	StorageBucketScopeId      string
	StorageBucketName         string
	StorageBucketDescription  string
	StorageBucketBucketName   string
	StorageBucketBucketPrefix string
	StorageBucketWorkerFilter string
	StorageBucketAttributes   []byte
	PluginId                  string
	PluginName                string
	PluginDescription         string
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
		Id:           usb.StorageBucketId,
		ScopeId:      usb.StorageBucketScopeId,
		PluginId:     usb.PluginId,
		Name:         wrapperspb.String(usb.StorageBucketBucketName),
		Description:  wrapperspb.String(usb.StorageBucketDescription),
		BucketName:   usb.StorageBucketBucketName,
		BucketPrefix: usb.StorageBucketBucketPrefix,
		WorkerFilter: usb.StorageBucketWorkerFilter,
		Plugin: &plugins.PluginInfo{
			Id:          usb.PluginId,
			Name:        usb.PluginName,
			Description: usb.PluginDescription,
		},
	}
	if usb.StorageBucketAttributes != nil {
		attrs := &structpb.Struct{}
		if err := proto.Unmarshal(usb.StorageBucketAttributes, attrs); err != nil {
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
		sbc.SetStorageBucketId(usb.StorageBucketId)
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
