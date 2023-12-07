// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package plugin

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

const StorageDomain = "storage"

func init() {
	if err := subtypes.Register(StorageDomain, Subtype, globals.PluginStorageBucketPrefix); err != nil {
		panic(err)
	}
}

const (
	Subtype = subtypes.Subtype("plugin")
)

func newStorageBucketId(ctx context.Context) (string, error) {
	const op = "plugin.newStorageBucketId"
	id, err := db.NewPublicId(ctx, globals.PluginStorageBucketPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}
