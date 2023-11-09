// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

const StorageDomain = "storage"

func init() {
	globals.RegisterPrefixSubtype(globals.PluginStorageBucketPrefix, StorageDomain, Subtype)
}

const (
	Subtype = globals.Subtype("plugin")
)

func newStorageBucketId(ctx context.Context) (string, error) {
	const op = "plugin.newStorageBucketId"
	id, err := db.NewPublicId(ctx, globals.PluginStorageBucketPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}
