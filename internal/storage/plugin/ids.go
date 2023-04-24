// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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

// PublicId prefixes for the resources in the plugin package.
const (
	Subtype = subtypes.Subtype("plugin")
)

func newStorageBucketId(ctx context.Context) (string, error) {
	const op = "plugin.newStorageBucketId"
	id, err := db.NewPublicId(globals.PluginStorageBucketPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}
