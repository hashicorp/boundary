// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

// PublicId prefixes for the resources in the plugin package.
const (
	PluginPrefix = "pl"
)

func newPluginId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, PluginPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "plugin.newPluginId")
	}
	return id, nil
}
