// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

// PublicId prefixes for the resources in the plugin package.
const (
	PluginPrefix = "pl"
)

func newPluginId() (string, error) {
	id, err := db.NewPublicId(PluginPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, "plugin.newPluginId")
	}
	return id, nil
}
