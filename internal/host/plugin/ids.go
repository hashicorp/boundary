// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/types/resource"
)

func init() {
	globals.RegisterPrefixToResourceInfo(globals.PluginHostCatalogPrefix, resource.HostCatalog, host.Domain, Subtype)
	globals.RegisterPrefixToResourceInfo(globals.PluginHostCatalogPreviousPrefix, resource.HostCatalog, host.Domain, Subtype)
	globals.RegisterPrefixToResourceInfo(globals.PluginHostSetPrefix, resource.HostSet, host.Domain, Subtype)
	globals.RegisterPrefixToResourceInfo(globals.PluginHostSetPreviousPrefix, resource.HostSet, host.Domain, Subtype)
	globals.RegisterPrefixToResourceInfo(globals.PluginHostPrefix, resource.Host, host.Domain, Subtype)
	globals.RegisterPrefixToResourceInfo(globals.PluginHostPreviousPrefix, resource.Host, host.Domain, Subtype)
}

// PublicId prefixes for the resources in the plugin package.
const (
	Subtype = globals.Subtype("plugin")
)

func newHostCatalogId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.PluginHostCatalogPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "plugin.newHostCatalogId")
	}
	return id, nil
}

func newHostSetId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.PluginHostSetPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "plugin.newHostSetId")
	}
	return id, nil
}

func newHostId(ctx context.Context, catalogId, externalId string) (string, error) {
	const op = "plugin.newHostId"
	if catalogId == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing catalog id")
	}
	if externalId == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing external id")
	}
	id, err := db.NewPublicId(ctx, globals.PluginHostPrefix, db.WithPrngValues([]string{catalogId, externalId}))
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}
