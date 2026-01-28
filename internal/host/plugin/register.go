// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"

	"github.com/hashicorp/boundary/internal/host"
)

func init() {
	host.RegisterCatalogSubtype("plugin", &hostHooks{})
}

type hostHooks struct{}

// NewCatalog creates a new plugin host catalog from the result
func (hostHooks) NewCatalog(ctx context.Context, result *host.CatalogListQueryResult) (host.Catalog, error) {
	s := allocHostCatalog()
	s.PublicId = result.PublicId
	s.ProjectId = result.ProjectId
	s.CreateTime = result.CreateTime
	s.UpdateTime = result.UpdateTime
	s.Name = result.Name
	s.Description = result.Description
	s.ProjectId = result.ProjectId
	s.Version = result.Version
	s.PluginId = result.PluginId
	s.SecretsHmac = result.SecretsHmac
	s.Attributes = result.Attributes
	s.WorkerFilter = result.WorkerFilter

	return s, nil
}
