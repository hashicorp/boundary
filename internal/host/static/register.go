// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"

	"github.com/hashicorp/boundary/internal/host"
)

func init() {
	host.RegisterCatalogSubtype("static", &hostHooks{})
}

type hostHooks struct{}

// NewCatalog creates a new static host catalog from the result
func (hostHooks) NewCatalog(ctx context.Context, result *host.CatalogListQueryResult) (host.Catalog, error) {
	s := allocCatalog()
	s.PublicId = result.PublicId
	s.ProjectId = result.ProjectId
	s.CreateTime = result.CreateTime
	s.UpdateTime = result.UpdateTime
	s.Name = result.Name
	s.Description = result.Description
	s.ProjectId = result.ProjectId
	s.Version = result.Version

	return s, nil
}
