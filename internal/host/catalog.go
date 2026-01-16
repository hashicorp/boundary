// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package host

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
)

// CatalogListQueryResult describes the result from the
// host catalog list query used to list all host
// catalog subtypes.
type CatalogListQueryResult struct {
	// PublicId is a surrogate key suitable for use in a public API.
	PublicId string `gorm:"primary_key"`
	// The Project Id of the owning project and must be set.
	ProjectId string
	// Optional name of the host catalog.
	Name string
	// Optional description of the host catalog.
	Description string
	// Create time of the host catalog.
	CreateTime *timestamp.Timestamp
	// Update time of the host catalog.
	UpdateTime *timestamp.Timestamp
	// Version of the host catalog.
	Version uint32
	// Optional plugin ID of the host catalog.
	PluginId string
	// Optional secrets HMAC of the host catalog.
	SecretsHmac []byte
	// Optional attributes of the host catalog.
	Attributes []byte
	// The subtype of the host catalog.
	Subtype string
	// Optional worker filter of a plugin-subtype host catalog.
	WorkerFilter string
}

func (s *CatalogListQueryResult) toCatalog(ctx context.Context) (Catalog, error) {
	const op = "host.(*CatalogListQueryResult).toCatalog"

	newFn, ok := subtypeRegistry.newFunc(globals.Subtype(s.Subtype))
	if !ok {
		return nil, errors.New(ctx,
			errors.InvalidParameter,
			op,
			fmt.Sprintf("%s is an unknown host catalog subtype of %s", s.PublicId, s.Subtype),
		)
	}

	return newFn(ctx, s)
}
