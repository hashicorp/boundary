// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/types/resource"
)

func init() {
	globals.RegisterPrefixToResourceInfo(globals.StaticHostCatalogPrefix, resource.HostCatalog, host.Domain, Subtype)
	globals.RegisterPrefixToResourceInfo(globals.StaticHostSetPrefix, resource.HostSet, host.Domain, Subtype)
	globals.RegisterPrefixToResourceInfo(globals.StaticHostPrefix, resource.Host, host.Domain, Subtype)
}

// PublicId prefixes for the resources in the static package.
const (
	Subtype = globals.Subtype("static")
)

func newHostCatalogId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.StaticHostCatalogPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "static.newHostCatalogId")
	}
	return id, nil
}

func newHostId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.StaticHostPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "static.newHostId")
	}
	return id, nil
}

func newHostSetId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.StaticHostSetPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "static.newHostSetId")
	}
	return id, nil
}
