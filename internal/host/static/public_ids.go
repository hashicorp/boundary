// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

func init() {
	if err := subtypes.Register(host.Domain, Subtype, globals.StaticHostCatalogPrefix, globals.StaticHostSetPrefix, globals.StaticHostPrefix); err != nil {
		panic(err)
	}
}

// PublicId prefixes for the resources in the static package.
const (
	Subtype = subtypes.Subtype("static")
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
