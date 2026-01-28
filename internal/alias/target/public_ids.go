// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/alias"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
)

func init() {
	globals.RegisterPrefixToResourceInfo(globals.TargetAliasPrefix, resource.Alias, alias.Domain, Subtype)
}

// PublicId prefixes for the resources in the static package.
const (
	Subtype = globals.Subtype("target")
)

// newAliasId creates a new id for a target alias.
func newAliasId(ctx context.Context) (string, error) {
	const op = "target.newAliasId"
	id, err := db.NewPublicId(ctx, globals.TargetAliasPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}
