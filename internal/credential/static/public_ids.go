// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
)

func init() {
	globals.RegisterPrefixToResourceInfo(globals.StaticCredentialStorePrefix, resource.CredentialStore, credential.Domain, Subtype)
	globals.RegisterPrefixToResourceInfo(globals.StaticCredentialStorePreviousPrefix, resource.CredentialStore, credential.Domain, Subtype)
}

// PublicId prefixes for the resources in the static package.
const (
	Subtype = globals.Subtype("static")
)

func newCredentialStoreId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.StaticCredentialStorePrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "static.newCredentialStoreId")
	}
	return id, nil
}
