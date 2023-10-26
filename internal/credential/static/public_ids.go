// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

func init() {
	if err := subtypes.Register(credential.Domain, globals.StaticSubtype, globals.StaticCredentialStorePrefix, globals.StaticCredentialStorePreviousPrefix); err != nil {
		panic(err)
	}
}

func newCredentialStoreId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.StaticCredentialStorePrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "static.newCredentialStoreId")
	}
	return id, nil
}
