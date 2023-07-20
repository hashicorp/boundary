// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package static

import (
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

func newHostCatalogId() (string, error) {
	id, err := db.NewPublicId(globals.StaticHostCatalogPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, "static.newHostCatalogId")
	}
	return id, nil
}

func newHostId() (string, error) {
	id, err := db.NewPublicId(globals.StaticHostPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, "static.newHostId")
	}
	return id, nil
}

func newHostSetId() (string, error) {
	id, err := db.NewPublicId(globals.StaticHostSetPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, "static.newHostSetId")
	}
	return id, nil
}
