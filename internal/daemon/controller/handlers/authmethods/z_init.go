// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authmethods

import (
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"golang.org/x/exp/maps"
)

// init functions process in alphabetical order of filenames within a package.
// this needs to run last since it used the IdActions variable which gets
// modified in other init functions in this package.
func init() {
	// TODO: refactor to remove IdActions and CollectionActions package variables
	// Then this registration can happen in authmethod_service.go and we don't
	// need to worry about the order of init functions in a package.
	action.RegisterResource(resource.AuthMethod, action.Union(maps.Values(IdActions)...), CollectionActions)
}
