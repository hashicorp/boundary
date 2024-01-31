// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package aliases

import (
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
)

var (
	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = action.NewActionSet(
		action.NoOp,
		action.Read,
		action.Update,
		action.Delete,
	)

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.NewActionSet(
		action.Create,
		action.List,
	)
)

func init() {
	// TODO: refactor to remove idActionsMap and CollectionActions package variables
	action.RegisterResource(resource.Alias, action.Union(IdActions), CollectionActions)
}
