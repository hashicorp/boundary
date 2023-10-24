// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package authtoken

import (
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// ListResponse holds the information returned from List and ListRefresh
// TODO(johanbrandhorst): Move this into a shared struct when refactoring.
type ListResponse struct {
	Items               []*AuthToken
	DeletedIds          []string
	EstimatedTotalItems int
	CompleteListing     bool
	RefreshToken        *refreshtoken.Token
}
