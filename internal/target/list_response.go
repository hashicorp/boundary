// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// will likely eventually become a generic response and moved from target
type ListResponse struct {
	Items               []Target
	DeletedIds          []string
	EstimatedTotalItems int
	CompleteListing     bool
	RefreshToken        *refreshtoken.Token
}
