// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package pagination

import (
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// Item defines a subset of a boundary.Resource that can
// be used as an input to a DB operation for the purposes
// of pagination and sorting.
type Item interface {
	GetPublicId() string
	GetUpdateTime() *timestamp.Timestamp
	GetResourceType() resource.Type
}
