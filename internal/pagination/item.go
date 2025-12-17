// Copyright IBM Corp. 2020, 2025
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
	GetCreateTime() *timestamp.Timestamp
	GetUpdateTime() *timestamp.Timestamp
	GetResourceType() resource.Type
}
