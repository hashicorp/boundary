// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package pagination

import (
	"context"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/util"
)

// Item defines a subset of a boundary.Resource that can
// be used as an input to a DB operation for the purposes
// of pagination and sorting.
type Item interface {
	GetPublicId() string
	GetUpdateTime() *timestamp.Timestamp
	GetResourceType() resource.Type
}

// ValidateItem validates an item.
func ValidateItem(ctx context.Context, item Item) error {
	const op = "pagination.ValidateItem"
	if util.IsNil(item) {
		return errors.New(ctx, errors.InvalidParameter, op, "nil item", errors.WithoutEvent())
	}
	if item.GetPublicId() == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing public id", errors.WithoutEvent())
	}
	if item.GetUpdateTime() == nil || item.GetUpdateTime().AsTime().IsZero() {
		return errors.New(ctx, errors.InvalidParameter, op, "missing update time", errors.WithoutEvent())
	}
	if item.GetResourceType() == resource.Unknown || item.GetResourceType() == resource.All {
		return errors.New(ctx, errors.InvalidParameter, op, "missing resource type", errors.WithoutEvent())
	}
	return nil
}
