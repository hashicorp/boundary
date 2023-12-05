// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
)

// List lists up to page size credential stores, filtering out entries that
// do not pass the filter item function. It will automatically request
// more credential stores from the database, at page size chunks, to fill the page.
// It returns a new list token used to continue pagination or refresh items.
// Credential stores are ordered by create time descending (most recently created first).
func (s *StoreService) List(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[Store],
	projectIds []string,
) (*pagination.ListResponse[Store], error) {
	const op = "credential.(*StoreService).List"

	switch {
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case projectIds == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing project ids")
	}

	listItemsFn := func(ctx context.Context, lastPageItem Store, limit int) ([]Store, time.Time, error) {
		return s.list(ctx, projectIds, lastPageItem, limit)
	}

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, s.estimatedCount)
}
