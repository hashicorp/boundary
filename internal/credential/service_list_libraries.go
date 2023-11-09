// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
)

// LibraryListingService defines the interface expected
// to list, estimate the count of and list deleted items of
// credential libraries.
type LibraryListingService interface {
	EstimatedCount(context.Context) (int, error)
	ListDeletedIds(context.Context, time.Time) ([]string, time.Time, error)
	List(context.Context, string, ...Option) ([]Library, error)
}

// List lists credential libraries according to the page size,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned libraries.
func ListLibraries(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[Library],
	service LibraryListingService,
	credentialStoreId string,
) (*pagination.ListResponse[Library], error) {
	const op = "credential.ListLibraries"

	if len(grantsHash) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	}
	if pageSize < 1 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	}
	if filterItemFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	}
	if service == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing service")
	}
	if credentialStoreId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing credential store ID")
	}

	listItemsFn := func(ctx context.Context, lastPageItem Library, limit int) ([]Library, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		}
		return service.List(ctx, credentialStoreId, opts...)
	}

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, service.EstimatedCount)
}
