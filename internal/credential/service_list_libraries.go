// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/pagination"
)

// LibraryService defines the interface expected
// to list, estimate the count of and list deleted items of
// credential libraries.
type LibraryService interface {
	EstimatedCount(context.Context) (int, error)
	ListDeletedIds(context.Context, time.Time) ([]string, time.Time, error)
	List(context.Context, string, ...Option) ([]Library, error)
}

// This function is a callback passed down from the application service layer
// used to filter out protobuf libraries that don't match any user-supplied filter.
type ListFilterLibraryFunc func(Library) (bool, error)

// List lists credential libraries according to the page size,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned libraries.
func ListLibraries(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[Library],
	service LibraryService,
	credentialStoreId string,
) (*pagination.ListResponse2[Library], error) {
	listItemsFn := func(ctx context.Context, lastPageItem Library, limit int) ([]Library, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts,
				WithStartPageAfterItem(lastPageItem),
			)
		}
		return service.List(ctx, credentialStoreId, opts...)
	}

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, service.EstimatedCount)
}
