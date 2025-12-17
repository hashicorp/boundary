// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/util"
)

// LibraryService defines the interface expected
// to list, estimate the count of and list deleted items of
// credential libraries.
type LibraryService interface {
	EstimatedLibraryCount(context.Context) (int, error)
	ListDeletedLibraryIds(context.Context, time.Time) ([]string, time.Time, error)
	ListLibraries(context.Context, string, ...Option) ([]Library, time.Time, error)
	ListLibrariesRefresh(context.Context, string, time.Time, ...Option) ([]Library, time.Time, error)
}

// ListLibraries lists up to page size credential libraries, filtering out entries that
// do not pass the filter item function. It will automatically request
// more credential libraries from the database, at page size chunks, to fill the page.
// It returns a new list token used to continue pagination or refresh items.
// Credential libraries are ordered by create time descending (most recently created first).
func ListLibraries(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[Library],
	service LibraryService,
	credentialStoreId string,
) (*pagination.ListResponse[Library], error) {
	const op = "credential.ListLibraries"

	switch {
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case util.IsNil(service):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing service")
	case credentialStoreId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing credential store ID")
	}

	listItemsFn := func(ctx context.Context, lastPageItem Library, limit int) ([]Library, time.Time, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		}
		return service.ListLibraries(ctx, credentialStoreId, opts...)
	}

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, service.EstimatedLibraryCount)
}
