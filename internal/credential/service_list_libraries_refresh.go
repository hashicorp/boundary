// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// ListRefresh lists credential libraries according to the page size and refresh token,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned libraries.
func ListLibrariesRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[Library],
	tok *refreshtoken.Token,
	service LibraryListingService,
	credentialStoreId string,
) (*pagination.ListResponse[Library], error) {
	const op = "credential.ListLibrariesRefresh"

	if len(grantsHash) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	}
	if pageSize < 1 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	}
	if filterItemFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	}
	if tok == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing token")
	}
	if service == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing service")
	}
	if credentialStoreId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing credential store ID")
	}

	listItemsFn := func(ctx context.Context, tok *refreshtoken.Token, lastPageItem Library, limit int) ([]Library, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		} else {
			opts = append(opts, WithStartPageAfterItem(tok.LastItem()))
		}
		return service.List(ctx, credentialStoreId, opts...)
	}

	return pagination.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, service.EstimatedCount, service.ListDeletedIds, tok)
}
