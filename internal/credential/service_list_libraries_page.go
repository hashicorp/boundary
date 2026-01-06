// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/util"
)

// ListLibrariesPage lists up to page size credential libraries, filtering out entries that
// do not pass the filter item function. It will automatically request
// more credential libraries from the database, at page size chunks, to fill the page.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// Credential libraries are ordered by create time descending (most recently created first).
func ListLibrariesPage(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[Library],
	tok *listtoken.Token,
	service LibraryService,
	credentialStoreId string,
) (*pagination.ListResponse[Library], error) {
	const op = "credential.ListLibrariesPage"

	switch {
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case tok == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing token")
	case util.IsNil(service):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing service")
	case credentialStoreId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing credential store id")
	case tok.ResourceType != resource.CredentialLibrary:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have an credential library resource type")
	}
	if _, ok := tok.Subtype.(*listtoken.PaginationToken); !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a pagination token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem Library, limit int) ([]Library, time.Time, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		} else {
			lastItem, err := tok.LastItem(ctx)
			if err != nil {
				return nil, time.Time{}, err
			}
			opts = append(opts, WithStartPageAfterItem(lastItem))
		}
		return service.ListLibraries(ctx, credentialStoreId, opts...)
	}

	return pagination.ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, service.EstimatedLibraryCount, tok)
}
