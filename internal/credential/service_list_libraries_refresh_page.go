// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/util"
)

// ListRefreshPage lists up to page size credential libraries, filtering out entries that
// do not pass the filter item function. It will automatically request
// more credential libraries from the database, at page size chunks, to fill the page.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// Credential libraries are ordered by update time descending (most recently updated first).
// Credential libraries may contain items that were already returned during the initial
// pagination phase. It also returns a list of any credential libraries deleted since the
// last response.
func ListLibrariesRefreshPage(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[Library],
	tok *listtoken.Token,
	service LibraryService,
	credentialStoreId string,
) (*pagination.ListResponse[Library], error) {
	const op = "credential.ListLibrariesRefreshPage"

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
	rt, ok := tok.Subtype.(*listtoken.RefreshToken)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a refresh token component")
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
		// Add the database read timeout to account for any creations missed due to concurrent
		// transactions in the original list pagination phase.
		return service.ListLibrariesRefresh(ctx, credentialStoreId, rt.PhaseLowerBound.Add(-globals.RefreshReadLookbackDuration), opts...)
	}
	listDeletedIdsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
		// Add the database read timeout to account for any deletes missed due to concurrent
		// transactions in the original list pagination phase.
		return service.ListDeletedLibraryIds(ctx, since.Add(-globals.RefreshReadLookbackDuration))
	}

	return pagination.ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, service.EstimatedLibraryCount, listDeletedIdsFn, tok)
}
