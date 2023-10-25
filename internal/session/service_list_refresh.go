// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// ListRefresh lists sessions according to the page size and refresh token,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned sessions.
func ListRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[*Session],
	tok *refreshtoken.Token,
	repo *Repository,
	includeTerminated bool,
) (*pagination.ListResponse[*Session], error) {
	const op = "session.ListRefresh"

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
	if repo == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing repo")
	}

	listItemsFn := func(ctx context.Context, tok *refreshtoken.Token, lastPageItem *Session, limit int) ([]*Session, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts,
				WithStartPageAfterItem(lastPageItem),
			)
		} else {
			opts = append(opts,
				WithStartPageAfterItem(tok.LastItem()),
			)
		}
		if includeTerminated {
			opts = append(opts,
				WithTerminated(includeTerminated),
			)
		}
		return repo.ListSessions(ctx, opts...)
	}

	return pagination.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedCount, repo.listDeletedIds, tok)
}
