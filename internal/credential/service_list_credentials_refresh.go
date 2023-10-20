// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"

	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// ListRefresh lists credentials according to the page size and refresh token,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned credentials.
func ListRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[Static],
	tok *refreshtoken.Token,
	repo Repository,
	credentialStoreId string,
) (*pagination.ListResponse2[Static], error) {
	listItemsFn := func(ctx context.Context, tok *refreshtoken.Token, lastPageItem Static, limit int) ([]Static, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		} else {
			opts = append(opts, WithStartPageAfterItem(tok.LastItem()))
		}
		return repo.ListCredentials(ctx, credentialStoreId, opts...)
	}

	return pagination.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.EstimatedCredentialCount, repo.ListDeletedCredentialIds, tok)
}
