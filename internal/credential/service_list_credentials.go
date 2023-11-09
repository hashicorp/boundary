// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
)

// CredentialListingService defines the interface expected
// to get the total number of credentials and deleted ids.
type CredentialListingService interface {
	EstimatedCredentialCount(context.Context) (int, error)
	ListDeletedCredentialIds(context.Context, time.Time) ([]string, time.Time, error)
	ListCredentials(context.Context, string, ...Option) ([]Static, error)
}

// List lists credentials according to the page size,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned credentials.
func List(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[Static],
	service CredentialListingService,
	credentialStoreId string,
) (*pagination.ListResponse[Static], error) {
	const op = "credential.ListRefresh"

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

	listItemsFn := func(ctx context.Context, lastPageItem Static, limit int) ([]Static, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		}
		return service.ListCredentials(ctx, credentialStoreId, opts...)
	}

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, service.EstimatedCredentialCount)
}
