// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/pagination"
)

// CredentialService defines the interface expected
// to get the total number of credentials and deleted ids.
type CredentialService interface {
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
	service CredentialService,
	credentialStoreId string,
) (*pagination.ListResponse2[Static], error) {
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
