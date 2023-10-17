// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// This function is a callback passed down from the application service layer
// used to filter out protobuf credentials that don't match any user-supplied filter.
type ListFilterCredentialFunc func(Static) (bool, error)

// Repository defines the interface expected
// to get the total number of credentials and deleted ids.
type Repository interface {
	EstimatedCredentialCount(context.Context) (int, error)
	ListDeletedCredentialIds(context.Context, time.Time) ([]string, time.Time, error)
	ListCredentials(context.Context, string, ...Option) ([]Static, error)
}

// List lists credentials according to the page size,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned credentials.
func List(
	ctx context.Context,
	credentialStoreId string,
	repo Repository,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListFilterCredentialFunc,
) (*ListCredentialsResponse, error) {
	const op = "credential.ListCredentials"

	limit := pageSize + 1
	opts := []Option{
		WithLimit(limit),
	}

	credentials := make([]Static, 0, limit)
dbLoop:
	for {
		// Request another page from the DB until we fill the final items
		page, err := repo.ListCredentials(ctx, credentialStoreId, opts...)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		for _, item := range page {
			ok, err := filterItemFn(item)
			if err != nil {
				return nil, err
			}
			if ok {
				credentials = append(credentials, item)
				// If we filled the items after filtering,
				// we're done.
				if len(credentials) == cap(credentials) {
					break dbLoop
				}
			}
		}
		// If the current page was shorter than the limit, stop iterating
		if len(page) < limit {
			break dbLoop
		}

		opts = []Option{
			WithLimit(limit),
			WithStartPageAfterItem(page[len(page)-1].GetPublicId(), page[len(page)-1].GetUpdateTime().AsTime()),
		}
	}
	// If we couldn't fill the items, it was a complete listing.
	completeListing := len(credentials) < cap(credentials)
	totalItems := len(credentials)
	if !completeListing {
		// Items is of size pageSize+1, so
		// truncate if it was filled.
		credentials = credentials[:pageSize]
		// If this was not a complete listing, get an estimate
		// of the total items from the DB.
		var err error
		totalItems, err = repo.EstimatedCredentialCount(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	resp := &ListCredentialsResponse{
		Items:               credentials,
		EstimatedTotalItems: totalItems,
		CompleteListing:     completeListing,
	}

	if len(credentials) > 0 {
		resp.RefreshToken = refreshtoken.FromResource(credentials[len(credentials)-1], grantsHash)
	}

	return resp, nil
}
