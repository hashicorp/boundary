// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"slices"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/util"
)

// SubtypeStoreService defines the interface expected
// to gather information about credential stores.
type SubtypeStoreService interface {
	EstimatedStoreCount(context.Context) (int, error)
	ListDeletedStoreIds(context.Context, time.Time, ...Option) ([]string, error)
	ListCredentialStores(context.Context, []string, ...Option) ([]Store, error)
}

// StoreService coordinates calls across different subtype services
// to gather information about all credential stores.
type StoreService struct {
	services []SubtypeStoreService
	writer   db.Writer
}

// NewStoreService returns a new credential store service.
func NewStoreService(ctx context.Context, writer db.Writer, vaultService SubtypeStoreService, staticService SubtypeStoreService) (*StoreService, error) {
	const op = "credential.NewStoreService"
	switch {
	case util.IsNil(writer):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing DB writer")
	case util.IsNil(vaultService):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing vault service")
	case util.IsNil(staticService):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing static service")
	}
	return &StoreService{
		services: []SubtypeStoreService{vaultService, staticService},
		writer:   writer,
	}, nil
}

// List lists credential stores according to the page size,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned stores.
func (s *StoreService) List(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[Store],
	projectIds []string,
) (*pagination.ListResponse[Store], error) {
	const op = "credential.(*StoreService).List"

	if len(grantsHash) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	}
	if pageSize < 1 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	}
	if filterItemFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	}
	if projectIds == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing project ids")
	}

	listItemsFn := func(ctx context.Context, lastPageItem Store, limit int) ([]Store, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		}
		// Request another page from the DB until we fill the final items
		var page []Store
		for _, service := range s.services {
			servicePage, err := service.ListCredentialStores(ctx, projectIds, opts...)
			if err != nil {
				return nil, err
			}
			page = append(page, servicePage...)
		}
		slices.SortFunc(page, func(i, j Store) int {
			return i.GetUpdateTime().AsTime().Compare(j.GetUpdateTime().AsTime())
		})
		// Truncate slice to at most limit number of elements
		if len(page) > limit {
			page = page[:limit]
		}
		return page, nil
	}
	estimatedCountFn := func(ctx context.Context) (int, error) {
		var totalItems int
		for _, service := range s.services {
			numItems, err := service.EstimatedStoreCount(ctx)
			if err != nil {
				return 0, nil
			}
			totalItems += numItems
		}
		return totalItems, nil
	}

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedCountFn)
}
