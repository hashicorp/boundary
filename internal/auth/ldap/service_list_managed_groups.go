// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
)

// ListManagedGroups lists up to page size ldap managed groups, filtering out entries that
// do not pass the filter item function. It will automatically request
// more managed groups from the database, at page size chunks, to fill the page.
// It returns a new list token used to continue pagination or refresh items.
// Managed groups are ordered by create time descending (most recently created first).
func ListManagedGroups(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[auth.ManagedGroup],
	repo *Repository,
	authMethodId string,
) (*pagination.ListResponse[auth.ManagedGroup], error) {
	const op = "ldap.ListManagedGroups"

	switch {
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case repo == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing repo")
	case authMethodId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method ID")
	}

	listItemsFn := func(ctx context.Context, lastPageItem auth.ManagedGroup, limit int) ([]auth.ManagedGroup, time.Time, error) {
		opts := []Option{
			WithLimit(ctx, limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(ctx, lastPageItem))
		}
		ldapManagedGroups, listTime, err := repo.ListManagedGroups(ctx, authMethodId, opts...)
		if err != nil {
			return nil, time.Time{}, err
		}
		var managedGroups []auth.ManagedGroup
		for _, managedGroup := range ldapManagedGroups {
			managedGroups = append(managedGroups, managedGroup)
		}
		return managedGroups, listTime, nil
	}

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedManagedGroupCount)
}
