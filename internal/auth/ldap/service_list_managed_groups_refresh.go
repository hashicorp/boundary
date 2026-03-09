// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// ListManagedGroupsRefresh lists ldap managed groups according to the page size
// and list token, filtering out entries that do not
// pass the filter item fn. It returns a new list token
// based on the old one, the grants hash, and the returned
// ldap managed groups.
func ListManagedGroupsRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[auth.ManagedGroup],
	tok *listtoken.Token,
	repo *Repository,
	authMethodId string,
) (*pagination.ListResponse[auth.ManagedGroup], error) {
	const op = "ldap.ListManagedGroupsRefresh"

	switch {
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case tok == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing token")
	case repo == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing repo")
	case authMethodId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method ID")
	case tok.ResourceType != resource.ManagedGroup:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a managed group resource type")
	}
	rt, ok := tok.Subtype.(*listtoken.StartRefreshToken)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a start-refresh token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem auth.ManagedGroup, limit int) ([]auth.ManagedGroup, time.Time, error) {
		opts := []Option{
			WithLimit(ctx, limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(ctx, lastPageItem))
		}
		// Add the database read timeout to managed group for any creations missed due to concurrent
		// transactions in the initial pagination phase.
		ldapManagedGroups, listTime, err := repo.ListManagedGroupsRefresh(ctx, authMethodId, rt.PreviousPhaseUpperBound.Add(-globals.RefreshReadLookbackDuration), opts...)
		if err != nil {
			return nil, time.Time{}, err
		}
		var managedGroups []auth.ManagedGroup
		for _, managedGroup := range ldapManagedGroups {
			managedGroups = append(managedGroups, managedGroup)
		}
		return managedGroups, listTime, nil
	}
	listDeletedIdsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
		// Add the database read timeout to managed group for any deletes missed due to concurrent
		// transactions in the original list pagination phase.
		return repo.listDeletedManagedGroupIds(ctx, since.Add(-globals.RefreshReadLookbackDuration))
	}

	return pagination.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedManagedGroupCount, listDeletedIdsFn, tok)
}
