// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"slices"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
)

func (s *AuthMethodService) ListAuthMethods(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[AuthMethod],
	scopeIds []string,
	withUnauthenticatedUser bool,
) (*pagination.ListResponse[AuthMethod], error) {
	const op = "auth.ListAuthMethods"

	if len(grantsHash) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	}
	if pageSize < 1 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	}
	if filterItemFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	}
	if len(scopeIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope ids")
	}

	listItemsFn := func(ctx context.Context, lastPageItem AuthMethod, limit int) ([]AuthMethod, error) {
		opts := []Option{
			WithLimit(ctx, limit),
		}
		if withUnauthenticatedUser {
			opts = append(opts, WithUnauthenticatedUser(ctx, withUnauthenticatedUser))
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		}
		ldapAuthMethods, err := s.ldapRepo.ListAuthMethods(ctx, scopeIds, opts...)
		if err != nil {
			return nil, err
		}
		oidcAuthMethods, err := s.oidcRepo.ListAuthMethods(ctx, scopeIds, opts...)
		if err != nil {
			return nil, err
		}
		pwAuthMethods, err := s.passwordRepo.ListAuthMethods(ctx, scopeIds, opts...)
		if err != nil {
			return nil, err
		}
		authMethods := append(ldapAuthMethods, append(oidcAuthMethods, pwAuthMethods...)...)
		slices.SortFunc(authMethods, func(i, j AuthMethod) int {
			return i.GetUpdateTime().AsTime().Compare(j.GetUpdateTime().AsTime())
		})
		if len(authMethods) > limit {
			authMethods = authMethods[:limit]
		}
		return authMethods, nil
	}
	estimatedCountFn := func(ctx context.Context) (int, error) {
		var err error
		totalLdapCount, err := s.ldapRepo.EstimatedAuthMethodCount(ctx)
		if err != nil {
			return 0, err
		}
		totalOidcCount, err := s.oidcRepo.EstimatedAuthMethodCount(ctx)
		if err != nil {
			return 0, err
		}
		totalPwCount, err := s.passwordRepo.EstimatedAuthMethodCount(ctx)
		if err != nil {
			return 0, err
		}
		return totalLdapCount + totalOidcCount + totalPwCount, nil
	}
	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedCountFn)
}
