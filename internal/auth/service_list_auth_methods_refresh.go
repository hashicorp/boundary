// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"slices"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// ListAuthMethodsRefresh lists auth methods according to the page size
// and refresh token, filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the old one, the grants hash,
// and the returned auth methods.
func (s *AuthMethodService) ListAuthMethodsRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[AuthMethod],
	tok *refreshtoken.Token,
	scopeIds []string,
	withUnauthenticatedUser bool,
) (*pagination.ListResponse[AuthMethod], error) {
	const op = "auth.ListAuthMethodsRefresh"

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
	if len(scopeIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope ids")
	}

	listItemsFn := func(ctx context.Context, tok *refreshtoken.Token, lastPageItem AuthMethod, limit int) ([]AuthMethod, error) {
		opts := []Option{
			WithLimit(ctx, limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(ctx, lastPageItem))
		} else {
			opts = append(opts, WithStartPageAfterItem(ctx, tok.LastItem()))
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
	listDeletedIdsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
		// Request and combine deleted ids from the DB for ldap, oidc, and passwords.
		// This statement here is the reason we need a struct for this. We need all the
		// deleted auth methods to be collated in a single transaction with a single
		// transaction timestamp. This requires access to a db Reader, which isn't available
		// to the handlers and can't be passed into this method. Therefore, a struct,
		// constructed in the controller, is necessary.
		var deletedIds []string
		var transactionTimestamp time.Time
		if _, err := s.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
			deletedLdapIds, err := s.ldapRepo.ListDeletedAuthMethodIds(ctx, tok.UpdatedTime, WithReaderWriter(ctx, r, w))
			if err != nil {
				return err
			}
			deletedOidcIds, err := s.oidcRepo.ListDeletedAuthMethodIds(ctx, tok.UpdatedTime, WithReaderWriter(ctx, r, w))
			if err != nil {
				return err
			}
			deletedPwIds, err := s.passwordRepo.ListDeletedAuthMethodIds(ctx, tok.UpdatedTime, WithReaderWriter(ctx, r, w))
			if err != nil {
				return err
			}
			transactionTimestamp, err = r.Now(ctx)
			if err != nil {
				return err
			}
			deletedIds = append(deletedLdapIds, append(deletedOidcIds, deletedPwIds...)...)
			return nil
		}); err != nil {
			return nil, time.Time{}, err
		}
		return deletedIds, transactionTimestamp, nil
	}
	return pagination.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedCountFn, listDeletedIdsFn, tok)
}
