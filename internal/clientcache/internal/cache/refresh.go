// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	stderrors "errors"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/util"
)

type RefreshService struct {
	repo *Repository
}

func NewRefreshService(ctx context.Context, r *Repository) (*RefreshService, error) {
	const op = "cache.NewRefreshService"
	switch {
	case util.IsNil(r):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "repository is nil")
	}
	return &RefreshService{repo: r}, nil
}

// cleanAndPickAuthTokens removes from the cache all auth tokens which are
// evicted from the cache or no longer stored in a keyring and returns the
// remaining ones.
// The returned auth tokens have not been validated against boundary
func (r *RefreshService) cleanAndPickAuthTokens(ctx context.Context, u *user) (map[AuthToken]string, error) {
	const op = "cache.(RefreshService).cleanAndPickAuthTokens"
	switch {
	case util.IsNil(u):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	}
	ret := make(map[AuthToken]string)

	tokens, err := r.repo.listTokens(ctx, u)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	for _, t := range tokens {
		keyringTokens, err := r.repo.listKeyringTokens(ctx, t)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("for user %v, auth token %q", u, t.Id))
		}
		for _, kt := range keyringTokens {
			at := r.repo.tokenKeyringFn(kt.KeyringType, kt.TokenName)
			switch {
			case at == nil, at.Id != kt.AuthTokenId, at.UserId != t.UserId:
				// delete the keyring token if the auth token in the keyring
				// has changed since it was stored in the cache.
				if err := r.repo.deleteKeyringToken(ctx, *kt); err != nil {
					return nil, errors.Wrap(ctx, err, op)
				}
			case at != nil:
				_, err := r.repo.tokenReadFromBoundaryFn(ctx, u.Address, at.Token)
				var apiErr *api.Error
				switch {
				case err != nil && api.ErrUnauthorized.Is(err):
					if err := r.repo.deleteKeyringToken(ctx, *kt); err != nil {
						return nil, errors.Wrap(ctx, err, op)
					}
					continue
				case err != nil && !errors.Is(err, apiErr):
					event.WriteError(ctx, op, err, event.WithInfoMsg("validating keyring stored token against boundary", "auth token id", at.Id))
					continue
				}
				ret[*t] = at.Token
			}
		}
		if atv, ok := r.repo.idToKeyringlessAuthToken.Load(t.Id); ok {
			if at, ok := atv.(*authtokens.AuthToken); ok {
				_, err := r.repo.tokenReadFromBoundaryFn(ctx, u.Address, at.Token)
				var apiErr *api.Error
				switch {
				case err != nil && api.ErrUnauthorized.Is(err):
					r.repo.idToKeyringlessAuthToken.Delete(t.Id)
					continue
				case err != nil && !errors.Is(err, apiErr):
					event.WriteError(ctx, op, err, event.WithInfoMsg("validating in memory stored token against boundary", "auth token id", at.Id))
					continue
				}

				ret[*t] = at.Token
			}
		}
	}
	return ret, nil
}

// refreshableUsers filters the provided users down to the set of users who can
// have their resources refreshed using refresh tokens.  A user is returned by
// this method if it has no resources in storage at all or it has a refresh
// token for any resource.
func (r *RefreshService) refreshableUsers(ctx context.Context, in []*user) ([]*user, error) {
	const op = "cache.(RefreshService).refreshableUsers"
	var ret []*user
	for _, u := range in {
		rt, err := r.repo.listRefreshTokens(ctx, u)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if len(rt) > 0 {
			ret = append(ret, u)
			continue
		}

		// If any resource exists for this user, since it doesn't have a refresh
		// token yet it is not refreshable.
		ts, err := r.repo.searchTargets(ctx, "true", nil, withUserId(u.Id))
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if len(ts) > 0 {
			continue
		}
		ss, err := r.repo.searchSessions(ctx, "true", nil, withUserId(u.Id))
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if len(ss) > 0 {
			continue
		}
		ret = append(ret, u)
	}
	return ret, nil
}

// Refresh iterates over all tokens in the cache that are for users who either
// have a refresh token or which do not have any resources in the cache yet. It
// then attempts to read those user's resources from boundary and updates the
// cache with the values retrieved there. Refresh accepts the options
// WithTargetRetrievalFunc and WithSessionRetrievalFunc which overwrites the
// default functions used to retrieve those resources from boundary.
func (r *RefreshService) Refresh(ctx context.Context, opt ...Option) error {
	const op = "cache.(RefreshService).Refresh"
	if err := r.repo.cleanExpiredOrOrphanedAuthTokens(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err := r.repo.syncKeyringlessTokensWithDb(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	us, err := r.repo.listUsers(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	us, err = r.refreshableUsers(ctx, us)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	var retErr error
	for _, u := range us {
		tokens, err := r.cleanAndPickAuthTokens(ctx, u)
		if err != nil {
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op))
			continue
		}

		if err := r.repo.refreshTargets(ctx, u, tokens, opt...); err != nil {
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op))
		}
		if err := r.repo.refreshSessions(ctx, u, tokens, opt...); err != nil {
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op))
		}

	}
	return retErr
}

// FullFetch is used for users of boundary instances which do not support
// refresh tokens. For these users a call to FullFetch retrieves all resources
// for that user and updates the database with the result. Users are identified
// as being in this group if they have at least one resource in the cache and
// do not have any refresh tokens. Users who do not have any resources nor
// refresh tokens are updated using Refresh.
func (r *RefreshService) FullFetch(ctx context.Context, opt ...Option) error {
	const op = "cache.(RefreshService).Refresh"
	if err := r.repo.cleanExpiredOrOrphanedAuthTokens(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err := r.repo.syncKeyringlessTokensWithDb(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	us, err := r.repo.listUsers(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	removeUsers, err := r.refreshableUsers(ctx, us)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	removedUserIds := make(map[string]struct{}, len(removeUsers))
	for _, ru := range removeUsers {
		removedUserIds[ru.Id] = struct{}{}
	}

	var retErr error
	for _, u := range us {
		if _, ok := removedUserIds[u.Id]; ok {
			continue
		}

		tokens, err := r.cleanAndPickAuthTokens(ctx, u)
		if err != nil {
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op))
			continue
		}

		if err := r.repo.fullFetchTargets(ctx, u, tokens, opt...); err != nil {
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op))
		}
		if err := r.repo.fullFetchSessions(ctx, u, tokens, opt...); err != nil {
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op))
		}

	}
	return retErr
}
