// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	stderrors "errors"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/util"
)

type RefreshService struct {
	repo *Repository
	// the amount of time that should have passed since the last refresh for a
	// call to RefreshForSearch will cause a refresh request to be sent to a
	// boundary controller.
	maxSearchStaleness time.Duration
	// the amount of time that RefreshForSearch should run before it times out.
	maxSearchRefreshTimeout time.Duration
}

func NewRefreshService(ctx context.Context, r *Repository, maxSearchStaleness, maxSearchRefreshTimeout time.Duration) (*RefreshService, error) {
	const op = "cache.NewRefreshService"
	switch {
	case util.IsNil(r):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "repository is nil")
	case maxSearchStaleness < 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "max search staleness is negative")
	}
	return &RefreshService{
		repo:                    r,
		maxSearchStaleness:      maxSearchStaleness,
		maxSearchRefreshTimeout: maxSearchRefreshTimeout,
	}, nil
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
				case err != nil && (api.ErrUnauthorized.Is(err) || api.ErrNotFound.Is(err)):
					if err := r.repo.deleteKeyringToken(ctx, *kt); err != nil {
						return nil, errors.Wrap(ctx, err, op)
					}
					event.WriteSysEvent(ctx, op, "Removed auth token from cache because it was not found to be valid in boundary", "auth token id", at.Id)
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
				case err != nil && (api.ErrUnauthorized.Is(err) || api.ErrNotFound.Is(err)):
					r.repo.idToKeyringlessAuthToken.Delete(t.Id)
					event.WriteSysEvent(ctx, op, "Removed auth token from cache because it was not found to be valid in boundary", "auth token id", at.Id)
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

// cacheSupportedUsers filters the provided users down to the set of users who
// can have their resources refreshed using refresh tokens.  A user is returned
// by this method if it does not have a sentinel value refresh token marking it
// as unsupported for caching.
func (r *RefreshService) cacheSupportedUsers(ctx context.Context, in []*user) ([]*user, error) {
	const op = "cache.(RefreshService).cacheSupportedUsers"
	var ret []*user
	for _, u := range in {
		cs, err := r.repo.cacheSupportState(ctx, u)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if cs.supported != NotSupportedCacheSupport {
			ret = append(ret, u)
		}
	}
	return ret, nil
}

// RefreshForSearch refreshes a specific resource type owned by the user associated
// with the provided auth token id, if it hasn't been refreshed in a certain
// amount of time. If the resources has been updated recently, or if it is known
// that the user's boundary instance doesn't support partial refreshing, this
// method returns without any requests to the boundary controller.
// While the criteria of whether the user will refresh or not is almost the same
// as the criteria used in Refresh, RefreshForSearch will not refresh any
// data if there is not a refresh token stored for the resource. It
// might make sense to change this in the future, but the reasoning used is
// that we should not be making an initial load of all resources while blocking
// a search query, in case we have not yet even attempted to load the resources
// for this user yet.
// Note: Currently, if the context timesout we stop refreshing completely and
// return to the caller.  A possible enhancement in the future would be to return
// when the context is Done, but allow the refresh to proceed in the background.
func (r *RefreshService) RefreshForSearch(ctx context.Context, authTokenid string, resourceType SearchableResource, opt ...Option) error {
	const op = "cache.(RefreshService).RefreshForSearch"
	if r.maxSearchRefreshTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.maxSearchRefreshTimeout)
		defer cancel()
	}
	at, err := r.repo.LookupToken(ctx, authTokenid)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if at == nil {
		return errors.New(ctx, errors.NotFound, op, "auth token not found")
	}
	u, err := r.repo.lookupUser(ctx, at.UserId)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if u == nil {
		return errors.New(ctx, errors.NotFound, op, "user not found")
	}
	us, err := r.cacheSupportedUsers(ctx, []*user{u})
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	switch len(us) {
	case 0:
		// The provided user is not refreshable, so do not refresh.
		return nil
	case 1:
		u = us[0]
	default:
		return errors.New(ctx, errors.Internal, op, "unexpected number of refreshable users")
	}

	tokens, err := r.cleanAndPickAuthTokens(ctx, u)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	switch resourceType {
	case Targets:
		rtv, err := r.repo.lookupRefreshToken(ctx, u, targetResourceType)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if opts.withIgnoreSearchStaleness || rtv != nil && time.Since(rtv.UpdateTime) > r.maxSearchStaleness {
			if err := r.repo.refreshTargets(ctx, u, tokens, opt...); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}
	case Sessions:
		rtv, err := r.repo.lookupRefreshToken(ctx, u, sessionResourceType)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if opts.withIgnoreSearchStaleness || rtv != nil && time.Since(rtv.UpdateTime) > r.maxSearchStaleness {
			if err := r.repo.refreshSessions(ctx, u, tokens, opt...); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}
	default:
		return errors.New(ctx, errors.InvalidParameter, op, "unrecognized resource type")
	}

	return nil
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

	us, err = r.cacheSupportedUsers(ctx, us)
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
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for user id %s", u.Id))))
		}
		if err := r.repo.refreshSessions(ctx, u, tokens, opt...); err != nil {
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for user id %s", u.Id))))
		}

	}
	return retErr
}

// RecheckCachingSupport is used for users of boundary instances which do not
// support refresh tokens. For these users a call to RecheckCachingSupport
// retrieves resources for that user to see if the controller now returns a
// refresh token. Users who do not have any resources nor refresh tokens still
// are Refreshed. If caching moves from unsupported to supported this method
// will cache the results automatically.
func (r *RefreshService) RecheckCachingSupport(ctx context.Context, opt ...Option) error {
	const op = "cache.(RefreshService).RecheckCachingSupport"
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

	removeUsers, err := r.cacheSupportedUsers(ctx, us)
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

		if err := r.repo.checkCachingTargets(ctx, u, tokens, opt...); err != nil {
			if err == ErrRefreshNotSupported {
				// This is expected so no need to propogate the error up
				continue
			}
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for user id %s", u.Id))))
		}
		if err := r.repo.checkCachingSessions(ctx, u, tokens, opt...); err != nil {
			if err == ErrRefreshNotSupported {
				// This is expected so no need to propogate the error up
				continue
			}
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for user id %s", u.Id))))
		}

	}
	return retErr
}
