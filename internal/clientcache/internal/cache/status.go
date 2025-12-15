// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

// RefreshTokenStatus is the status of a resource token
type RefreshTokenStatus struct {
	Age      time.Duration
	LastUsed time.Duration
}

type ErrorStatus struct {
	Error        string
	LastReturned time.Duration
}

// ResourceStatus contains the status of a specific resource type contained in
// the cache for a specific user.
type ResourceStatus struct {
	Name         string
	Count        int
	LastError    *ErrorStatus
	RefreshToken *RefreshTokenStatus
}

// AuthTokenStatus contains the status of an auth token tracked in the cache for
// a specific user.
type AuthTokenStatus struct {
	Id                    string
	KeyringReferences     int
	KeyringlessReferences int
}

type BoundaryStatus struct {
	// The boundary address for this user
	Address          string
	CachingSupported CacheSupport
	LastSupportCheck time.Duration
}

// UserStatus contains the status of a specific user tracked by the cache
type UserStatus struct {
	// The Id of the user this status is for
	Id             string
	BoundaryStatus BoundaryStatus
	// The auth tokens used by this user to authenticate with the boundary instance
	AuthTokens []AuthTokenStatus
	// The resources tracked by the cache for this user
	Resources []ResourceStatus
}

// Status contains the status of the cache.
type Status struct {
	Users []UserStatus
}

// StatusService provides a service that gives status information about the
// cache.
type StatusService struct {
	repo *Repository
}

// NewStatusService returns a new StatusService
func NewStatusService(ctx context.Context, r *Repository) (*StatusService, error) {
	const op = "cache.NewStatusService"
	switch {
	case util.IsNil(r):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "repository is nil")
	}
	return &StatusService{repo: r}, nil
}

// Status returns the Status of the cache repository
func (s *StatusService) Status(ctx context.Context) (*Status, error) {
	const op = "cache.(StatusService).Status"
	ret := &Status{}
	users, err := s.repo.listUsers(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	for _, u := range users {
		us := UserStatus{
			Id: u.Id,
		}

		cacheSupported, err := s.repo.cacheSupportState(ctx, u)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		us.BoundaryStatus = BoundaryStatus{
			Address:          u.Address,
			CachingSupported: cacheSupported.supported,
		}
		if cacheSupported.lastChecked != nil && !cacheSupported.lastChecked.IsZero() {
			us.BoundaryStatus.LastSupportCheck = time.Since(*cacheSupported.lastChecked)
		}

		toks, err := s.repo.listTokens(ctx, u)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		for _, t := range toks {
			ts := &AuthTokenStatus{
				Id: t.Id,
			}
			kt, err := s.repo.listKeyringTokens(ctx, t)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			ts.KeyringReferences = len(kt)
			if _, ok := s.repo.idToKeyringlessAuthToken.Load(t.Id); ok {
				ts.KeyringlessReferences = 1
			}
			us.AuthTokens = append(us.AuthTokens, *ts)
		}

		for _, rt := range []resourceType{resolvableAliasResourceType, targetResourceType, sessionResourceType} {
			ts, err := s.resourceStatus(ctx, u, rt)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			us.Resources = append(us.Resources, *ts)
		}

		ret.Users = append(ret.Users, us)
	}
	return ret, nil
}

func (s *StatusService) resourceStatus(ctx context.Context, u *user, rt resourceType) (*ResourceStatus, error) {
	const op = "cache.(StatusService).resourceStatus"
	switch {
	case u == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user id is empty")
	case !rt.valid():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "resource type is invalid")
	}
	ret := ResourceStatus{
		Name: string(rt),
	}

	refTok, err := s.refreshTokenStatus(ctx, u, rt)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	ret.RefreshToken = refTok

	errStatus, err := s.errorStatus(ctx, u, rt)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	ret.LastError = errStatus

	err = func() error {
		query := fmt.Sprintf("select count(*) from %s where fk_user_id = @user_id", rt.ColumnName())
		r, err := s.repo.rw.Query(ctx, query, []any{sql.Named("user_id", u.Id)})
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		defer r.Close()
		r.Next()
		var count int
		if err := s.repo.rw.ScanRows(ctx, r, &count); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		ret.Count = count
		return nil
	}()
	if err != nil {
		return nil, err
	}

	return &ret, nil
}

func (s *StatusService) errorStatus(ctx context.Context, u *user, rt resourceType) (*ErrorStatus, error) {
	const op = "cache.(StatusService).errorStatus"
	switch {
	case u == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user id is empty")
	case !rt.valid():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "resource type is invalid")
	}
	apiErr, err := s.repo.lookupError(ctx, u, rt)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if apiErr == nil {
		return nil, nil
	}
	return &ErrorStatus{
		Error:        apiErr.Error,
		LastReturned: time.Since(apiErr.CreateTime),
	}, nil
}

func (s *StatusService) refreshTokenStatus(ctx context.Context, u *user, rt resourceType) (*RefreshTokenStatus, error) {
	const op = "cache.(StatusService).refreshTokenStatus"
	switch {
	case u == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user id is empty")
	case !rt.valid():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "resource type is invalid")
	}
	refTok := &refreshToken{
		UserId:       u.Id,
		ResourceType: rt,
	}
	if err := s.repo.rw.LookupById(ctx, refTok); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	if refTok.RefreshToken == sentinelNoRefreshToken {
		return nil, nil
	}

	ret := &RefreshTokenStatus{
		LastUsed: time.Since(refTok.UpdateTime),
		Age:      time.Since(refTok.CreateTime),
	}
	return ret, nil
}
