// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/hashicorp/boundary/internal/clientcache/internal/cache"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/boundary/version"
)

// RefreshTokenStatus is the status of a resource token
type RefreshTokenStatus struct {
	Age      time.Duration `json:"age,omitempty"`
	LastUsed time.Duration `json:"last_used,omitempty"`
}

type ErrorStatus struct {
	Error        string        `json:"error,omitempty"`
	LastReturned time.Duration `json:"last_returned,omitempty"`
}

// ResourceStatus contains the status of a specific resource type contained in
// the cache for a specific user.
type ResourceStatus struct {
	Name         string              `json:"name,omitempty"`
	Count        int                 `json:"count"`
	LastError    *ErrorStatus        `json:"last_error,omitempty"`
	RefreshToken *RefreshTokenStatus `json:"refresh_token,omitempty"`
}

// AuthTokenStatus contains the status of an auth token tracked in the cache for
// a specific user.
type AuthTokenStatus struct {
	Id                    string `json:"id,omitempty"`
	KeyringReferences     int    `json:"keyring_references,omitempty"`
	KeyringlessReferences int    `json:"keyringless_references,omitempty"`
}

// Information about the boundary controller the data is being cached from.
type BoundaryStatus struct {
	// The boundary address for this user
	Address string `json:"address,omitempty"`
	// Whether the controller responses are supported by the cache
	CacheSupport string `json:"cache_support,omitempty"`
	// How long ago the Boundary instance was checked for cache compatibility
	LastSupportCheck time.Duration `json:"last_support_check,omitempty"`
}

// UserStatus contains the status of a specific user tracked by the cache
type UserStatus struct {
	// The Id of the user this status is for
	Id string `json:"id,omitempty"`
	// The boundary instance this user connects to
	BoundaryInstance BoundaryStatus `json:"boundary_instance,omitempty"`
	// The auth tokens used by this user to authenticate with the boundary instance
	AuthTokens []AuthTokenStatus `json:"auth_tokens,omitempty"`
	// The resources tracked by the cache for this user
	Resources []ResourceStatus `json:"resources,omitempty"`
}

// StatusResult is the struct returned to status requests.
type StatusResult struct {
	Uptime        time.Duration `json:"uptime,omitempty"`
	SocketAddress string        `json:"socket_address,omitempty"`
	LogLocation   string        `json:"log_location,omitempty"`
	Version       string        `json:"version,omitempty"`
	Users         []UserStatus  `json:"users,omitempty"`
}

func newStatusHandlerFunc(ctx context.Context, repo *cache.Repository, socketAddr, logLocation string) (http.HandlerFunc, error) {
	const op = "daemon.newStatusHandlerFunc"
	switch {
	case util.IsNil(repo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "repository is missing")
	}
	started := time.Now()

	s, err := cache.NewStatusService(ctx, repo)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		res, err := s.Status(ctx)
		if err != nil {
			switch {
			case errors.Match(errors.T(errors.InvalidParameter), err):
				writeError(w, err.Error(), http.StatusBadRequest)
			default:
				writeError(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		if res == nil {
			writeError(w, "nil StatusResult generated", http.StatusInternalServerError)
			return
		}

		apiRes := toApiStatus(res, started, socketAddr, logLocation)
		j, err := json.Marshal(apiRes)
		if err != nil {
			writeError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(j); err != nil {
			writeError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}, nil
}

// toApiStatus converts a domain status result to an api status result
func toApiStatus(in *cache.Status, started time.Time, socketAddr, logLocation string) *StatusResult {
	if in == nil {
		return nil
	}

	out := &StatusResult{
		// Round(0) strips the monotonic clock from results which can drift
		// by a wide degree from the wall clock in the case where the system
		// sleeps.
		Uptime:        time.Since(started.Round(0)),
		SocketAddress: socketAddr,
		Version:       version.Get().FullVersionNumber(true),
		LogLocation:   logLocation,
	}

	for _, inU := range in.Users {
		outU := UserStatus{
			Id: inU.Id,
			BoundaryInstance: BoundaryStatus{
				Address:          inU.BoundaryStatus.Address,
				CacheSupport:     string(inU.BoundaryStatus.CachingSupported),
				LastSupportCheck: inU.BoundaryStatus.LastSupportCheck,
			},
		}
		for _, inAt := range inU.AuthTokens {
			outU.AuthTokens = append(outU.AuthTokens, AuthTokenStatus{
				Id:                    inAt.Id,
				KeyringReferences:     inAt.KeyringReferences,
				KeyringlessReferences: inAt.KeyringlessReferences,
			})
		}
		for _, inR := range inU.Resources {
			var outErr *ErrorStatus
			if inR.LastError != nil {
				outErr = &ErrorStatus{
					Error:        inR.LastError.Error,
					LastReturned: inR.LastError.LastReturned,
				}
			}
			var outRefTok *RefreshTokenStatus
			if inR.RefreshToken != nil {
				outRefTok = &RefreshTokenStatus{
					Age:      inR.RefreshToken.Age,
					LastUsed: inR.RefreshToken.LastUsed,
				}
			}
			outU.Resources = append(outU.Resources, ResourceStatus{
				Name:         inR.Name,
				Count:        inR.Count,
				LastError:    outErr,
				RefreshToken: outRefTok,
			})
		}

		out.Users = append(out.Users, outU)
	}
	return out
}
