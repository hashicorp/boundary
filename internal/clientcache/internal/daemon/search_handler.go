// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/clientcache/internal/cache"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/go-hclog"
)

// SearchResult is the struct returned to search requests.
type SearchResult struct {
	Targets  []*targets.Target   `json:"targets,omitempty"`
	Sessions []*sessions.Session `json:"sessions,omitempty"`
}

const (
	filterKey       = "filter"
	queryKey        = "query"
	resourceKey     = "resource"
	forceRefreshKey = "force_refresh"
	authTokenIdKey  = "auth_token_id"
)

func newSearchHandlerFunc(ctx context.Context, repo *cache.Repository, refreshService *cache.RefreshService, logger hclog.Logger) (http.HandlerFunc, error) {
	const op = "daemon.newSearchHandlerFunc"
	switch {
	case util.IsNil(repo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "repository is missing")
	case util.IsNil(logger):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "logger is missing")
	case util.IsNil(refreshService):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "refresh service is missing")
	}

	s, err := cache.NewSearchService(ctx, repo)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		reqCtx := r.Context()
		resource := r.URL.Query().Get(resourceKey)
		authTokenId := r.URL.Query().Get(authTokenIdKey)

		searchableResource := cache.ToSearchableResource(resource)
		switch {
		case resource == "":
			event.WriteError(ctx, op, errors.New(ctx, errors.InvalidParameter, op, "resource is a required field but was empty"))
			writeError(w, "resource is a required field but was empty", http.StatusBadRequest)
			return
		case !searchableResource.Valid():
			event.WriteError(ctx, op, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("provided resource %q is not a valid searchable resource", resource)))
			writeError(w, "provided resource is not a valid searchable resource", http.StatusBadRequest)
			return
		case authTokenId == "":
			event.WriteError(ctx, op, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s is a required field but was empty", authTokenIdKey)))
			writeError(w, fmt.Sprintf("%s is a required field but was empty", authTokenIdKey), http.StatusBadRequest)
			return
		}

		t, err := repo.LookupToken(reqCtx, authTokenId, cache.WithUpdateLastAccessedTime(true))
		if err != nil || t == nil {
			if err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("when looking up the auth token", "auth_token_id", authTokenId))
			}
			if t == nil {
				event.WriteError(ctx, op, errors.New(ctx, errors.NotFound, op, fmt.Sprintf("auth token with id %q not found in cache", authTokenId)))
			}
			writeError(w, "Forbidden", http.StatusForbidden)
			return
		}

		supported, err := s.Supported(reqCtx, t)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("when checking if search is supported for the provided auth token", "auth_token_id", authTokenId))
			writeError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !supported {
			event.WriteError(ctx, op, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("search not supported for the provided auth token %q", authTokenId)))
			writeUnsupportedError(w)
			return
		}

		var opts []cache.Option
		if b, err := strconv.ParseBool(r.URL.Query().Get(forceRefreshKey)); err == nil && b {
			opts = append(opts, cache.WithIgnoreSearchStaleness(true))
		}

		// Refresh the resources for the provided user, if possible. This is best
		// effort, so if there is any problem refreshing, we just log the error
		// and move on to handling the search request.
		if err := refreshService.RefreshForSearch(reqCtx, authTokenId, searchableResource, opts...); err != nil {
			// we don't stop the search, we just log that the inline refresh failed
			event.WriteError(ctx, op, err, event.WithInfoMsg("when refreshing the resources inline for search", "auth_token_id", authTokenId, "resource", searchableResource))
		}

		query := r.URL.Query().Get(queryKey)
		filter := r.URL.Query().Get(filterKey)

		res, err := s.Search(reqCtx, cache.SearchParams{
			AuthTokenId: authTokenId,
			Resource:    searchableResource,
			Query:       query,
			Filter:      filter,
		})
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("when performing search", "auth_token_id", authTokenId, "resource", searchableResource, "query", query, "filter", filter))
			switch {
			case errors.Match(errors.T(errors.InvalidParameter), err):
				writeError(w, err.Error(), http.StatusBadRequest)
			default:
				writeError(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		if res == nil {
			writeError(w, "nil SearchResult generated", http.StatusInternalServerError)
			return
		}

		apiRes := toApiResult(res)
		j, err := json.Marshal(apiRes)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("when marshaling search result to JSON", "auth_token_id", authTokenId, "resource", searchableResource, "query", query, "filter", filter))
			writeError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(j)
	}, nil
}

// toApiResult converts a domain search result to an api search result
func toApiResult(sr *cache.SearchResult) *SearchResult {
	return &SearchResult{
		Targets:  sr.Targets,
		Sessions: sr.Sessions,
	}
}

var errSearchNotSupported = &api.Error{
	Kind:    "Unsupported Search Request",
	Message: "The request is for a Boundary instance that doesn't support search. The Boundary instance must support refresh tokens for search to be supported.",
}

func writeUnsupportedError(w http.ResponseWriter) {
	b, err := json.Marshal(errSearchNotSupported)
	if err != nil {
		http.Error(w, fmt.Sprintf("Unable to marshal error %v into api error format: %s", errSearchNotSupported, err.Error()), http.StatusInternalServerError)
		return
	}
	http.Error(w, string(b), http.StatusBadRequest)
}
