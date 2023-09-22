// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/daemon/cache"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

// SearchResult is the struct returned to search requests.
type SearchResult struct {
	Targets  []*targets.Target   `json:",omitempty"`
	Sessions []*sessions.Session `json:",omitempty"`
}

const (
	filterKey   = "filter"
	queryKey    = "query"
	resourceKey = "resource"

	boundaryAddrKey = "boundary_addr"
	authTokenIdKey  = "auth_token_id"
)

func newSearchTargetsHandlerFunc(ctx context.Context, repo *cache.Repository) (http.HandlerFunc, error) {
	const op = "daemon.newSearchTargetsHandlerFunc"
	switch {
	case util.IsNil(repo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "repository is missing")
	}

	searchableResources := map[string]searcher{
		"targets": &searchFns[*targets.Target]{
			list:  repo.ListTargets,
			query: repo.QueryTargets,
			searchResult: func(t []*targets.Target) *SearchResult {
				return &SearchResult{Targets: t}
			},
		},
		"sessions": &searchFns[*sessions.Session]{
			list:  repo.ListSessions,
			query: repo.QuerySessions,
			searchResult: func(s []*sessions.Session) *SearchResult {
				return &SearchResult{Sessions: s}
			},
		},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		filter, err := handlers.NewFilter(ctx, r.URL.Query().Get(filterKey))
		if err != nil {
			writeError(w, err.Error(), http.StatusBadRequest)
			return
		}

		resource := r.URL.Query().Get(resourceKey)
		authTokenId := r.URL.Query().Get(authTokenIdKey)

		switch {
		case resource == "":
			writeError(w, "resource is a required field but was empty", http.StatusBadRequest)
			return
		case authTokenId == "":
			writeError(w, fmt.Sprintf("%s is a required field but was empty", authTokenIdKey), http.StatusBadRequest)
			return
		}

		t, err := repo.LookupToken(ctx, authTokenId, cache.WithUpdateLastAccessedTime(true))
		if err != nil || t == nil {
			writeError(w, "Forbidden", http.StatusForbidden)
			return
		}

		query := r.URL.Query().Get(queryKey)

		rSearcher, ok := searchableResources[resource]
		if !ok {
			writeError(w, fmt.Sprintf("search doesn't support %q resource", resource), http.StatusBadRequest)
			return
		}
		res, err := rSearcher.search(r.Context(), authTokenId, query, filter)
		if err != nil {
			switch {
			case errors.Match(errors.T(errors.InvalidParameter), err):
				writeError(w, err.Error(), http.StatusBadRequest)
			default:
				writeError(w, err.Error(), http.StatusInternalServerError)
			}
		}
		if res == nil {
			writeError(w, "nil SearchResult generated", http.StatusInternalServerError)
		}

		j, err := json.Marshal(res)
		if err != nil {
			writeError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(j)
	}, nil
}

type searcher interface {
	search(ctx context.Context, authTokenId, query string, filter *handlers.Filter) (*SearchResult, error)
}

// searchFns is a struct that collects all the functions needed to perform a search
// on a specific resource type.
type searchFns[T any] struct {
	// list takes a context and an auth token and returns all resources for the
	// user of that auth token.
	list func(context.Context, string) ([]T, error)
	// query takes a context, an auth token, and a query string and returns all
	// resources for that auth token that matches the provided query parameter
	query        func(context.Context, string, string) ([]T, error)
	searchResult func([]T) *SearchResult
}

func (l *searchFns[T]) search(ctx context.Context, authTokenId, query string, filter *handlers.Filter) (*SearchResult, error) {
	const op = "daemon.(lookupFns).search"
	var found []T
	var err error
	switch query {
	case "":
		found, err = l.list(ctx, authTokenId)
	default:
		found, err = l.query(ctx, authTokenId, query)
	}
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	finalResults := make([]T, 0, len(found))
	for _, item := range found {
		if filter.Match(item) {
			finalResults = append(finalResults, item)
		}
	}
	return l.searchResult(finalResults), nil
}
