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

	tokenNameKey    = "token_name"
	boundaryAddrKey = "boundary_addr"
	keyringTypeKey  = "keyring_type"
	authTokenIdKey  = "auth_token_id"
)

func newSearchTargetsHandlerFunc(ctx context.Context, repo *cache.Repository) (http.HandlerFunc, error) {
	const op = "daemon.newSearchTargetsHandlerFunc"
	switch {
	case util.IsNil(repo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "repository is missing")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		filter, err := handlers.NewFilter(ctx, r.URL.Query().Get(filterKey))
		if err != nil {
			writeError(w, err.Error(), http.StatusBadRequest)
			return
		}

		resource := r.URL.Query().Get(resourceKey)
		tokenName := r.URL.Query().Get(tokenNameKey)
		keyringType := r.URL.Query().Get(keyringTypeKey)
		authTokenId := r.URL.Query().Get(authTokenIdKey)

		switch {
		case resource == "":
			writeError(w, "resource is a required field but was empty", http.StatusBadRequest)
			return
		case tokenName == "":
			writeError(w, fmt.Sprintf("%s is a required field but was empty", tokenNameKey), http.StatusBadRequest)
			return
		case keyringType == "":
			writeError(w, fmt.Sprintf("%s is a required field but was empty", keyringTypeKey), http.StatusBadRequest)
			return
		case authTokenId == "":
			writeError(w, fmt.Sprintf("%s is a required field but was empty", authTokenIdKey), http.StatusBadRequest)
			return
		}

		t, err := repo.LookupToken(ctx, tokenName, keyringType, cache.WithAuthTokenId(authTokenId), cache.WithUpdateLastAccessedTime(true))
		if err != nil || t == nil {
			writeError(w, "Forbidden", http.StatusForbidden)
			return
		}

		query := r.URL.Query().Get(queryKey)

		var res *SearchResult
		switch resource {
		case "targets":
			res, err = searchTargets(r.Context(), repo, t, query, filter)
		case "sessions":
			res, err = searchSessions(r.Context(), repo, t, query, filter)
		default:
			writeError(w, fmt.Sprintf("search doesn't support %q resource", resource), http.StatusBadRequest)
			return
		}

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

func searchTargets(ctx context.Context, repo *cache.Repository, p *cache.Token, query string, filter *handlers.Filter) (*SearchResult, error) {
	var found []*targets.Target
	var err error
	switch query {
	case "":
		found, err = repo.ListTargets(ctx, p)
	default:
		found, err = repo.QueryTargets(ctx, p, query)
	}
	if err != nil {
		return nil, err
	}

	finalTars := make([]*targets.Target, 0, len(found))
	for _, item := range found {
		if filter.Match(item) {
			finalTars = append(finalTars, item)
		}
	}
	return &SearchResult{
		Targets: finalTars,
	}, nil
}

func searchSessions(ctx context.Context, repo *cache.Repository, p *cache.Token, query string, filter *handlers.Filter) (*SearchResult, error) {
	var found []*sessions.Session
	var err error
	switch query {
	case "":
		found, err = repo.ListSessions(ctx, p)
	default:
		found, err = repo.QuerySessions(ctx, p, query)
	}
	if err != nil {
		return nil, err
	}

	finalSess := make([]*sessions.Session, 0, len(found))
	for _, item := range found {
		if filter.Match(item) {
			finalSess = append(finalSess, item)
		}
	}
	return &SearchResult{
		Sessions: finalSess,
	}, nil
}
