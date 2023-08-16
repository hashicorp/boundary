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
)

func newSearchTargetsHandlerFunc(ctx context.Context, store *cache.Store) (http.HandlerFunc, error) {
	const op = "daemon.newSearchTargetsHandlerFunc"
	switch {
	case util.IsNil(store):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "store is missing")
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
		boundaryAddr := r.URL.Query().Get(boundaryAddrKey)

		switch {
		case resource == "":
			writeError(w, "resource is a required field but was empty", http.StatusBadRequest)
			return
		case resource != "targets":
			writeError(w, fmt.Sprintf("search doesn't support %q resource", resource), http.StatusBadRequest)
			return
		case tokenName == "":
			writeError(w, fmt.Sprintf("%s is a required field but was empty", tokenNameKey), http.StatusBadRequest)
			return
		case keyringType == "":
			writeError(w, fmt.Sprintf("%s is a required field but was empty", keyringTypeKey), http.StatusBadRequest)
			return
		case boundaryAddr == "":
			writeError(w, fmt.Sprintf("%s is a required field but was empty", boundaryAddrKey), http.StatusBadRequest)
			return
		}

		repo, err := cache.NewRepository(ctx, store)
		if err != nil {
			writeError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		p, err := repo.LookupPersona(ctx, boundaryAddr, keyringType, tokenName, cache.WithUpdateLastAccessedTime(true))
		if err != nil || p == nil {
			writeError(w, "Forbidden", http.StatusForbidden)
			return
		}

		query := r.URL.Query().Get(queryKey)
		var found []*targets.Target
		switch query {
		case "":
			found, err = repo.ListTargets(r.Context(), p)
		default:
			found, err = repo.QueryTargets(r.Context(), p, query)
		}

		if err != nil {
			switch {
			case errors.Match(errors.T(errors.InvalidParameter), err):
				writeError(w, err.Error(), http.StatusBadRequest)
			default:
				writeError(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")

		finalItems := make([]*targets.Target, 0, len(found))
		for _, item := range found {
			if filter.Match(item) {
				finalItems = append(finalItems, item)
			}
		}

		res := SearchResult{
			Targets: finalItems,
		}
		j, err := json.Marshal(res)
		if err != nil {
			writeError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(j)
	}, nil
}
