// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/daemon/cache"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

const (
	filterKey   = "filter"
	queryKey    = "query"
	resourceKey = "resource"

	tokenNameKey    = "token_name"
	boundaryAddrKey = "boundary_addr"
	keyringTypeKey  = "keyring_type"

	idContainsKey          = "id_contains"
	nameContainsKey        = "name_contains"
	descriptionContainsKey = "description_contains"
	addressContainsKey     = "address_contains"

	idStartsWithKey          = "id_starts_with"
	nameStartsWithKey        = "name_starts_with"
	descriptionStartsWithKey = "description_starts_with"
	addressStartsWithKey     = "address_starts_with"

	idEndsWithKey          = "id_ends_with"
	nameEndsWithKey        = "name_ends_with"
	descriptionEndsWithKey = "description_ends_with"
	addressEndsWithKey     = "address_ends_with"
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
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resource := r.URL.Query().Get(resourceKey)
		tokenName := r.URL.Query().Get(tokenNameKey)
		keyringType := r.URL.Query().Get(keyringTypeKey)
		boundaryAddr := r.URL.Query().Get(boundaryAddrKey)

		switch {
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

		var found []*targets.Target
		switch {
		case r.URL.Query().Get(queryKey) != "":
			found, err = repo.QueryTargets(r.Context(), p, r.URL.Query().Get(queryKey))
		default:
			found, err = repo.FindTargets(
				r.Context(),
				p,
				cache.WithIdContains(r.URL.Query().Get(idContainsKey)),
				cache.WithNameContains(r.URL.Query().Get(nameContainsKey)),
				cache.WithDescriptionContains(r.URL.Query().Get(descriptionContainsKey)),
				cache.WithAddressContains(r.URL.Query().Get(addressContainsKey)),

				cache.WithIdStartsWith(r.URL.Query().Get(idStartsWithKey)),
				cache.WithNameStartsWith(r.URL.Query().Get(nameStartsWithKey)),
				cache.WithDescriptionStartsWith(r.URL.Query().Get(descriptionStartsWithKey)),
				cache.WithAddressStartsWith(r.URL.Query().Get(addressStartsWithKey)),

				cache.WithIdEndsWith(r.URL.Query().Get(idEndsWithKey)),
				cache.WithNameEndsWith(r.URL.Query().Get(nameEndsWithKey)),
				cache.WithDescriptionEndsWith(r.URL.Query().Get(descriptionEndsWithKey)),
				cache.WithAddressEndsWith(r.URL.Query().Get(addressEndsWithKey)),
			)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		finalItems := make([]*targets.Target, 0, len(found))
		for _, item := range found {
			if filter.Match(item) {
				finalItems = append(finalItems, item)
			}
		}

		items := struct {
			Items []*targets.Target `json:"items"`
		}{
			Items: finalItems,
		}
		j, err := json.Marshal(items)
		if err != nil {
			writeError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(j)
	}, nil
}
