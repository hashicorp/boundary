// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/api/aliases"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/go-bexpr"
)

type SearchableResource string

const (
	Unknown  SearchableResource = "unknown"
	Aliases  SearchableResource = "aliases"
	Targets  SearchableResource = "targets"
	Sessions SearchableResource = "sessions"
)

func (r SearchableResource) Valid() bool {
	switch r {
	case Aliases, Targets, Sessions:
		return true
	}
	return false
}

func ToSearchableResource(s string) SearchableResource {
	switch {
	case strings.EqualFold(s, string(Aliases)):
		return Aliases
	case strings.EqualFold(s, string(Targets)):
		return Targets
	case strings.EqualFold(s, string(Sessions)):
		return Sessions
	}
	return Unknown
}

// SearchParams contains the parameters for searching in the cache
type SearchParams struct {
	// the name of the resource. eg. "targets" or "sessions"
	Resource SearchableResource
	// the auth token id for the user id that has resources synced to the cache
	AuthTokenId string
	// the optional mql query to use when searching the resources.
	Query string
	// the optional bexpr filter string that all results will be filtered by
	Filter string
}

// SearchResult returns the results from searching the cache.
type SearchResult struct {
	Aliases  []*aliases.Alias
	Targets  []*targets.Target
	Sessions []*sessions.Session
}

// SearchService is a domain service that can search across all resources in the
// cache.
type SearchService struct {
	searchableResources map[SearchableResource]resourceSearcher
	repo                *Repository
}

func NewSearchService(ctx context.Context, repo *Repository) (*SearchService, error) {
	const op = "cache.NewSearchService"
	switch {
	case util.IsNil(repo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "repo is nil")
	}
	return &SearchService{
		repo: repo,
		searchableResources: map[SearchableResource]resourceSearcher{
			Aliases: &resourceSearchFns[*aliases.Alias]{
				list:  repo.ListAliases,
				query: repo.QueryAliases,
				searchResult: func(a []*aliases.Alias) *SearchResult {
					return &SearchResult{Aliases: a}
				},
			},
			Targets: &resourceSearchFns[*targets.Target]{
				list:  repo.ListTargets,
				query: repo.QueryTargets,
				searchResult: func(t []*targets.Target) *SearchResult {
					return &SearchResult{Targets: t}
				},
			},
			Sessions: &resourceSearchFns[*sessions.Session]{
				list:  repo.ListSessions,
				query: repo.QuerySessions,
				searchResult: func(s []*sessions.Session) *SearchResult {
					return &SearchResult{Sessions: s}
				},
			},
		},
	}, nil
}

// Supported returns true if the provided search is supported for the provided
// auth token.
func (s *SearchService) Supported(ctx context.Context, t *AuthToken) (bool, error) {
	const op = "cache.(SearchService).Supported"
	switch {
	case util.IsNil(t):
		return false, errors.New(ctx, errors.InvalidParameter, op, "auth token is nil", errors.WithoutEvent())
	case t.UserId == "":
		return false, errors.New(ctx, errors.InvalidParameter, op, "auth token's user id is empty", errors.WithoutEvent())
	}
	u, err := s.repo.lookupUser(ctx, t.UserId)
	if err != nil {
		return false, errors.Wrap(ctx, err, op, errors.WithoutEvent())
	}
	if u == nil {
		return false, errors.New(ctx, errors.NotFound, op, "user not found for auth token", errors.WithoutEvent())
	}
	cs, err := s.repo.cacheSupportState(ctx, u)
	if err != nil {
		return false, errors.Wrap(ctx, err, op, errors.WithoutEvent())
	}
	return cs.supported != NotSupportedCacheSupport, nil
}

// Search returns a SearchResult based on the provided SearchParams.  If the
// SearchParams doesn't have a valid searchable resource or an auth token id
// an error is returned. If the auth token id is unrecognized or is associated
// with a user id which doesn't have any resources associated with it an empty
// SearchResult is returned. SearchResult will only have at most one field
// populated.
func (s *SearchService) Search(ctx context.Context, params SearchParams) (*SearchResult, error) {
	const op = "cache.(SearchService).Search"
	switch {
	case !params.Resource.Valid():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "invalid resource")
	case params.AuthTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth token id")
	}
	rSearcher, ok := s.searchableResources[params.Resource]
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("resource name %q is not recognized", params.Resource))
	}
	resp, err := rSearcher.search(ctx, params)
	if err != nil {
		err = errors.Wrap(ctx, err, op)
	}
	return resp, err
}

// resourceSearchFns is a struct that collects all the functions needed to
// perform a search  on a specific resource type.
type resourceSearchFns[T any] struct {
	// list takes a context and an auth token and returns all resources for the
	// user of that auth token. If the provided auth token is not in the cache
	// an empty slice and no error is returned.
	list func(context.Context, string) ([]T, error)
	// query takes a context, an auth token, and a query string and returns all
	// resources for that auth token that matches the provided query parameter.
	// If the provided auth token is not in the cache an empty slice and no
	// error is returned.
	query func(context.Context, string, string) ([]T, error)
	// searchResult is a function which provides a SearchResult based on the
	// type of T. SearchResult contains different fields for the different
	// resource types returned, so for example if T is *targets.Target the
	// returned SearchResult will have it's "Targets" field populated so the
	// searchResult should take the passed in paramater and assign it to the
	// appropriate field in the SearchResult.
	searchResult func([]T) *SearchResult
}

// resourceSearcher is an interface that only resourceSearchFns[T] is expected
// to satisfy. Specifying this interface allows the code to have a map with
// resourceSearchFns values which have different bound generic types.
type resourceSearcher interface {
	search(ctx context.Context, p SearchParams) (*SearchResult, error)
}

// search will perform a query using the provided query string or a list if the
// provided query string is empty and filter than based on the provided filter.
// The results are tied to the user id associated with the provided auth token id.
// If the auth token id or the associated user are not in the cache  no error
// is returned and the returned SearchResults will be empty.
// search implements searcher.
func (l *resourceSearchFns[T]) search(ctx context.Context, p SearchParams) (*SearchResult, error) {
	const op = "daemon.(resourceSearchFns).search"

	var found []T
	var err error
	switch p.Query {
	case "":
		found, err = l.list(ctx, p.AuthTokenId)
	default:
		found, err = l.query(ctx, p.AuthTokenId, p.Query)
	}
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	if p.Filter == "" {
		return l.searchResult(found), nil
	}

	e, err := bexpr.CreateEvaluator(p.Filter, bexpr.WithTagName("json"))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("couldn't build filter"), errors.WithCode(errors.InvalidParameter))
	}
	finalResults := make([]T, 0, len(found))
	for _, item := range found {
		if m, err := e.Evaluate(filterItem{item}); err == nil && m {
			finalResults = append(finalResults, item)
		}
	}
	return l.searchResult(finalResults), nil
}

type filterItem struct {
	Item any `json:"item"`
}
