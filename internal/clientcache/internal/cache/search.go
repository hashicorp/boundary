// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/api/aliases"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/go-bexpr"
)

type SortBy string

const (
	SortByDefault   SortBy = ""
	SortByName      SortBy = "name"
	SortByCreatedAt SortBy = "created_at"
)

type SortDirection string

const (
	SortDirectionDefault SortDirection = ""
	Ascending            SortDirection = "asc"
	Descending           SortDirection = "desc"
)

type SearchableResource string

const (
	Unknown           SearchableResource = "unknown"
	ResolvableAliases SearchableResource = "resolvable-aliases"
	Targets           SearchableResource = "targets"
	Sessions          SearchableResource = "sessions"
	ImplicitScopes    SearchableResource = "implicit-scopes"
)

func (r SearchableResource) Valid() bool {
	switch r {
	case ResolvableAliases, Targets, Sessions, ImplicitScopes:
		return true
	}
	return false
}

func ToSearchableResource(s string) SearchableResource {
	switch {
	case strings.EqualFold(s, string(ResolvableAliases)):
		return ResolvableAliases
	case strings.EqualFold(s, string(Targets)):
		return Targets
	case strings.EqualFold(s, string(Sessions)):
		return Sessions
	case strings.EqualFold(s, string(ImplicitScopes)):
		return ImplicitScopes
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
	// Max result set size is an override to the default max result set size
	MaxResultSetSize int
	// Which column to sort results by, default is resource specific
	SortBy SortBy
	// Which direction to sort results by (asc, desc), default is resource specific
	SortDirection SortDirection
}

// SearchResult returns the results from searching the cache.
type SearchResult struct {
	ResolvableAliases []*aliases.Alias    `json:"resolvable_aliases,omitempty"`
	Targets           []*targets.Target   `json:"targets,omitempty"`
	Sessions          []*sessions.Session `json:"sessions,omitempty"`
	ImplicitScopes    []*scopes.Scope     `json:"implicit_scopes,omitempty"`

	// Incomplete is true if the search results are incomplete, that is, we are
	// returning only a subset based on the max result set size
	Incomplete bool `json:"incomplete,omitempty"`
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
			ResolvableAliases: &resourceSearchFns[*aliases.Alias]{
				list:  repo.ListResolvableAliases,
				query: repo.QueryResolvableAliases,
				filter: func(in *SearchResult, e *bexpr.Evaluator) {
					finalResults := make([]*aliases.Alias, 0, len(in.ResolvableAliases))
					for _, item := range in.ResolvableAliases {
						if m, err := e.Evaluate(filterItem{item}); err == nil && m {
							finalResults = append(finalResults, item)
						}
					}
					in.ResolvableAliases = finalResults
				},
			},
			Targets: &resourceSearchFns[*targets.Target]{
				list:  repo.ListTargets,
				query: repo.QueryTargets,
				filter: func(in *SearchResult, e *bexpr.Evaluator) {
					finalResults := make([]*targets.Target, 0, len(in.Targets))
					for _, item := range in.Targets {
						if m, err := e.Evaluate(filterItem{item}); err == nil && m {
							finalResults = append(finalResults, item)
						}
					}
					in.Targets = finalResults
				},
			},
			Sessions: &resourceSearchFns[*sessions.Session]{
				list:  repo.ListSessions,
				query: repo.QuerySessions,
				filter: func(in *SearchResult, e *bexpr.Evaluator) {
					finalResults := make([]*sessions.Session, 0, len(in.Sessions))
					for _, item := range in.Sessions {
						if m, err := e.Evaluate(filterItem{item}); err == nil && m {
							finalResults = append(finalResults, item)
						}
					}
					in.Sessions = finalResults
				},
			},
			ImplicitScopes: &resourceSearchFns[*scopes.Scope]{
				list:  repo.ListImplicitScopes,
				query: repo.QueryImplicitScopes,
				filter: func(in *SearchResult, e *bexpr.Evaluator) {
					finalResults := make([]*scopes.Scope, 0, len(in.ImplicitScopes))
					for _, item := range in.ImplicitScopes {
						if m, err := e.Evaluate(filterItem{item}); err == nil && m {
							finalResults = append(finalResults, item)
						}
					}
					in.ImplicitScopes = finalResults
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
	list func(context.Context, string, ...Option) (*SearchResult, error)
	// query takes a context, an auth token, and a query string and returns all
	// resources for that auth token that matches the provided query parameter.
	// If the provided auth token is not in the cache an empty slice and no
	// error is returned.
	query func(context.Context, string, string, ...Option) (*SearchResult, error)
	// filter takes results and a ready-to-use evaluator and filters the items
	// in the result
	filter func(*SearchResult, *bexpr.Evaluator)
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
	const op = "cache.(resourceSearchFns).search"

	var found *SearchResult
	var err error
	switch p.Query {
	case "":
		found, err = l.list(ctx, p.AuthTokenId, WithMaxResultSetSize(p.MaxResultSetSize))
	default:
		found, err = l.query(ctx, p.AuthTokenId, p.Query, WithMaxResultSetSize(p.MaxResultSetSize))
	}
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	if p.Filter == "" {
		return found, nil
	}

	e, err := bexpr.CreateEvaluator(p.Filter, bexpr.WithTagName("json"))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("couldn't build filter"), errors.WithCode(errors.InvalidParameter))
	}

	l.filter(found, e)
	return found, nil
}

type filterItem struct {
	Item any `json:"item"`
}
