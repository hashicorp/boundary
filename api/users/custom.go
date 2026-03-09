// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package users

import (
	"context"
	"fmt"
	"net/url"

	"github.com/hashicorp/boundary/api/aliases"
)

// ListResolvableAliases builds and sends a request to the API for listing
// resolvable aliases for the specified user. It retrieves all remaining pages
// and includes in the result the list token for paginating through future
// updates. To use the list token use the users.WithListToken option.
func (c *Client) ListResolvableAliases(ctx context.Context, userId string, opt ...Option) (*aliases.AliasListResult, error) {
	if userId == "" {
		return nil, fmt.Errorf("empty userId value passed into ListResolvableAliases request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, _ := getOpts(opt...)
	apiClient := aliases.NewClient(c.client)
	return apiClient.List(ctx, "global",
		aliases.WithAutomaticVersioning(opts.withAutomaticVersioning),
		aliases.WithSkipCurlOutput(opts.withSkipCurlOutput),
		aliases.WithFilter(opts.withFilter),
		aliases.WithListToken(opts.withListToken),
		aliases.WithClientDirectedPagination(opts.withClientDirectedPagination),
		aliases.WithPageSize(opts.withPageSize),
		aliases.WithRecursive(opts.withRecursive),
		aliases.WithResourcePathOverride(fmt.Sprintf("users/%s:list-resolvable-aliases", url.PathEscape(userId))),
	)
}

func (c *Client) ListResolvableAliasesNextPage(ctx context.Context, userId string, currentPage *aliases.AliasListResult, opt ...Option) (*aliases.AliasListResult, error) {
	if currentPage == nil {
		return nil, fmt.Errorf("empty currentPage value passed into ListResolvableAliasesNextPage request")
	}
	if userId == "" {
		return nil, fmt.Errorf("empty userId value passed into ListResolvableAliasesNextPage request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}
	if currentPage.ResponseType == "complete" || currentPage.ResponseType == "" {
		return nil, fmt.Errorf("no more pages available in ListResolvableAliasesNextPage request")
	}

	opts, _ := getOpts(opt...)
	apiClient := aliases.NewClient(c.client)
	return apiClient.ListNextPage(ctx, currentPage,
		aliases.WithAutomaticVersioning(opts.withAutomaticVersioning),
		aliases.WithSkipCurlOutput(opts.withSkipCurlOutput),
		aliases.WithFilter(opts.withFilter),
		aliases.WithListToken(opts.withListToken),
		aliases.WithClientDirectedPagination(opts.withClientDirectedPagination),
		aliases.WithPageSize(opts.withPageSize),
		aliases.WithRecursive(opts.withRecursive),
		aliases.WithResourcePathOverride(fmt.Sprintf("users/%s:list-resolvable-aliases", url.PathEscape(userId))),
	)
}
