// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package users

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strconv"

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

	opts, apiOpts := getOpts(opt...)
	req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("users/%s:list-resolvable-aliases", url.PathEscape(userId)), nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating List request: %w", err)
	}

	if len(opts.queryMap) > 0 {
		q := url.Values{}
		for k, v := range opts.queryMap {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during List call: %w", err)
	}

	target := new(aliases.AliasListResult)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, fmt.Errorf("error decoding List response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.Response = resp
	if target.ResponseType == "complete" || target.ResponseType == "" {
		return target, nil
	}

	// In case we shortcut out due to client directed pagination, ensure these
	// are set
	target.Recursive = opts.withRecursive
	target.PageSize = opts.withPageSize
	target.AllRemovedIds = target.RemovedIds
	if opts.withClientDirectedPagination {
		return target, nil
	}

	allItems := make([]*aliases.Alias, 0, target.EstItemCount)
	allItems = append(allItems, target.Items...)

	// If there are more results, automatically fetch the rest of the results.
	// idToIndex keeps a map from the ID of an item to its index in target.Items.
	// This is used to update updated items in-place and remove deleted items
	// from the result after pagination is done.
	idToIndex := map[string]int{}
	for i, item := range allItems {
		idToIndex[item.Id] = i
	}

	// If we're here there are more pages and the client does not want to
	// paginate on their own; fetch them as this call returns all values.
	currentPage := target
	for {
		nextPage, err := c.ListResolvableAliasesNextPage(ctx, userId, currentPage, opt...)
		if err != nil {
			return nil, fmt.Errorf("error getting next page in List call: %w", err)
		}

		for _, item := range nextPage.Items {
			if i, ok := idToIndex[item.Id]; ok {
				// Item has already been seen at index i, update in-place
				allItems[i] = item
			} else {
				allItems = append(allItems, item)
				idToIndex[item.Id] = len(allItems) - 1
			}
		}

		currentPage = nextPage

		if currentPage.ResponseType == "complete" {
			break
		}
	}

	// The current page here is the final page of the results, that is, the
	// response type is "complete"

	// Remove items that were deleted since the end of the last iteration.
	// If a User has been updated and subsequently removed, we don't want
	// it to appear both in the Items and RemovedIds, so we remove it from the Items.
	for _, removedId := range currentPage.RemovedIds {
		if i, ok := idToIndex[removedId]; ok {
			// Remove the item at index i without preserving order
			// https://github.com/golang/go/wiki/SliceTricks#delete-without-preserving-order
			allItems[i] = allItems[len(allItems)-1]
			allItems = allItems[:len(allItems)-1]
			// Update the index of the previously last element
			idToIndex[allItems[i].Id] = i
		}
	}
	// Sort the results again since in-place updates and deletes
	// may have shuffled items. We sort by created time descending
	// (most recently created first), same as the API.
	slices.SortFunc(allItems, func(i, j *aliases.Alias) int {
		return j.CreatedTime.Compare(i.CreatedTime)
	})
	// Since we paginated to the end, we can avoid confusion
	// for the user by setting the estimated item count to the
	// length of the items slice. If we don't set this here, it
	// will equal the value returned in the last response, which is
	// often much smaller than the total number returned.
	currentPage.EstItemCount = uint(len(allItems))
	// Set items to the full list we have collected here
	currentPage.Items = allItems
	// Set the returned value to the last page with calculated values
	target = currentPage
	// Finally, since we made at least 2 requests to the server to fulfill this
	// function call, resp.Body and resp.Map will only contain the most recent response.
	// Overwrite them with the true response.
	target.Response.Body.Reset()
	if err := json.NewEncoder(target.Response.Body).Encode(target); err != nil {
		return nil, fmt.Errorf("error encoding final JSON list response: %w", err)
	}
	if err := json.Unmarshal(target.Response.Body.Bytes(), &target.Response.Map); err != nil {
		return nil, fmt.Errorf("error encoding final map list response: %w", err)
	}
	// Note: the HTTP response body is consumed by resp.Decode in the loop,
	// so it doesn't need to be updated (it will always be, and has always been, empty).
	return target, nil
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

	opts, apiOpts := getOpts(opt...)

	// Don't require them to re-specify recursive
	if currentPage.Recursive {
		opts.queryMap["recursive"] = "true"
	}

	if currentPage.PageSize != 0 {
		opts.queryMap["page_size"] = strconv.FormatUint(uint64(currentPage.PageSize), 10)
	}

	req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("users/%s:list-resolvable-aliases", url.PathEscape(userId)), nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating List request: %w", err)
	}

	opts.queryMap["list_token"] = currentPage.ListToken
	if len(opts.queryMap) > 0 {
		q := url.Values{}
		for k, v := range opts.queryMap {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during List call during ListNextPage: %w", err)
	}

	nextPage := new(aliases.AliasListResult)
	apiErr, err := resp.Decode(nextPage)
	if err != nil {
		return nil, fmt.Errorf("error decoding List response during ListNextPage: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}

	// Ensure values are carried forward to the next call
	nextPage.Recursive = currentPage.Recursive
	nextPage.PageSize = currentPage.PageSize
	// Cache the removed IDs from this page
	nextPage.AllRemovedIds = append(currentPage.AllRemovedIds, nextPage.RemovedIds...)
	// Set the response body to the current response
	nextPage.Response = resp
	// If we're done iterating, pull the full set of removed IDs into the last
	// response
	if nextPage.ResponseType == "complete" {
		// Collect up the last values
		nextPage.RemovedIds = nextPage.AllRemovedIds
		// For now, removedIds will only be populated if this pagination cycle
		// was the result of a "refresh" operation (i.e., the caller provided a
		// list token option to this call).
		//
		// Sort to make response deterministic
		slices.Sort(nextPage.RemovedIds)
		// Remove any duplicates
		nextPage.RemovedIds = slices.Compact(nextPage.RemovedIds)
	}

	return nextPage, nil
}
