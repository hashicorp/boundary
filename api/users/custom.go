// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package users

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"

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
	// If there are more results, automatically fetch the rest of the results.
	// idToIndex keeps a map from the ID of an item to its index in target.Items.
	// This is used to update updated items in-place and remove deleted items
	// from the result after pagination is done.
	idToIndex := map[string]int{}
	for i, item := range target.Items {
		idToIndex[item.Id] = i
	}
	for {
		req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("users/%s:list-resolvable-aliases", url.PathEscape(userId)), nil, apiOpts...)
		if err != nil {
			return nil, fmt.Errorf("error creating List request: %w", err)
		}

		opts.queryMap["list_token"] = target.ListToken
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

		page := new(aliases.AliasListResult)
		apiErr, err := resp.Decode(page)
		if err != nil {
			return nil, fmt.Errorf("error decoding List response: %w", err)
		}
		if apiErr != nil {
			return nil, apiErr
		}
		for _, item := range page.Items {
			if i, ok := idToIndex[item.Id]; ok {
				// Item has already been seen at index i, update in-place
				target.Items[i] = item
			} else {
				target.Items = append(target.Items, item)
				idToIndex[item.Id] = len(target.Items) - 1
			}
		}
		// RemovedIds contain any Alias that were deleted since the last response.
		target.RemovedIds = append(target.RemovedIds, page.RemovedIds...)
		target.EstItemCount = page.EstItemCount
		target.ListToken = page.ListToken
		target.ResponseType = page.ResponseType
		target.Response = resp
		if target.ResponseType == "complete" {
			break
		}
	}
	// For now, removedIds will only be populated if this pagination cycle was the result of a
	// "refresh" operation (i.e., the caller provided a list token option to this call).
	//
	// Sort to make response deterministic
	slices.Sort(target.RemovedIds)
	// Remove any duplicates
	target.RemovedIds = slices.Compact(target.RemovedIds)
	// Remove items that were deleted since the end of the last iteration.
	// If an Alias has been updated and subsequently removed, we don't want
	// it to appear both in the Items and RemovedIds, so we remove it from the Items.
	for _, removedId := range target.RemovedIds {
		if i, ok := idToIndex[removedId]; ok {
			// Remove the item at index i without preserving order
			// https://github.com/golang/go/wiki/SliceTricks#delete-without-preserving-order
			target.Items[i] = target.Items[len(target.Items)-1]
			target.Items = target.Items[:len(target.Items)-1]
			// Update the index of the previously last element
			idToIndex[target.Items[i].Id] = i
		}
	}
	// Since we paginated to the end, we can avoid confusion
	// for the user by setting the estimated item count to the
	// length of the items slice. If we don't set this here, it
	// will equal the value returned in the last response, which is
	// often much smaller than the total number returned.
	target.EstItemCount = uint(len(target.Items))
	// Sort the results again since in-place updates and deletes
	// may have shuffled items. We sort by created time descending
	// (most recently created first), same as the API.
	slices.SortFunc(target.Items, func(i, j *aliases.Alias) int {
		return j.CreatedTime.Compare(i.CreatedTime)
	})
	// Finally, since we made at least 2 requests to the server to fulfill this
	// function call, resp.Body and resp.Map will only contain the most recent response.
	// Overwrite them with the true response.
	target.GetResponse().Body.Reset()
	if err := json.NewEncoder(target.GetResponse().Body).Encode(target); err != nil {
		return nil, fmt.Errorf("error encoding final JSON list response: %w", err)
	}
	if err := json.Unmarshal(target.GetResponse().Body.Bytes(), &target.GetResponse().Map); err != nil {
		return nil, fmt.Errorf("error encoding final map list response: %w", err)
	}
	// Note: the HTTP response body is consumed by resp.Decode in the loop,
	// so it doesn't need to be updated (it will always be, and has always been, empty).
	return target, nil
}
