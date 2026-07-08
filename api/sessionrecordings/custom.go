// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package sessionrecordings

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"

	"github.com/hashicorp/boundary/api"
)

// Download makes a Boundary request to download the requested session recording
// or media resource.
func (c *Client) Download(ctx context.Context, contentId string, opt ...Option) (io.ReadCloser, error) {
	switch {
	case contentId == "":
		return nil, fmt.Errorf("empty content id value passed into download request")
	case c.client == nil:
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", "session-recordings/"+url.PathEscape(contentId)+":download", nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating download request: %w", err)
	}
	mimeType, ok := opts.queryMap["mime_type"]
	if !ok {
		// Maintain backwards compatibility if mime-type isn't passed in.
		opts.queryMap["mime_type"] = api.AsciiCastMimeType
		mimeType = api.AsciiCastMimeType
	}
	req.Header.Set("Accept", mimeType)

	if len(opts.queryMap) > 0 {
		q := url.Values{}
		for k, v := range opts.queryMap {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during download call: %w", err)
	}
	if resp.StatusCode() >= 400 {
		resp.Body = new(bytes.Buffer)
		if _, err := resp.Body.ReadFrom(resp.HttpResponse().Body); err != nil {
			return nil, fmt.Errorf("error reading response body: %w", err)
		}
		if resp.Body.Len() > 0 {
			return nil, errors.New(resp.Body.String())
		}
		return nil, fmt.Errorf("error reading response body: status was %d", resp.StatusCode())
	}
	return resp.HttpResponse().Body, nil
}

// ReApplyStoragePolicy will reapply a storage policy to a session recording.
func (c *Client) ReApplyStoragePolicy(ctx context.Context, contentId string, opt ...Option) (*SessionRecordingReadResult, error) {
	switch {
	case contentId == "":
		return nil, fmt.Errorf("empty content id value passed into download request")
	case c.client == nil:
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "POST", "session-recordings/"+url.PathEscape(contentId)+":reapply-storage-policy", nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating reapply storage policy request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during ReApplyStoragePolicy call: %w", err)
	}

	target := new(SessionRecordingReadResult)
	target.Item = new(SessionRecording)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding ReApplyStoragePolicy response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.Response = resp
	return target, nil
}

// Export starts an export against a session recording connection.
func (c *Client) Export(ctx context.Context, connectionRecordingId, mimeType string, opt ...Option) (*ExportCreateResult, error) {
	switch {
	case connectionRecordingId == "":
		return nil, fmt.Errorf("empty connectionRecordingId")
	case mimeType == "":
		return nil, fmt.Errorf("empty mimeType")
	case c.client == nil:
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)
	opts.postMap["mime_type"] = mimeType

	req, err := c.client.NewRequest(ctx, "POST", "session-recordings/"+url.PathEscape(connectionRecordingId)+":export", opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
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
		return nil, fmt.Errorf("error performing client request: %w", err)
	}

	target := new(ExportCreateResult)
	target.Item = new(Export)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.Response = resp
	return target, nil
}

// ReadExport reads an export.
func (c *Client) ReadExport(ctx context.Context, exportId string, opt ...Option) (*ExportReadResult, error) {
	switch {
	case exportId == "":
		return nil, fmt.Errorf("empty exportId")
	case c.client == nil:
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", "session-recordings/"+url.PathEscape(exportId)+":export", nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
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
		return nil, fmt.Errorf("error performing client request: %w", err)
	}

	target := new(ExportReadResult)
	target.Item = new(Export)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.Response = resp
	return target, nil
}

// ListExports lists existing session recording exports.
func (c *Client) ListExports(ctx context.Context, scopeId string, opt ...Option) (*ExportListResult, error) {
	switch {
	case scopeId == "":
		return nil, fmt.Errorf("empty scopeId")
	case c.client == nil:
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)
	opts.queryMap["scope_id"] = scopeId

	requestPath := "session-recordings:list-exports"
	if opts.withResourcePathOverride != "" {
		requestPath = opts.withResourcePathOverride
	}

	req, err := c.client.NewRequest(ctx, "GET", requestPath, nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
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
		return nil, fmt.Errorf("error performing client request: %w", err)
	}

	target := new(ExportListResult)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.Response = resp
	if target.ResponseType == "complete" || target.ResponseType == "" {
		return target, nil
	}

	// In case we shortcut out due to client directed pagination, ensure these
	// are set.
	target.recursive = opts.withRecursive
	target.pageSize = opts.withPageSize
	target.scopeId = scopeId
	target.allRemovedIds = target.RemovedIds
	if opts.withClientDirectedPagination {
		return target, nil
	}

	allItems := make([]*Export, 0, target.EstItemCount)
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
		nextPage, err := c.ListExportsNextPage(ctx, currentPage, opt...)
		if err != nil {
			return nil, fmt.Errorf("error getting next page: %w", err)
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
	// If a SessionRecording has been updated and subsequently removed, we don't want
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
	slices.SortFunc(allItems, func(i, j *Export) int {
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

// ListExportsNextPage obtains the next page of an export listing process, given
// the current page.
func (c *Client) ListExportsNextPage(ctx context.Context, currentPage *ExportListResult, opt ...Option) (*ExportListResult, error) {
	if currentPage == nil {
		return nil, fmt.Errorf("empty currentPage")
	}
	if currentPage.scopeId == "" {
		return nil, fmt.Errorf("empty scopeId")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}
	if currentPage.ResponseType == "complete" || currentPage.ResponseType == "" {
		return nil, fmt.Errorf("no more pages available")
	}

	opts, apiOpts := getOpts(opt...)
	opts.queryMap["scope_id"] = currentPage.scopeId

	// Don't require them to re-specify recursive
	if currentPage.recursive {
		opts.queryMap["recursive"] = "true"
	}

	if currentPage.pageSize != 0 {
		opts.queryMap["page_size"] = strconv.FormatUint(uint64(currentPage.pageSize), 10)
	}

	requestPath := "session-recordings:list-exports"
	if opts.withResourcePathOverride != "" {
		requestPath = opts.withResourcePathOverride
	}

	req, err := c.client.NewRequest(ctx, "GET", requestPath, nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
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
		return nil, fmt.Errorf("error performing client request: %w", err)
	}

	nextPage := new(ExportListResult)
	apiErr, err := resp.Decode(nextPage)
	if err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}

	// Ensure values are carried forward to the next call
	nextPage.scopeId = currentPage.scopeId

	nextPage.recursive = currentPage.recursive

	nextPage.pageSize = currentPage.pageSize
	// Cache the removed IDs from this page
	nextPage.allRemovedIds = append(currentPage.allRemovedIds, nextPage.RemovedIds...)
	// Set the response body to the current response
	nextPage.Response = resp
	// If we're done iterating, pull the full set of removed IDs into the last
	// response
	if nextPage.ResponseType == "complete" {
		// Collect up the last values
		nextPage.RemovedIds = nextPage.allRemovedIds
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

// CancelExport cancels an existing export.
func (c *Client) CancelExport(ctx context.Context, exportId string, opt ...Option) (*ExportDeleteResult, error) {
	switch {
	case exportId == "":
		return nil, fmt.Errorf("empty exportId")
	case c.client == nil:
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "POST", "session-recordings/"+url.PathEscape(exportId)+":export:cancel", nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
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
		return nil, fmt.Errorf("error performing client request: %w", err)
	}

	apiErr, err := resp.Decode(nil)
	if err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}

	return &ExportDeleteResult{Response: resp}, nil
}
