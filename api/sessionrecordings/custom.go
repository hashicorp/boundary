// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package sessionrecordings

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/hashicorp/boundary/api"
)

// Download will of course download the request session recording resource.
// Currently it always requests a mime-type of asciicast.
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
	opts.queryMap["mime_type"] = api.AsciiCastMimeType
	req.Header.Set("Accept", api.AsciiCastMimeType)

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
