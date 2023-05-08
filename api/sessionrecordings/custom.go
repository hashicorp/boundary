// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sessionrecordings

import (
	"context"
	"fmt"
	"io"
	"net/url"
)

const chunkSize = 64 * 1024 // assume we're using 64 KiB see: https://github.com/grpc/grpc.github.io/issues/371

func (c *Client) Download(ctx context.Context, contentId string, opt ...Option) (io.ReadCloser, error) {
	switch {
	case contentId == "":
		return nil, fmt.Errorf("empty content id value passed into download request")
	case c.client == nil:
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", "session_recordings/"+url.PathEscape(contentId)+":download", nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating download request: %w", err)
	}
	req.Header.Set("Accept", "application/x-asciicast")

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
	return resp.HttpResponse().Body, nil
}
