package targets

import (
	"bytes"
	"context"
	"fmt"
	"net/url"

	"github.com/hashicorp/boundary/api"
)

type SessionAuthorizationResult struct {
	Item         *SessionAuthorization
	responseBody *bytes.Buffer
	responseMap  map[string]interface{}
}

func (n SessionAuthorizationResult) GetItem() interface{} {
	return n.Item
}

func (n SessionAuthorizationResult) GetResponseBody() *bytes.Buffer {
	return n.responseBody
}

func (n SessionAuthorizationResult) GetResponseMap() map[string]interface{} {
	return n.responseMap
}

func (c *Client) Authorize(ctx context.Context, targetId string, opt ...Option) (*SessionAuthorizationResult, *api.Error, error) {
	if targetId == "" {
		return nil, nil, fmt.Errorf("empty targetId value passed into Authorize request")
	}

	opts, apiOpts := getOpts(opt...)

	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("targets/%s:authorize", targetId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Authorize request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during Authorize call: %w", err)
	}

	sar := new(SessionAuthorizationResult)
	sar.Item = new(SessionAuthorization)
	apiErr, err := resp.Decode(sar.Item)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Authorize response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	sar.responseBody = resp.Body
	sar.responseMap = resp.Map
	return sar, apiErr, nil
}
