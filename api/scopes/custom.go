package scopes

import (
	"context"
	"fmt"
	"net/url"

	"github.com/hashicorp/boundary/api"
)

type KeyListResult struct {
	Items    []*Key
	response *api.Response
}

func (n KeyListResult) GetItems() []*Key {
	return n.Items
}

func (n KeyListResult) GetResponse() *api.Response {
	return n.response
}

type KeysRotateResult struct {
	response *api.Response
}

func (n KeysRotateResult) GetResponse() *api.Response {
	return n.response
}

func (c *Client) ListKeys(ctx context.Context, scopeId string, opt ...Option) (*KeyListResult, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("empty scopeId value passed into ListKeys request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", "scopes/"+url.PathEscape(scopeId)+":list-keys", nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating ListKeys request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during ListKeys call: %w", err)
	}

	target := new(KeyListResult)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, fmt.Errorf("error decoding ListKeys response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}

func (c *Client) RotateKeys(ctx context.Context, scopeId string, rewrapKeys bool, opt ...Option) (*KeysRotateResult, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("empty scopeId value passed into RotateKeys request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	opts.postMap["scope_id"] = scopeId
	opts.postMap["rewrap"] = rewrapKeys

	req, err := c.client.NewRequest(ctx, "POST", "scopes:rotate-keys", opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating RotateKeys request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during RotateKeys call: %w", err)
	}

	apiErr, err := resp.Decode(nil)
	if err != nil {
		return nil, fmt.Errorf("error decoding RotateKeys response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}

	target := &KeysRotateResult{
		response: resp,
	}
	return target, nil
}
