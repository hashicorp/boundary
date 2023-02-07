// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package targets

import (
	"context"
	"fmt"
	"net/url"

	"github.com/hashicorp/boundary/api"
)

type SessionAuthorizationResult struct {
	Item     *SessionAuthorization
	response *api.Response
}

func (n SessionAuthorizationResult) GetItem() any {
	return n.Item
}

func (n SessionAuthorizationResult) GetResponse() *api.Response {
	return n.response
}

func (c *Client) AuthorizeSession(ctx context.Context, targetId string, opt ...Option) (*SessionAuthorizationResult, error) {
	opts, apiOpts := getOpts(opt...)

	if targetId == "" {
		if opts.postMap["name"] == nil {
			return nil, fmt.Errorf("empty target name provided to AuthorizeSession request")
		}
		scopeIdEmpty := opts.postMap["scope_id"] == nil
		scopeNameEmpty := opts.postMap["scope_name"] == nil
		switch {
		case scopeIdEmpty && scopeNameEmpty:
			return nil, fmt.Errorf("empty targetId value and no combination of target name and scope ID/name passed into AuthorizeSession request")
		case !scopeIdEmpty && !scopeNameEmpty:
			return nil, fmt.Errorf("both scope ID and scope name cannot be provided in AuthorizeSession request")
		default:
			// Name is not empty and only one of scope ID or name set
			targetId = opts.postMap["name"].(string)
		}
	}

	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("targets/%s:authorize-session", targetId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating AuthorizeSession request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during AuthorizeSession call: %w", err)
	}

	target := new(SessionAuthorizationResult)
	target.Item = new(SessionAuthorization)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding AuthorizeSession response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}
