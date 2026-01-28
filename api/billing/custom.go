// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package billing

import (
	"context"
	"fmt"
	"net/url"

	"github.com/hashicorp/boundary/api"
)

type MonthlyActiveUsersResult struct {
	Items    []*ActiveUsers
	response *api.Response
}

func (r MonthlyActiveUsersResult) GetItems() any {
	return r.Items
}

func (r MonthlyActiveUsersResult) GetResponse() *api.Response {
	return r.response
}

func (c *Client) MonthlyActiveUsers(ctx context.Context, opt ...Option) (*MonthlyActiveUsersResult, error) {
	opts, apiOpts := getOpts(opt...)

	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	req, err := c.client.NewRequest(ctx, "GET", "billing:monthly-active-users", nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating MonthlyActiveUsers request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during MonthlyActiveUsers call: %w", err)
	}

	mau := new(MonthlyActiveUsersResult)
	mau.Items = []*ActiveUsers{}
	apiErr, err := resp.Decode(mau)
	if err != nil {
		return nil, fmt.Errorf("error decoding MonthlyActiveUsers response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	mau.response = resp
	return mau, nil
}
