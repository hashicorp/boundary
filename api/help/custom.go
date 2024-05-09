// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package help

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/api"
)

// Client is a client for this collection
type Client struct {
	client *api.Client
}

// Creates a new client for this collection. The submitted API client is cloned;
// modifications to it after generating this client will not have effect. If you
// need to make changes to the underlying API client, use ApiClient() to access
// it.
func NewClient(c *api.Client) *Client {
	return &Client{client: c.Clone()}
}

// ApiClient returns the underlying API client
func (c *Client) ApiClient() *api.Client {
	return c.client
}

type HelpResult struct {
	Answer   string `json:"answer"`
	response *api.Response
}

type helpRequest struct {
	Query string `json:"query"`
}

func (c *Client) Help(ctx context.Context, query string) (*HelpResult, error) {
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	req, err := c.client.NewRequest(ctx, "POST", "help", &helpRequest{Query: query})
	if err != nil {
		return nil, fmt.Errorf("error creating Help request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during Help call: %w", err)
	}

	h := new(HelpResult)
	apiErr, err := resp.Decode(h)
	if err != nil {
		return nil, fmt.Errorf("error decoding Help response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	h.response = resp
	return h, nil
}
