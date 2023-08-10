// Code generated by "make api"; DO NOT EDIT.
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package authtokens

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
)

type AuthToken struct {
	Id                      string            `json:"id,omitempty"`
	ScopeId                 string            `json:"scope_id,omitempty"`
	Scope                   *scopes.ScopeInfo `json:"scope,omitempty"`
	Token                   string            `json:"token,omitempty"`
	UserId                  string            `json:"user_id,omitempty"`
	AuthMethodId            string            `json:"auth_method_id,omitempty"`
	AccountId               string            `json:"account_id,omitempty"`
	CreatedTime             time.Time         `json:"created_time,omitempty"`
	UpdatedTime             time.Time         `json:"updated_time,omitempty"`
	ApproximateLastUsedTime time.Time         `json:"approximate_last_used_time,omitempty"`
	ExpirationTime          time.Time         `json:"expiration_time,omitempty"`
	AuthorizedActions       []string          `json:"authorized_actions,omitempty"`

	response *api.Response
}

type AuthTokenReadResult struct {
	Item     *AuthToken
	response *api.Response
}

func (n AuthTokenReadResult) GetItem() *AuthToken {
	return n.Item
}

func (n AuthTokenReadResult) GetResponse() *api.Response {
	return n.response
}

type AuthTokenUpdateResult = AuthTokenReadResult

type AuthTokenDeleteResult struct {
	response *api.Response
}

// GetItem will always be nil for AuthTokenDeleteResult
func (n AuthTokenDeleteResult) GetItem() interface{} {
	return nil
}

func (n AuthTokenDeleteResult) GetResponse() *api.Response {
	return n.response
}

type AuthTokenListResult struct {
	Items    []*AuthToken
	response *api.Response
}

func (n AuthTokenListResult) GetItems() []*AuthToken {
	return n.Items
}

func (n AuthTokenListResult) GetResponse() *api.Response {
	return n.response
}

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

func (c *Client) Read(ctx context.Context, id string, opt ...Option) (*AuthTokenReadResult, error) {
	if id == "" {
		return nil, fmt.Errorf("empty id value passed into Read request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("auth-tokens/%s", url.PathEscape(id)), nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating Read request: %w", err)
	}

	if len(opts.queryMap) > 0 {
		q := url.Values{}
		for k, v := range opts.queryMap {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	resp, err := c.client.Do(req, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during Read call: %w", err)
	}

	target := new(AuthTokenReadResult)
	target.Item = new(AuthToken)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding Read response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}

func (c *Client) Delete(ctx context.Context, id string, opt ...Option) (*AuthTokenDeleteResult, error) {
	if id == "" {
		return nil, fmt.Errorf("empty id value passed into Delete request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "DELETE", fmt.Sprintf("auth-tokens/%s", url.PathEscape(id)), nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating Delete request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during Delete call: %w", err)
	}

	apiErr, err := resp.Decode(nil)
	if err != nil {
		return nil, fmt.Errorf("error decoding Delete response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}

	target := &AuthTokenDeleteResult{
		response: resp,
	}
	return target, nil
}

func (c *Client) List(ctx context.Context, scopeId string, opt ...Option) (*AuthTokenListResult, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("empty scopeId value passed into List request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)
	opts.queryMap["scope_id"] = scopeId

	req, err := c.client.NewRequest(ctx, "GET", "auth-tokens", nil, apiOpts...)
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

	target := new(AuthTokenListResult)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, fmt.Errorf("error decoding List response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}
