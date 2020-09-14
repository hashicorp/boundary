// Code generated by "make api"; DO NOT EDIT.
package authtokens

import (
	"bytes"
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
	CreatedTime             time.Time         `json:"created_time,omitempty"`
	UpdatedTime             time.Time         `json:"updated_time,omitempty"`
	ApproximateLastUsedTime time.Time         `json:"approximate_last_used_time,omitempty"`
	ExpirationTime          time.Time         `json:"expiration_time,omitempty"`

	responseBody *bytes.Buffer
	responseMap  map[string]interface{}
}

func (n AuthToken) ResponseBody() *bytes.Buffer {
	return n.responseBody
}

func (n AuthToken) ResponseMap() map[string]interface{} {
	return n.responseMap
}

type AuthTokenReadResult struct {
	Item         *AuthToken
	responseBody *bytes.Buffer
	responseMap  map[string]interface{}
}

func (n AuthTokenReadResult) ResponseBody() *bytes.Buffer {
	return n.responseBody
}

func (n AuthTokenReadResult) ResponseMap() map[string]interface{} {
	return n.responseMap
}

type AuthTokenCreateResult = AuthTokenReadResult
type AuthTokenUpdateResult = AuthTokenReadResult

type AuthTokenDeleteResult struct {
	responseBody *bytes.Buffer
	responseMap  map[string]interface{}
}

func (n AuthTokenDeleteResult) ResponseBody() *bytes.Buffer {
	return n.responseBody
}

func (n AuthTokenDeleteResult) ResponseMap() map[string]interface{} {
	return n.responseMap
}

type AuthTokenListResult struct {
	Items        []*AuthToken
	responseBody *bytes.Buffer
	responseMap  map[string]interface{}
}

func (n AuthTokenListResult) ResponseBody() *bytes.Buffer {
	return n.responseBody
}

func (n AuthTokenListResult) ResponseMap() map[string]interface{} {
	return n.responseMap
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

func (c *Client) Read(ctx context.Context, authTokenId string, opt ...Option) (*AuthTokenReadResult, *api.Error, error) {
	if authTokenId == "" {
		return nil, nil, fmt.Errorf("empty  authTokenId value passed into Read request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("auth-tokens/%s", authTokenId), nil, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Read request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during Read call: %w", err)
	}

	target := new(AuthTokenReadResult)
	target.Item = new(AuthToken)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Read response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	target.responseBody = resp.Body
	target.responseMap = resp.Map
	return target, apiErr, nil
}

func (c *Client) Delete(ctx context.Context, authTokenId string, opt ...Option) (*AuthTokenDeleteResult, *api.Error, error) {
	if authTokenId == "" {
		return nil, nil, fmt.Errorf("empty authTokenId value passed into Delete request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "DELETE", fmt.Sprintf("auth-tokens/%s", authTokenId), nil, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Delete request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during Delete call: %w", err)
	}

	apiErr, err := resp.Decode(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Delete response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}

	target := &AuthTokenDeleteResult{
		responseBody: resp.Body,
		responseMap:  resp.Map,
	}
	return target, nil, nil
}

func (c *Client) List(ctx context.Context, scopeId string, opt ...Option) (*AuthTokenListResult, *api.Error, error) {
	if scopeId == "" {
		return nil, nil, fmt.Errorf("empty scopeId value passed into List request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)
	opts.queryMap["scope_id"] = scopeId

	req, err := c.client.NewRequest(ctx, "GET", "auth-tokens", nil, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating List request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during List call: %w", err)
	}

	target := new(AuthTokenListResult)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding List response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	target.responseBody = resp.Body
	target.responseMap = resp.Map
	return target, apiErr, nil
}
