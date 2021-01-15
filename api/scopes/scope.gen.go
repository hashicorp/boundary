// Code generated by "make api"; DO NOT EDIT.
package scopes

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/hashicorp/boundary/api"
)

type Scope struct {
	Id                          string              `json:"id,omitempty"`
	ScopeId                     string              `json:"scope_id,omitempty"`
	Scope                       *ScopeInfo          `json:"scope,omitempty"`
	Name                        string              `json:"name,omitempty"`
	Description                 string              `json:"description,omitempty"`
	CreatedTime                 time.Time           `json:"created_time,omitempty"`
	UpdatedTime                 time.Time           `json:"updated_time,omitempty"`
	Version                     uint32              `json:"version,omitempty"`
	Type                        string              `json:"type,omitempty"`
	AuthorizedActions           []string            `json:"authorized_actions,omitempty"`
	CollectionAuthorizedActions map[string][]string `json:"collection_authorized_actions,omitempty"`

	response *api.Response
}

func (n Scope) ResponseBody() *bytes.Buffer {
	return n.response.Body
}

func (n Scope) ResponseMap() map[string]interface{} {
	return n.response.Map
}

func (n Scope) ResponseStatus() int {
	return n.response.HttpResponse().StatusCode
}

type ScopeReadResult struct {
	Item     *Scope
	response *api.Response
}

func (n ScopeReadResult) GetItem() interface{} {
	return n.Item
}

func (n ScopeReadResult) GetResponseBody() *bytes.Buffer {
	return n.response.Body
}

func (n ScopeReadResult) GetResponseMap() map[string]interface{} {
	return n.response.Map
}

type (
	ScopeCreateResult = ScopeReadResult
	ScopeUpdateResult = ScopeReadResult
)

type ScopeDeleteResult struct {
	response *api.Response
}

func (n ScopeDeleteResult) GetResponseBody() *bytes.Buffer {
	return n.response.Body
}

func (n ScopeDeleteResult) GetResponseMap() map[string]interface{} {
	return n.response.Map
}

type ScopeListResult struct {
	Items    []*Scope
	response *api.Response
}

func (n ScopeListResult) GetItems() interface{} {
	return n.Items
}

func (n ScopeListResult) GetResponseBody() *bytes.Buffer {
	return n.response.Body
}

func (n ScopeListResult) GetResponseMap() map[string]interface{} {
	return n.response.Map
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

func (c *Client) Create(ctx context.Context, scopeId string, opt ...Option) (*ScopeCreateResult, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("empty scopeId value passed into Create request")
	}

	opts, apiOpts := getOpts(opt...)

	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts.postMap["scope_id"] = scopeId

	req, err := c.client.NewRequest(ctx, "POST", "scopes", opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating Create request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during Create call: %w", err)
	}

	target := new(ScopeCreateResult)
	target.Item = new(Scope)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding Create response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}

func (c *Client) Read(ctx context.Context, scopeId string, opt ...Option) (*ScopeReadResult, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("empty scopeId value passed into Read request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("scopes/%s", scopeId), nil, apiOpts...)
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

	target := new(ScopeReadResult)
	target.Item = new(Scope)
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

func (c *Client) Update(ctx context.Context, scopeId string, version uint32, opt ...Option) (*ScopeUpdateResult, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("empty scopeId value passed into Update request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into Update request and automatic versioning not specified")
		}
		existingTarget, existingErr := c.Read(ctx, scopeId, append([]Option{WithSkipCurlOutput(true)}, opt...)...)
		if existingErr != nil {
			if api.AsServerError(existingErr) != nil {
				return nil, fmt.Errorf("error from controller when performing initial check-and-set read: %w", existingErr)
			}
			return nil, fmt.Errorf("error performing initial check-and-set read: %w", existingErr)
		}
		if existingTarget == nil {
			return nil, errors.New("nil resource response found when performing initial check-and-set read")
		}
		if existingTarget.Item == nil {
			return nil, errors.New("nil resource found when performing initial check-and-set read")
		}
		version = existingTarget.Item.Version
	}

	opts.postMap["version"] = version

	req, err := c.client.NewRequest(ctx, "PATCH", fmt.Sprintf("scopes/%s", scopeId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating Update request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during Update call: %w", err)
	}

	target := new(ScopeUpdateResult)
	target.Item = new(Scope)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding Update response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}

func (c *Client) Delete(ctx context.Context, scopeId string, opt ...Option) (*ScopeDeleteResult, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("empty scopeId value passed into Delete request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "DELETE", fmt.Sprintf("scopes/%s", scopeId), nil, apiOpts...)
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

	target := &ScopeDeleteResult{
		response: resp,
	}
	return target, nil
}

func (c *Client) List(ctx context.Context, scopeId string, opt ...Option) (*ScopeListResult, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("empty scopeId value passed into List request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)
	opts.queryMap["scope_id"] = scopeId

	req, err := c.client.NewRequest(ctx, "GET", "scopes", nil, apiOpts...)
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

	target := new(ScopeListResult)
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
