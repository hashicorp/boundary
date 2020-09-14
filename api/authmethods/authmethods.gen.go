// Code generated by "make api"; DO NOT EDIT.
package authmethods

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/kr/pretty"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
)

type AuthMethod struct {
	Id          string                 `json:"id,omitempty"`
	ScopeId     string                 `json:"scope_id,omitempty"`
	Scope       *scopes.ScopeInfo      `json:"scope,omitempty"`
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	CreatedTime time.Time              `json:"created_time,omitempty"`
	UpdatedTime time.Time              `json:"updated_time,omitempty"`
	Version     uint32                 `json:"version,omitempty"`
	Type        string                 `json:"type,omitempty"`
	Attributes  map[string]interface{} `json:"attributes,omitempty"`

	lastResponseBody *bytes.Buffer
	lastResponseMap  map[string]interface{}
}

func (n AuthMethod) LastResponseBody() *bytes.Buffer {
	return n.lastResponseBody
}

func (n AuthMethod) LastResponseMap() map[string]interface{} {
	return n.lastResponseMap
}

type AuthMethodReadResult struct {
	Item             *AuthMethod
	lastResponseBody *bytes.Buffer
	lastResponseMap  map[string]interface{}
}

func (n AuthMethodReadResult) LastResponseBody() *bytes.Buffer {
	return n.lastResponseBody
}

func (n AuthMethodReadResult) LastResponseMap() map[string]interface{} {
	return n.lastResponseMap
}

type AuthMethodCreateResult = AuthMethodReadResult
type AuthMethodUpdateResult = AuthMethodReadResult

type AuthMethodDeleteResult struct {
	lastResponseBody *bytes.Buffer
	lastResponseMap  map[string]interface{}
}

func (n AuthMethodDeleteResult) LastResponseBody() *bytes.Buffer {
	return n.lastResponseBody
}

func (n AuthMethodDeleteResult) LastResponseMap() map[string]interface{} {
	return n.lastResponseMap
}

type AuthMethodListResult struct {
	Items            []*AuthMethod
	lastResponseBody *bytes.Buffer
	lastResponseMap  map[string]interface{}
}

func (n AuthMethodListResult) LastResponseBody() *bytes.Buffer {
	return n.lastResponseBody
}

func (n AuthMethodListResult) LastResponseMap() map[string]interface{} {
	return n.lastResponseMap
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

func (c *Client) Create(ctx context.Context, resourceType string, scopeId string, opt ...Option) (*AuthMethodCreateResult, *api.Error, error) {
	if scopeId == "" {
		return nil, nil, fmt.Errorf("empty scopeId value passed into Create request")
	}

	opts, apiOpts := getOpts(opt...)

	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}
	if resourceType == "" {
		return nil, nil, fmt.Errorf("empty resourceType value passed into Create request")
	} else {
		opts.postMap["type"] = resourceType
	}

	opts.postMap["scope_id"] = scopeId

	req, err := c.client.NewRequest(ctx, "POST", "auth-methods", opts.postMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Create request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during Create call: %w", err)
	}

	target := new(AuthMethodCreateResult)
	target.Item = new(AuthMethod)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Create response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	target.lastResponseBody = resp.Body
	target.lastResponseMap = resp.Map
	return target, apiErr, nil
}

func (c *Client) Read(ctx context.Context, authMethodId string, opt ...Option) (*AuthMethodReadResult, *api.Error, error) {
	if authMethodId == "" {
		return nil, nil, fmt.Errorf("empty  authMethodId value passed into Read request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("auth-methods/%s", authMethodId), nil, apiOpts...)
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

	target := new(AuthMethodReadResult)
	target.Item = new(AuthMethod)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Read response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	target.lastResponseBody = resp.Body
	target.lastResponseMap = resp.Map
	return target, apiErr, nil
}

func (c *Client) Update(ctx context.Context, authMethodId string, version uint32, opt ...Option) (*AuthMethodUpdateResult, *api.Error, error) {
	if authMethodId == "" {
		return nil, nil, fmt.Errorf("empty authMethodId value passed into Update request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, nil, errors.New("zero version number passed into Update request and automatic versioning not specified")
		}
		existingTarget, existingApiErr, existingErr := c.Read(ctx, authMethodId, opt...)
		if existingErr != nil {
			return nil, nil, fmt.Errorf("error performing initial check-and-set read: %w", existingErr)
		}
		if existingApiErr != nil {
			return nil, nil, fmt.Errorf("error from controller when performing initial check-and-set read: %s", pretty.Sprint(existingApiErr))
		}
		if existingTarget == nil {
			return nil, nil, errors.New("nil resource response found when performing initial check-and-set read")
		}
		if existingTarget.Item == nil {
			return nil, nil, errors.New("nil resource found when performing initial check-and-set read")
		}
		version = existingTarget.Item.Version
	}

	opts.postMap["version"] = version

	req, err := c.client.NewRequest(ctx, "PATCH", fmt.Sprintf("auth-methods/%s", authMethodId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Update request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during Update call: %w", err)
	}

	target := new(AuthMethodUpdateResult)
	target.Item = new(AuthMethod)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Update response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	target.lastResponseBody = resp.Body
	target.lastResponseMap = resp.Map
	return target, apiErr, nil
}

func (c *Client) Delete(ctx context.Context, authMethodId string, opt ...Option) (*AuthMethodDeleteResult, *api.Error, error) {
	if authMethodId == "" {
		return nil, nil, fmt.Errorf("empty authMethodId value passed into Delete request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "DELETE", fmt.Sprintf("auth-methods/%s", authMethodId), nil, apiOpts...)
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

	target := &AuthMethodDeleteResult{
		lastResponseBody: resp.Body,
		lastResponseMap:  resp.Map,
	}
	return target, nil, nil
}

func (c *Client) List(ctx context.Context, scopeId string, opt ...Option) (*AuthMethodListResult, *api.Error, error) {
	if scopeId == "" {
		return nil, nil, fmt.Errorf("empty scopeId value passed into List request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)
	opts.queryMap["scope_id"] = scopeId

	req, err := c.client.NewRequest(ctx, "GET", "auth-methods", nil, apiOpts...)
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

	target := new(AuthMethodListResult)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding List response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	target.lastResponseBody = resp.Body
	target.lastResponseMap = resp.Map
	return target, apiErr, nil
}
