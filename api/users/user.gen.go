// Code generated by "make api"; DO NOT EDIT.
package users

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
)

type User struct {
	Id                string            `json:"id,omitempty"`
	ScopeId           string            `json:"scope_id,omitempty"`
	Scope             *scopes.ScopeInfo `json:"scope,omitempty"`
	Name              string            `json:"name,omitempty"`
	Description       string            `json:"description,omitempty"`
	CreatedTime       time.Time         `json:"created_time,omitempty"`
	UpdatedTime       time.Time         `json:"updated_time,omitempty"`
	Version           uint32            `json:"version,omitempty"`
	AccountIds        []string          `json:"account_ids,omitempty"`
	Accounts          []*Account        `json:"accounts,omitempty"`
	AuthorizedActions []string          `json:"authorized_actions,omitempty"`

	response *api.Response
}

type UserReadResult struct {
	Item     *User
	response *api.Response
}

func (n UserReadResult) GetItem() interface{} {
	return n.Item
}

func (n UserReadResult) GetResponse() *api.Response {
	return n.response
}

type (
	UserCreateResult = UserReadResult
	UserUpdateResult = UserReadResult
)

type UserDeleteResult struct {
	response *api.Response
}

// GetItem will always be nil for UserDeleteResult
func (n UserDeleteResult) GetItem() interface{} {
	return nil
}

func (n UserDeleteResult) GetResponse() *api.Response {
	return n.response
}

type UserListResult struct {
	Items    []*User
	response *api.Response
}

func (n UserListResult) GetItems() interface{} {
	return n.Items
}

func (n UserListResult) GetResponse() *api.Response {
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

func (c *Client) Create(ctx context.Context, scopeId string, opt ...Option) (*UserCreateResult, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("empty scopeId value passed into Create request")
	}

	opts, apiOpts := getOpts(opt...)

	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts.postMap["scope_id"] = scopeId

	req, err := c.client.NewRequest(ctx, "POST", "users", opts.postMap, apiOpts...)
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

	target := new(UserCreateResult)
	target.Item = new(User)
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

func (c *Client) Read(ctx context.Context, userId string, opt ...Option) (*UserReadResult, error) {
	if userId == "" {
		return nil, fmt.Errorf("empty userId value passed into Read request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("users/%s", userId), nil, apiOpts...)
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

	target := new(UserReadResult)
	target.Item = new(User)
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

func (c *Client) Update(ctx context.Context, userId string, version uint32, opt ...Option) (*UserUpdateResult, error) {
	if userId == "" {
		return nil, fmt.Errorf("empty userId value passed into Update request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into Update request and automatic versioning not specified")
		}
		existingTarget, existingErr := c.Read(ctx, userId, append([]Option{WithSkipCurlOutput(true)}, opt...)...)
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

	req, err := c.client.NewRequest(ctx, "PATCH", fmt.Sprintf("users/%s", userId), opts.postMap, apiOpts...)
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

	target := new(UserUpdateResult)
	target.Item = new(User)
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

func (c *Client) Delete(ctx context.Context, userId string, opt ...Option) (*UserDeleteResult, error) {
	if userId == "" {
		return nil, fmt.Errorf("empty userId value passed into Delete request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "DELETE", fmt.Sprintf("users/%s", userId), nil, apiOpts...)
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

	target := &UserDeleteResult{
		response: resp,
	}
	return target, nil
}

func (c *Client) List(ctx context.Context, scopeId string, opt ...Option) (*UserListResult, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("empty scopeId value passed into List request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)
	opts.queryMap["scope_id"] = scopeId

	req, err := c.client.NewRequest(ctx, "GET", "users", nil, apiOpts...)
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

	target := new(UserListResult)
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

func (c *Client) AddAccounts(ctx context.Context, userId string, version uint32, accountIds []string, opt ...Option) (*UserUpdateResult, error) {
	if userId == "" {
		return nil, fmt.Errorf("empty userId value passed into AddAccounts request")
	}
	if len(accountIds) == 0 {
		return nil, errors.New("empty accountIds passed into AddAccounts request")
	}
	if c.client == nil {
		return nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into AddAccounts request")
		}
		existingTarget, existingErr := c.Read(ctx, userId, append([]Option{WithSkipCurlOutput(true)}, opt...)...)
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
	opts.postMap["account_ids"] = accountIds

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("users/%s:add-accounts", userId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating AddAccounts request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during AddAccounts call: %w", err)
	}

	target := new(UserUpdateResult)
	target.Item = new(User)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding AddAccounts response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}

func (c *Client) SetAccounts(ctx context.Context, userId string, version uint32, accountIds []string, opt ...Option) (*UserUpdateResult, error) {
	if userId == "" {
		return nil, fmt.Errorf("empty userId value passed into SetAccounts request")
	}

	if c.client == nil {
		return nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into SetAccounts request")
		}
		existingTarget, existingErr := c.Read(ctx, userId, append([]Option{WithSkipCurlOutput(true)}, opt...)...)
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
	opts.postMap["account_ids"] = accountIds

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("users/%s:set-accounts", userId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating SetAccounts request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during SetAccounts call: %w", err)
	}

	target := new(UserUpdateResult)
	target.Item = new(User)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding SetAccounts response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}

func (c *Client) RemoveAccounts(ctx context.Context, userId string, version uint32, accountIds []string, opt ...Option) (*UserUpdateResult, error) {
	if userId == "" {
		return nil, fmt.Errorf("empty userId value passed into RemoveAccounts request")
	}
	if len(accountIds) == 0 {
		return nil, errors.New("empty accountIds passed into RemoveAccounts request")
	}
	if c.client == nil {
		return nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into RemoveAccounts request")
		}
		existingTarget, existingErr := c.Read(ctx, userId, append([]Option{WithSkipCurlOutput(true)}, opt...)...)
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
	opts.postMap["account_ids"] = accountIds

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("users/%s:remove-accounts", userId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating RemoveAccounts request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during RemoveAccounts call: %w", err)
	}

	target := new(UserUpdateResult)
	target.Item = new(User)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding RemoveAccounts response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}
