// Code generated by "make api"; DO NOT EDIT.
package users

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/scopes"
)

type User struct {
	Id          string            `json:"id,omitempty"`
	Scope       *scopes.ScopeInfo `json:"scope,omitempty"`
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	CreatedTime time.Time         `json:"created_time,omitempty"`
	UpdatedTime time.Time         `json:"updated_time,omitempty"`
	Disabled    bool              `json:"disabled,omitempty"`
}

type userClient struct {
	client *api.Client
}

func NewUserClient(c *api.Client) *userClient {
	return &userClient{client: c}
}

func (c *userClient) Create(ctx context.Context, opt ...Option) (*User, *api.Error, error) {
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("users"), opts.valueMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during Create call: %w", err)
	}

	target := new(User)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Create response: %w", err)
	}

	return target, apiErr, nil
}

func (c *userClient) Read(ctx context.Context, userId string, opt ...Option) (*User, *api.Error, error) {
	if userId == "" {
		return nil, nil, fmt.Errorf("empty userId value passed into Read request")
	}

	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	_, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("users/%s", userId), nil, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Read request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during Read call: %w", err)
	}

	target := new(User)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Read response: %w", err)
	}

	return target, apiErr, nil
}

func (c *userClient) Update(ctx context.Context, userId string, version uint32, opt ...Option) (*User, *api.Error, error) {
	if userId == "" {
		return nil, nil, fmt.Errorf("empty userId value passed into Update request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "PATCH", fmt.Sprintf("users/%s", userId), opts.valueMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Update request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during Update call: %w", err)
	}

	target := new(User)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Update response: %w", err)
	}

	return target, apiErr, nil
}

func (c *userClient) Delete(ctx context.Context, userId string, opt ...Option) (bool, *api.Error, error) {
	if userId == "" {
		return false, nil, fmt.Errorf("empty userId value passed into Delete request")
	}

	if c.client == nil {
		return false, nil, fmt.Errorf("nil client")
	}

	_, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "DELETE", fmt.Sprintf("users/%s", userId), nil, apiOpts...)
	if err != nil {
		return false, nil, fmt.Errorf("error creating Delete request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("error performing client request during Delete call: %w", err)
	}

	type deleteResponse struct {
		Existed bool
	}
	target := &deleteResponse{}
	apiErr, err := resp.Decode(target)
	if err != nil {
		return false, nil, fmt.Errorf("error decoding Delete response: %w", err)
	}

	return target.Existed, apiErr, nil
}

func (c *userClient) List(ctx context.Context, opt ...Option) ([]*User, *api.Error, error) {
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	_, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("users"), nil, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating List request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during List call: %w", err)
	}

	type listResponse struct {
		Items []*User
	}
	target := &listResponse{}
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding List response: %w", err)
	}

	return target.Items, apiErr, nil
}
