// Code generated by "make api"; DO NOT EDIT.
package users

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/kr/pretty"

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
	Version     uint32            `json:"version,omitempty"`
}

type usersClient struct {
	client *api.Client
}

func NewUsersClient(c *api.Client) *usersClient {
	return &usersClient{client: c}
}

func (c *usersClient) Create(ctx context.Context, opt ...Option) (*User, *api.Error, error) {
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "POST", "users", opts.valueMap, apiOpts...)
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

func (c *usersClient) Read(ctx context.Context, userId string, opt ...Option) (*User, *api.Error, error) {
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

func (c *usersClient) Update(ctx context.Context, userId string, version uint32, opt ...Option) (*User, *api.Error, error) {
	if userId == "" {
		return nil, nil, fmt.Errorf("empty userId value passed into Update request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, nil, errors.New("zero version number passed into Update request and automatic versioning not specified")
		}
		existingTarget, existingApiErr, existingErr := c.Read(ctx, userId, opt...)
		if existingErr != nil {
			return nil, nil, fmt.Errorf("error performing initial check-and-set read: %w", existingErr)
		}
		if existingApiErr != nil {
			return nil, nil, fmt.Errorf("error from controller when performing initial check-and-set read: %s", pretty.Sprint(existingApiErr))
		}
		if existingTarget == nil {
			return nil, nil, errors.New("nil resource found when performing initial check-and-set read")
		}
		version = existingTarget.Version
	}

	req, err := c.client.NewRequest(ctx, "PATCH", fmt.Sprintf("users/%s", userId), opts.valueMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Update request: %w", err)
	}

	q := url.Values{}
	q.Add("version", fmt.Sprintf("%d", version))
	req.URL.RawQuery = q.Encode()

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

func (c *usersClient) Delete(ctx context.Context, userId string, opt ...Option) (bool, *api.Error, error) {
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

func (c *usersClient) List(ctx context.Context, opt ...Option) ([]*User, *api.Error, error) {
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	_, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", "users", nil, apiOpts...)
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
