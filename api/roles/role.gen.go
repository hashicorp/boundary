// Code generated by "make api"; DO NOT EDIT.
package roles

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/scopes"
)

type Role struct {
	Id           string            `json:"id,omitempty"`
	Scope        *scopes.ScopeInfo `json:"scope,omitempty"`
	Name         string            `json:"name,omitempty"`
	Description  string            `json:"description,omitempty"`
	CreatedTime  time.Time         `json:"created_time,omitempty"`
	UpdatedTime  time.Time         `json:"updated_time,omitempty"`
	Disabled     bool              `json:"disabled,omitempty"`
	GrantScopeId string            `json:"grant_scope_id,omitempty"`
	Version      uint32            `json:"version,omitempty"`
	PrincipalIds []string          `json:"principal_ids,omitempty"`
	Principals   []*Principal      `json:"principals,omitempty"`
	GrantStrings []string          `json:"grant_strings,omitempty"`
	Grants       []*Grant          `json:"grants,omitempty"`
}

type roleClient struct {
	client *api.Client
}

func NewRoleClient(c *api.Client) *roleClient {
	return &roleClient{client: c}
}

func (c *roleClient) Create(ctx context.Context, opt ...Option) (*Role, *api.Error, error) {
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("roles"), opts.valueMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during Create call: %w", err)
	}

	target := new(Role)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Create response: %w", err)
	}

	return target, apiErr, nil
}

func (c *roleClient) Read(ctx context.Context, roleId string, opt ...Option) (*Role, *api.Error, error) {
	if roleId == "" {
		return nil, nil, fmt.Errorf("empty roleId value passed into Read request")
	}

	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	_, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("roles/%s", roleId), nil, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Read request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during Read call: %w", err)
	}

	target := new(Role)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Read response: %w", err)
	}

	return target, apiErr, nil
}

func (c *roleClient) Update(ctx context.Context, roleId string, version uint32, opt ...Option) (*Role, *api.Error, error) {
	if roleId == "" {
		return nil, nil, fmt.Errorf("empty roleId value passed into Update request")
	}
	if version == 0 {
		return nil, nil, errors.New("zero version number passed into Update request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "PATCH", fmt.Sprintf("roles/%s", roleId), opts.valueMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Update request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during Update call: %w", err)
	}

	target := new(Role)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Update response: %w", err)
	}

	return target, apiErr, nil
}

func (c *roleClient) Delete(ctx context.Context, roleId string, opt ...Option) (bool, *api.Error, error) {
	if roleId == "" {
		return false, nil, fmt.Errorf("empty roleId value passed into Delete request")
	}

	if c.client == nil {
		return false, nil, fmt.Errorf("nil client")
	}

	_, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "DELETE", fmt.Sprintf("roles/%s", roleId), nil, apiOpts...)
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

func (c *roleClient) List(ctx context.Context, opt ...Option) ([]*Role, *api.Error, error) {
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	_, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("roles"), nil, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating List request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during List call: %w", err)
	}

	type listResponse struct {
		Items []*Role
	}
	target := &listResponse{}
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding List response: %w", err)
	}

	return target.Items, apiErr, nil
}
