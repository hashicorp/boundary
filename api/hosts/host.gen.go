// Code generated by "make api"; DO NOT EDIT.
package hosts

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
)

type Host struct {
	Id          string            `json:"id,omitempty"`
	Scope       *scopes.ScopeInfo `json:"scope,omitempty"`
	Type        string            `json:"type,omitempty"`
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	CreatedTime time.Time         `json:"created_time,omitempty"`
	UpdatedTime time.Time         `json:"updated_time,omitempty"`
	Disabled    bool              `json:"disabled,omitempty"`
	Address     string            `json:"address,omitempty"`
}

type hostsClient struct {
	client *api.Client
}

func NewHostsClient(c *api.Client) *hostsClient {
	return &hostsClient{client: c}
}

func (c *hostsClient) Create(ctx context.Context, hostCatalogId string, opt ...Option) (*Host, *api.Error, error) {
	if hostCatalogId == "" {
		return nil, nil, fmt.Errorf("empty hostCatalogId value passed into Create request")
	}

	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("host-catalogs/%s/hosts", hostCatalogId), opts.valueMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during Create call: %w", err)
	}

	target := new(Host)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Create response: %w", err)
	}

	return target, apiErr, nil
}

func (c *hostsClient) Read(ctx context.Context, hostCatalogId string, hostId string, opt ...Option) (*Host, *api.Error, error) {
	if hostCatalogId == "" {
		return nil, nil, fmt.Errorf("empty hostCatalogId value passed into Read request")
	}

	if hostId == "" {
		return nil, nil, fmt.Errorf("empty hostId value passed into Read request")
	}

	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	_, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("host-catalogs/%s/hosts/%s", hostCatalogId, hostId), nil, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Read request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during Read call: %w", err)
	}

	target := new(Host)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Read response: %w", err)
	}

	return target, apiErr, nil
}

func (c *hostsClient) Update(ctx context.Context, hostCatalogId string, hostId string, version uint32, opt ...Option) (*Host, *api.Error, error) {
	if hostCatalogId == "" {
		return nil, nil, fmt.Errorf("empty hostCatalogId value passed into Update request")
	}
	if hostId == "" {
		return nil, nil, fmt.Errorf("empty hostId value passed into Update request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "PATCH", fmt.Sprintf("host-catalogs/%s/hosts/%s", hostCatalogId, hostId), opts.valueMap, apiOpts...)
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

	target := new(Host)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Update response: %w", err)
	}

	return target, apiErr, nil
}

func (c *hostsClient) Delete(ctx context.Context, hostCatalogId string, hostId string, opt ...Option) (bool, *api.Error, error) {
	if hostCatalogId == "" {
		return false, nil, fmt.Errorf("empty hostCatalogId value passed into Delete request")
	}

	if hostId == "" {
		return false, nil, fmt.Errorf("empty hostId value passed into Delete request")
	}

	if c.client == nil {
		return false, nil, fmt.Errorf("nil client")
	}

	_, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "DELETE", fmt.Sprintf("host-catalogs/%s/hosts/%s", hostCatalogId, hostId), nil, apiOpts...)
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

func (c *hostsClient) List(ctx context.Context, hostCatalogId string, opt ...Option) ([]*Host, *api.Error, error) {
	if hostCatalogId == "" {
		return nil, nil, fmt.Errorf("empty hostCatalogId value passed into List request")
	}

	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	_, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("host-catalogs/%s/hosts", hostCatalogId), nil, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating List request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during List call: %w", err)
	}

	type listResponse struct {
		Items []*Host
	}
	target := &listResponse{}
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding List response: %w", err)
	}

	return target.Items, apiErr, nil
}
