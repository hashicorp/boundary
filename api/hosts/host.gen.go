// Code generated by "make api"; DO NOT EDIT.
package hosts

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/scopes"
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

type hostClient struct {
	client *api.Client
}

func NewHostClient(c *api.Client) *hostClient {
	return &hostClient{client: c}
}

func (c *hostClient) Create(ctx context.Context, opt ...Option) (*Host, *api.Error, error) {
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("hosts"), opts.valueMap, apiOpts...)
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

func (c *hostClient) Read(ctx context.Context, hostId string, opt ...Option) (*Host, *api.Error, error) {
	if hostId == "" {
		return nil, nil, fmt.Errorf("empty hostId value passed into Read request")
	}

	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	_, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("hosts/%s", hostId), nil, apiOpts...)
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

func (c *hostClient) Update(ctx context.Context, hostId string, version uint32, opt ...Option) (*Host, *api.Error, error) {
	if hostId == "" {
		return nil, nil, fmt.Errorf("empty hostId value passed into Update request")
	}
	if version == 0 {
		return nil, nil, errors.New("zero version number passed into Update request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "PATCH", fmt.Sprintf("hosts"), opts.valueMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Update request: %w", err)
	}

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

func (c *hostClient) Delete(ctx context.Context, hostId string, opt ...Option) (bool, *api.Error, error) {
	if hostId == "" {
		return false, nil, fmt.Errorf("empty hostId value passed into Delete request")
	}

	if c.client == nil {
		return false, nil, fmt.Errorf("nil client")
	}

	_, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "DELETE", fmt.Sprintf("hosts/%s", hostId), nil, apiOpts...)
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

func (c *hostClient) List(ctx context.Context, opt ...Option) ([]Host, *api.Error, error) {
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	_, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("hosts"), nil, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating List request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during List call: %w", err)
	}

	type listResponse struct {
		Items []Host
	}
	target := &listResponse{}
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding List response: %w", err)
	}

	return target.Items, apiErr, nil
}

type Option func(*options)

type options struct {
	valueMap    map[string]interface{}
	withScopeId string
}

func getDefaultOptions() options {
	return options{
		valueMap: make(map[string]interface{}),
	}
}

func getOpts(opt ...Option) (options, []api.Option) {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	var apiOpts []api.Option
	if opts.withScopeId != "" {
		apiOpts = append(apiOpts, api.WithScopeId(opts.withScopeId))
	}
	return opts, apiOpts
}

func DefaultScopeId() Option {
	return func(o *options) {
		o.withScopeId = ""
	}
}

func WithScopeId(id string) Option {
	return func(o *options) {
		o.withScopeId = id
	}
}

func WithName(inName string) Option {
	return func(o *options) {
		o.valueMap["name"] = inName
	}
}

func DefaultName() Option {
	return func(o *options) {
		o.valueMap["name"] = nil
	}
}

func WithDescription(inDescription string) Option {
	return func(o *options) {
		o.valueMap["description"] = inDescription
	}
}

func DefaultDescription() Option {
	return func(o *options) {
		o.valueMap["description"] = nil
	}
}

func WithDisabled(inDisabled bool) Option {
	return func(o *options) {
		o.valueMap["disabled"] = inDisabled
	}
}

func DefaultDisabled() Option {
	return func(o *options) {
		o.valueMap["disabled"] = nil
	}
}

func WithAddress(inAddress string) Option {
	return func(o *options) {
		o.valueMap["address"] = inAddress
	}
}

func DefaultAddress() Option {
	return func(o *options) {
		o.valueMap["address"] = nil
	}
}
