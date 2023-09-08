// Code generated by "make api"; DO NOT EDIT.
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package hosts

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/plugins"
	"github.com/hashicorp/boundary/api/scopes"
)

type Host struct {
	Id                string                 `json:"id,omitempty"`
	HostCatalogId     string                 `json:"host_catalog_id,omitempty"`
	Scope             *scopes.ScopeInfo      `json:"scope,omitempty"`
	Plugin            *plugins.PluginInfo    `json:"plugin,omitempty"`
	Name              string                 `json:"name,omitempty"`
	Description       string                 `json:"description,omitempty"`
	CreatedTime       time.Time              `json:"created_time,omitempty"`
	UpdatedTime       time.Time              `json:"updated_time,omitempty"`
	Version           uint32                 `json:"version,omitempty"`
	Type              string                 `json:"type,omitempty"`
	HostSetIds        []string               `json:"host_set_ids,omitempty"`
	Attributes        map[string]interface{} `json:"attributes,omitempty"`
	IpAddresses       []string               `json:"ip_addresses,omitempty"`
	DnsNames          []string               `json:"dns_names,omitempty"`
	ExternalId        string                 `json:"external_id,omitempty"`
	ExternalName      string                 `json:"external_name,omitempty"`
	AuthorizedActions []string               `json:"authorized_actions,omitempty"`

	response *api.Response
}

type HostReadResult struct {
	Item     *Host
	response *api.Response
}

func (n HostReadResult) GetItem() *Host {
	return n.Item
}

func (n HostReadResult) GetResponse() *api.Response {
	return n.response
}

type HostCreateResult = HostReadResult
type HostUpdateResult = HostReadResult

type HostDeleteResult struct {
	response *api.Response
}

// GetItem will always be nil for HostDeleteResult
func (n HostDeleteResult) GetItem() interface{} {
	return nil
}

func (n HostDeleteResult) GetResponse() *api.Response {
	return n.response
}

type HostListResult struct {
	Items        []*Host  `json:"items,omitempty"`
	EstItemCount uint     `json:"est_item_count,omitempty"`
	RemovedIds   []string `json:"removed_ids,omitempty"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	ResponseType string   `json:"response_type,omitempty"`
	response     *api.Response
}

func (n HostListResult) GetItems() []*Host {
	return n.Items
}

func (n HostListResult) GetEstItemCount() uint {
	return n.EstItemCount
}

func (n HostListResult) GetRemovedIds() []string {
	return n.RemovedIds
}

func (n HostListResult) GetRefreshToken() string {
	return n.RefreshToken
}

func (n HostListResult) GetResponseType() string {
	return n.ResponseType
}

func (n HostListResult) GetResponse() *api.Response {
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

func (c *Client) Create(ctx context.Context, hostCatalogId string, opt ...Option) (*HostCreateResult, error) {
	if hostCatalogId == "" {
		return nil, fmt.Errorf("empty hostCatalogId value passed into Create request")
	}

	opts, apiOpts := getOpts(opt...)

	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts.postMap["host_catalog_id"] = hostCatalogId

	req, err := c.client.NewRequest(ctx, "POST", "hosts", opts.postMap, apiOpts...)
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

	target := new(HostCreateResult)
	target.Item = new(Host)
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

func (c *Client) Read(ctx context.Context, id string, opt ...Option) (*HostReadResult, error) {
	if id == "" {
		return nil, fmt.Errorf("empty id value passed into Read request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("hosts/%s", url.PathEscape(id)), nil, apiOpts...)
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

	target := new(HostReadResult)
	target.Item = new(Host)
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

func (c *Client) Update(ctx context.Context, id string, version uint32, opt ...Option) (*HostUpdateResult, error) {
	if id == "" {
		return nil, fmt.Errorf("empty id value passed into Update request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into Update request and automatic versioning not specified")
		}
		existingTarget, existingErr := c.Read(ctx, id, append([]Option{WithSkipCurlOutput(true)}, opt...)...)
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

	req, err := c.client.NewRequest(ctx, "PATCH", fmt.Sprintf("hosts/%s", url.PathEscape(id)), opts.postMap, apiOpts...)
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

	target := new(HostUpdateResult)
	target.Item = new(Host)
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

func (c *Client) Delete(ctx context.Context, id string, opt ...Option) (*HostDeleteResult, error) {
	if id == "" {
		return nil, fmt.Errorf("empty id value passed into Delete request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "DELETE", fmt.Sprintf("hosts/%s", url.PathEscape(id)), nil, apiOpts...)
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

	target := &HostDeleteResult{
		response: resp,
	}
	return target, nil
}

func (c *Client) List(ctx context.Context, hostCatalogId string, opt ...Option) (*HostListResult, error) {
	if hostCatalogId == "" {
		return nil, fmt.Errorf("empty hostCatalogId value passed into List request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)
	opts.queryMap["host_catalog_id"] = hostCatalogId

	req, err := c.client.NewRequest(ctx, "GET", "hosts", nil, apiOpts...)
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

	target := new(HostListResult)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, fmt.Errorf("error decoding List response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	if opts.withRefreshToken != "" || target.ResponseType == "complete" || target.ResponseType == "" {
		return target, nil
	}
	// if refresh token is not set explicitly and there are more results,
	// automatically fetch the rest of the results.
	// idToIndex keeps a map from the ID of an item to its index in target.Items.
	// This is used to update updated items in-place and remove deleted items
	// from the result after pagination is done.
	idToIndex := map[string]int{}
	for i, item := range target.Items {
		idToIndex[item.Id] = i
	}
	for {
		req, err := c.client.NewRequest(ctx, "GET", "hosts", nil, apiOpts...)
		if err != nil {
			return nil, fmt.Errorf("error creating List request: %w", err)
		}

		opts.queryMap["refresh_token"] = target.RefreshToken
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

		page := new(HostListResult)
		apiErr, err := resp.Decode(page)
		if err != nil {
			return nil, fmt.Errorf("error decoding List response: %w", err)
		}
		if apiErr != nil {
			return nil, apiErr
		}
		for _, item := range page.Items {
			if i, ok := idToIndex[item.Id]; ok {
				// Item has already been seen at index i, update in-place
				target.Items[i] = item
			} else {
				target.Items = append(target.Items, item)
				idToIndex[item.Id] = len(target.Items) - 1
			}
		}
		target.RemovedIds = append(target.RemovedIds, page.RemovedIds...)
		target.EstItemCount = page.EstItemCount
		target.RefreshToken = page.RefreshToken
		target.ResponseType = page.ResponseType
		target.response = resp
		if target.ResponseType == "complete" {
			break
		}
	}
	// Remove any items deleted since the start of the iteration,
	// and also remove those IDs from the RemovedIds slice.
	// https://github.com/golang/go/wiki/SliceTricks#filtering-without-allocating
	removedIds := target.RemovedIds
	target.RemovedIds = target.RemovedIds[:0]
	for _, removedId := range removedIds {
		if i, ok := idToIndex[removedId]; ok {
			// Remove the item at index i.
			// https://github.com/golang/go/wiki/SliceTricks#delete
			copy(target.Items[i:], target.Items[i+1:])
			target.Items[len(target.Items)-1] = nil
			target.Items = target.Items[:len(target.Items)-1]
		} else {
			target.RemovedIds = append(target.RemovedIds, removedId)
		}
	}
	return target, nil
}
