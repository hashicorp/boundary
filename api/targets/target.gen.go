// Code generated by "make api"; DO NOT EDIT.
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package targets

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
)

type Target struct {
	Id                                     string                 `json:"id,omitempty"`
	ScopeId                                string                 `json:"scope_id,omitempty"`
	Scope                                  *scopes.ScopeInfo      `json:"scope,omitempty"`
	Name                                   string                 `json:"name,omitempty"`
	Description                            string                 `json:"description,omitempty"`
	CreatedTime                            time.Time              `json:"created_time,omitempty"`
	UpdatedTime                            time.Time              `json:"updated_time,omitempty"`
	Version                                uint32                 `json:"version,omitempty"`
	Type                                   string                 `json:"type,omitempty"`
	HostSourceIds                          []string               `json:"host_source_ids,omitempty"`
	HostSources                            []*HostSource          `json:"host_sources,omitempty"`
	SessionMaxSeconds                      uint32                 `json:"session_max_seconds,omitempty"`
	SessionConnectionLimit                 int32                  `json:"session_connection_limit,omitempty"`
	WorkerFilter                           string                 `json:"worker_filter,omitempty"`
	EgressWorkerFilter                     string                 `json:"egress_worker_filter,omitempty"`
	IngressWorkerFilter                    string                 `json:"ingress_worker_filter,omitempty"`
	ApplicationCredentialSourceIds         []string               `json:"application_credential_source_ids,omitempty"`
	ApplicationCredentialSources           []*CredentialSource    `json:"application_credential_sources,omitempty"`
	BrokeredCredentialSourceIds            []string               `json:"brokered_credential_source_ids,omitempty"`
	BrokeredCredentialSources              []*CredentialSource    `json:"brokered_credential_sources,omitempty"`
	InjectedApplicationCredentialSourceIds []string               `json:"injected_application_credential_source_ids,omitempty"`
	InjectedApplicationCredentialSources   []*CredentialSource    `json:"injected_application_credential_sources,omitempty"`
	Attributes                             map[string]interface{} `json:"attributes,omitempty"`
	AuthorizedActions                      []string               `json:"authorized_actions,omitempty"`
	Address                                string                 `json:"address,omitempty"`

	response *api.Response
}

type TargetReadResult struct {
	Item     *Target
	response *api.Response
}

func (n TargetReadResult) GetItem() *Target {
	return n.Item
}

func (n TargetReadResult) GetResponse() *api.Response {
	return n.response
}

type TargetCreateResult = TargetReadResult
type TargetUpdateResult = TargetReadResult

type TargetDeleteResult struct {
	response *api.Response
}

// GetItem will always be nil for TargetDeleteResult
func (n TargetDeleteResult) GetItem() interface{} {
	return nil
}

func (n TargetDeleteResult) GetResponse() *api.Response {
	return n.response
}

type TargetListResult struct {
	Items        []*Target `json:"items,omitempty"`
	EstItemCount uint      `json:"est_item_count,omitempty"`
	RemovedIds   []string  `json:"removed_ids,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ResponseType string    `json:"response_type,omitempty"`
	response     *api.Response
}

func (n TargetListResult) GetItems() []*Target {
	return n.Items
}

func (n TargetListResult) GetEstItemCount() uint {
	return n.EstItemCount
}

func (n TargetListResult) GetRemovedIds() []string {
	return n.RemovedIds
}

func (n TargetListResult) GetRefreshToken() string {
	return n.RefreshToken
}

func (n TargetListResult) GetResponseType() string {
	return n.ResponseType
}

func (n TargetListResult) GetResponse() *api.Response {
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

func (c *Client) Create(ctx context.Context, resourceType string, scopeId string, opt ...Option) (*TargetCreateResult, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("empty scopeId value passed into Create request")
	}

	opts, apiOpts := getOpts(opt...)

	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}
	if resourceType == "" {
		return nil, fmt.Errorf("empty resourceType value passed into Create request")
	} else {
		opts.postMap["type"] = resourceType
	}

	opts.postMap["scope_id"] = scopeId

	req, err := c.client.NewRequest(ctx, "POST", "targets", opts.postMap, apiOpts...)
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

	target := new(TargetCreateResult)
	target.Item = new(Target)
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

func (c *Client) Read(ctx context.Context, id string, opt ...Option) (*TargetReadResult, error) {
	if id == "" {
		return nil, fmt.Errorf("empty id value passed into Read request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("targets/%s", url.PathEscape(id)), nil, apiOpts...)
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

	target := new(TargetReadResult)
	target.Item = new(Target)
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

func (c *Client) Update(ctx context.Context, id string, version uint32, opt ...Option) (*TargetUpdateResult, error) {
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

	req, err := c.client.NewRequest(ctx, "PATCH", fmt.Sprintf("targets/%s", url.PathEscape(id)), opts.postMap, apiOpts...)
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

	target := new(TargetUpdateResult)
	target.Item = new(Target)
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

func (c *Client) Delete(ctx context.Context, id string, opt ...Option) (*TargetDeleteResult, error) {
	if id == "" {
		return nil, fmt.Errorf("empty id value passed into Delete request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "DELETE", fmt.Sprintf("targets/%s", url.PathEscape(id)), nil, apiOpts...)
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

	target := &TargetDeleteResult{
		response: resp,
	}
	return target, nil
}

func (c *Client) List(ctx context.Context, scopeId string, opt ...Option) (*TargetListResult, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("empty scopeId value passed into List request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)
	opts.queryMap["scope_id"] = scopeId

	req, err := c.client.NewRequest(ctx, "GET", "targets", nil, apiOpts...)
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

	target := new(TargetListResult)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, fmt.Errorf("error decoding List response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	if target.ResponseType == "complete" || target.ResponseType == "" {
		return target, nil
	}
	// If there are more results, automatically fetch the rest of the results.
	// idToIndex keeps a map from the ID of an item to its index in target.Items.
	// This is used to update updated items in-place and remove deleted items
	// from the result after pagination is done.
	idToIndex := map[string]int{}
	for i, item := range target.Items {
		idToIndex[item.Id] = i
	}
	for {
		req, err := c.client.NewRequest(ctx, "GET", "targets", nil, apiOpts...)
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

		page := new(TargetListResult)
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
	for _, removedId := range target.RemovedIds {
		if i, ok := idToIndex[removedId]; ok {
			// Remove the item at index i without preserving order
			// https://github.com/golang/go/wiki/SliceTricks#delete-without-preserving-order
			target.Items[i] = target.Items[len(target.Items)-1]
			target.Items = target.Items[:len(target.Items)-1]
			// Update the index of the last element
			idToIndex[target.Items[i].Id] = i
		}
	}
	// Finally, sort the results again since in-place updates and deletes
	// may have shuffled items.
	slices.SortFunc(target.Items, func(i, j *Target) int {
		return i.UpdatedTime.Compare(j.UpdatedTime)
	})
	return target, nil
}

func (c *Client) AddCredentialSources(ctx context.Context, id string, version uint32, opt ...Option) (*TargetUpdateResult, error) {
	if id == "" {
		return nil, fmt.Errorf("empty id value passed into AddCredentialSources request")
	}

	if c.client == nil {
		return nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into AddCredentialSources request")
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

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("targets/%s:add-credential-sources", url.PathEscape(id)), opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating AddCredentialSources request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during AddCredentialSources call: %w", err)
	}

	target := new(TargetUpdateResult)
	target.Item = new(Target)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding AddCredentialSources response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}

func (c *Client) AddHostSources(ctx context.Context, id string, version uint32, hostSourceIds []string, opt ...Option) (*TargetUpdateResult, error) {
	if id == "" {
		return nil, fmt.Errorf("empty id value passed into AddHostSources request")
	}

	if len(hostSourceIds) == 0 {
		return nil, errors.New("empty hostSourceIds passed into AddHostSources request")
	}

	if c.client == nil {
		return nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into AddHostSources request")
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

	opts.postMap["host_source_ids"] = hostSourceIds

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("targets/%s:add-host-sources", url.PathEscape(id)), opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating AddHostSources request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during AddHostSources call: %w", err)
	}

	target := new(TargetUpdateResult)
	target.Item = new(Target)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding AddHostSources response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}

func (c *Client) SetCredentialSources(ctx context.Context, id string, version uint32, opt ...Option) (*TargetUpdateResult, error) {
	if id == "" {
		return nil, fmt.Errorf("empty id value passed into SetCredentialSources request")
	}

	if c.client == nil {
		return nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into SetCredentialSources request")
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

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("targets/%s:set-credential-sources", url.PathEscape(id)), opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating SetCredentialSources request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during SetCredentialSources call: %w", err)
	}

	target := new(TargetUpdateResult)
	target.Item = new(Target)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding SetCredentialSources response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}

func (c *Client) SetHostSources(ctx context.Context, id string, version uint32, hostSourceIds []string, opt ...Option) (*TargetUpdateResult, error) {
	if id == "" {
		return nil, fmt.Errorf("empty id value passed into SetHostSources request")
	}

	if c.client == nil {
		return nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into SetHostSources request")
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

	opts.postMap["host_source_ids"] = hostSourceIds

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("targets/%s:set-host-sources", url.PathEscape(id)), opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating SetHostSources request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during SetHostSources call: %w", err)
	}

	target := new(TargetUpdateResult)
	target.Item = new(Target)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding SetHostSources response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}

func (c *Client) RemoveCredentialSources(ctx context.Context, id string, version uint32, opt ...Option) (*TargetUpdateResult, error) {
	if id == "" {
		return nil, fmt.Errorf("empty id value passed into RemoveCredentialSources request")
	}

	if c.client == nil {
		return nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into RemoveCredentialSources request")
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

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("targets/%s:remove-credential-sources", url.PathEscape(id)), opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating RemoveCredentialSources request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during RemoveCredentialSources call: %w", err)
	}

	target := new(TargetUpdateResult)
	target.Item = new(Target)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding RemoveCredentialSources response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}

func (c *Client) RemoveHostSources(ctx context.Context, id string, version uint32, hostSourceIds []string, opt ...Option) (*TargetUpdateResult, error) {
	if id == "" {
		return nil, fmt.Errorf("empty id value passed into RemoveHostSources request")
	}

	if len(hostSourceIds) == 0 {
		return nil, errors.New("empty hostSourceIds passed into RemoveHostSources request")
	}

	if c.client == nil {
		return nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into RemoveHostSources request")
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

	opts.postMap["host_source_ids"] = hostSourceIds

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("targets/%s:remove-host-sources", url.PathEscape(id)), opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating RemoveHostSources request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during RemoveHostSources call: %w", err)
	}

	target := new(TargetUpdateResult)
	target.Item = new(Target)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding RemoveHostSources response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}
