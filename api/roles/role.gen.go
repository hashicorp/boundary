// Code generated by "make api"; DO NOT EDIT.
package roles

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

type Role struct {
	Id           string            `json:"id,omitempty"`
	ScopeId      string            `json:"scope_id,omitempty"`
	Scope        *scopes.ScopeInfo `json:"scope,omitempty"`
	Name         string            `json:"name,omitempty"`
	Description  string            `json:"description,omitempty"`
	CreatedTime  time.Time         `json:"created_time,omitempty"`
	UpdatedTime  time.Time         `json:"updated_time,omitempty"`
	Version      uint32            `json:"version,omitempty"`
	GrantScopeId string            `json:"grant_scope_id,omitempty"`
	PrincipalIds []string          `json:"principal_ids,omitempty"`
	Principals   []*Principal      `json:"principals,omitempty"`
	GrantStrings []string          `json:"grant_strings,omitempty"`
	Grants       []*Grant          `json:"grants,omitempty"`

	responseBody *bytes.Buffer
	responseMap  map[string]interface{}
}

func (n Role) ResponseBody() *bytes.Buffer {
	return n.responseBody
}

func (n Role) ResponseMap() map[string]interface{} {
	return n.responseMap
}

type RoleReadResult struct {
	Item         *Role
	responseBody *bytes.Buffer
	responseMap  map[string]interface{}
}

func (n RoleReadResult) GetItem() interface{} {
	return n.Item
}

func (n RoleReadResult) GetResponseBody() *bytes.Buffer {
	return n.responseBody
}

func (n RoleReadResult) GetResponseMap() map[string]interface{} {
	return n.responseMap
}

type RoleCreateResult = RoleReadResult
type RoleUpdateResult = RoleReadResult

type RoleDeleteResult struct {
	responseBody *bytes.Buffer
	responseMap  map[string]interface{}
}

func (n RoleDeleteResult) GetResponseBody() *bytes.Buffer {
	return n.responseBody
}

func (n RoleDeleteResult) GetResponseMap() map[string]interface{} {
	return n.responseMap
}

type RoleListResult struct {
	Items        []*Role
	responseBody *bytes.Buffer
	responseMap  map[string]interface{}
}

func (n RoleListResult) GetItems() interface{} {
	return n.Items
}

func (n RoleListResult) GetResponseBody() *bytes.Buffer {
	return n.responseBody
}

func (n RoleListResult) GetResponseMap() map[string]interface{} {
	return n.responseMap
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

func (c *Client) Create(ctx context.Context, scopeId string, opt ...Option) (*RoleCreateResult, *api.Error, error) {
	if scopeId == "" {
		return nil, nil, fmt.Errorf("empty scopeId value passed into Create request")
	}

	opts, apiOpts := getOpts(opt...)

	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts.postMap["scope_id"] = scopeId

	req, err := c.client.NewRequest(ctx, "POST", "roles", opts.postMap, apiOpts...)
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

	target := new(RoleCreateResult)
	target.Item = new(Role)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Create response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	target.responseBody = resp.Body
	target.responseMap = resp.Map
	return target, apiErr, nil
}

func (c *Client) Read(ctx context.Context, roleId string, opt ...Option) (*RoleReadResult, *api.Error, error) {
	if roleId == "" {
		return nil, nil, fmt.Errorf("empty roleId value passed into Read request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("roles/%s", roleId), nil, apiOpts...)
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

	target := new(RoleReadResult)
	target.Item = new(Role)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Read response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	target.responseBody = resp.Body
	target.responseMap = resp.Map
	return target, apiErr, nil
}

func (c *Client) Update(ctx context.Context, roleId string, version uint32, opt ...Option) (*RoleUpdateResult, *api.Error, error) {
	if roleId == "" {
		return nil, nil, fmt.Errorf("empty roleId value passed into Update request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, nil, errors.New("zero version number passed into Update request and automatic versioning not specified")
		}
		existingTarget, existingApiErr, existingErr := c.Read(ctx, roleId, opt...)
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

	req, err := c.client.NewRequest(ctx, "PATCH", fmt.Sprintf("roles/%s", roleId), opts.postMap, apiOpts...)
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

	target := new(RoleUpdateResult)
	target.Item = new(Role)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Update response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	target.responseBody = resp.Body
	target.responseMap = resp.Map
	return target, apiErr, nil
}

func (c *Client) Delete(ctx context.Context, roleId string, opt ...Option) (*RoleDeleteResult, *api.Error, error) {
	if roleId == "" {
		return nil, nil, fmt.Errorf("empty roleId value passed into Delete request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "DELETE", fmt.Sprintf("roles/%s", roleId), nil, apiOpts...)
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

	target := &RoleDeleteResult{
		responseBody: resp.Body,
		responseMap:  resp.Map,
	}
	return target, nil, nil
}

func (c *Client) List(ctx context.Context, scopeId string, opt ...Option) (*RoleListResult, *api.Error, error) {
	if scopeId == "" {
		return nil, nil, fmt.Errorf("empty scopeId value passed into List request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)
	opts.queryMap["scope_id"] = scopeId

	req, err := c.client.NewRequest(ctx, "GET", "roles", nil, apiOpts...)
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

	target := new(RoleListResult)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding List response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	target.responseBody = resp.Body
	target.responseMap = resp.Map
	return target, apiErr, nil
}

func (c *Client) AddGrants(ctx context.Context, roleId string, version uint32, grantStrings []string, opt ...Option) (*RoleUpdateResult, *api.Error, error) {
	if roleId == "" {
		return nil, nil, fmt.Errorf("empty roleId value passed into AddGrants request")
	}
	if len(grantStrings) == 0 {
		return nil, nil, errors.New("empty grantStrings passed into AddGrants request")
	}
	if c.client == nil {
		return nil, nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, nil, errors.New("zero version number passed into AddGrants request")
		}
		existingTarget, existingApiErr, existingErr := c.Read(ctx, roleId, opt...)
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
	opts.postMap["grant_strings"] = grantStrings

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("roles/%s:add-grants", roleId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating AddGrants request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during AddGrants call: %w", err)
	}

	target := new(RoleUpdateResult)
	target.Item = new(Role)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding AddGrants response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	target.responseBody = resp.Body
	target.responseMap = resp.Map
	return target, apiErr, nil
}

func (c *Client) AddPrincipals(ctx context.Context, roleId string, version uint32, principalIds []string, opt ...Option) (*RoleUpdateResult, *api.Error, error) {
	if roleId == "" {
		return nil, nil, fmt.Errorf("empty roleId value passed into AddPrincipals request")
	}
	if len(principalIds) == 0 {
		return nil, nil, errors.New("empty principalIds passed into AddPrincipals request")
	}
	if c.client == nil {
		return nil, nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, nil, errors.New("zero version number passed into AddPrincipals request")
		}
		existingTarget, existingApiErr, existingErr := c.Read(ctx, roleId, opt...)
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
	opts.postMap["principal_ids"] = principalIds

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("roles/%s:add-principals", roleId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating AddPrincipals request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during AddPrincipals call: %w", err)
	}

	target := new(RoleUpdateResult)
	target.Item = new(Role)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding AddPrincipals response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	target.responseBody = resp.Body
	target.responseMap = resp.Map
	return target, apiErr, nil
}

func (c *Client) SetGrants(ctx context.Context, roleId string, version uint32, grantStrings []string, opt ...Option) (*RoleUpdateResult, *api.Error, error) {
	if roleId == "" {
		return nil, nil, fmt.Errorf("empty roleId value passed into SetGrants request")
	}

	if c.client == nil {
		return nil, nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, nil, errors.New("zero version number passed into SetGrants request")
		}
		existingTarget, existingApiErr, existingErr := c.Read(ctx, roleId, opt...)
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
	opts.postMap["grant_strings"] = grantStrings

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("roles/%s:set-grants", roleId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating SetGrants request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during SetGrants call: %w", err)
	}

	target := new(RoleUpdateResult)
	target.Item = new(Role)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding SetGrants response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	target.responseBody = resp.Body
	target.responseMap = resp.Map
	return target, apiErr, nil
}

func (c *Client) SetPrincipals(ctx context.Context, roleId string, version uint32, principalIds []string, opt ...Option) (*RoleUpdateResult, *api.Error, error) {
	if roleId == "" {
		return nil, nil, fmt.Errorf("empty roleId value passed into SetPrincipals request")
	}

	if c.client == nil {
		return nil, nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, nil, errors.New("zero version number passed into SetPrincipals request")
		}
		existingTarget, existingApiErr, existingErr := c.Read(ctx, roleId, opt...)
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
	opts.postMap["principal_ids"] = principalIds

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("roles/%s:set-principals", roleId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating SetPrincipals request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during SetPrincipals call: %w", err)
	}

	target := new(RoleUpdateResult)
	target.Item = new(Role)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding SetPrincipals response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	target.responseBody = resp.Body
	target.responseMap = resp.Map
	return target, apiErr, nil
}

func (c *Client) RemoveGrants(ctx context.Context, roleId string, version uint32, grantStrings []string, opt ...Option) (*RoleUpdateResult, *api.Error, error) {
	if roleId == "" {
		return nil, nil, fmt.Errorf("empty roleId value passed into RemoveGrants request")
	}
	if len(grantStrings) == 0 {
		return nil, nil, errors.New("empty grantStrings passed into RemoveGrants request")
	}
	if c.client == nil {
		return nil, nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, nil, errors.New("zero version number passed into RemoveGrants request")
		}
		existingTarget, existingApiErr, existingErr := c.Read(ctx, roleId, opt...)
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
	opts.postMap["grant_strings"] = grantStrings

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("roles/%s:remove-grants", roleId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating RemoveGrants request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during RemoveGrants call: %w", err)
	}

	target := new(RoleUpdateResult)
	target.Item = new(Role)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding RemoveGrants response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	target.responseBody = resp.Body
	target.responseMap = resp.Map
	return target, apiErr, nil
}

func (c *Client) RemovePrincipals(ctx context.Context, roleId string, version uint32, principalIds []string, opt ...Option) (*RoleUpdateResult, *api.Error, error) {
	if roleId == "" {
		return nil, nil, fmt.Errorf("empty roleId value passed into RemovePrincipals request")
	}
	if len(principalIds) == 0 {
		return nil, nil, errors.New("empty principalIds passed into RemovePrincipals request")
	}
	if c.client == nil {
		return nil, nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, nil, errors.New("zero version number passed into RemovePrincipals request")
		}
		existingTarget, existingApiErr, existingErr := c.Read(ctx, roleId, opt...)
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
	opts.postMap["principal_ids"] = principalIds

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("roles/%s:remove-principals", roleId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating RemovePrincipals request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during RemovePrincipals call: %w", err)
	}

	target := new(RoleUpdateResult)
	target.Item = new(Role)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding RemovePrincipals response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	target.responseBody = resp.Body
	target.responseMap = resp.Map
	return target, apiErr, nil
}
