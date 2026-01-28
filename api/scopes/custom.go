// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package scopes

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/hashicorp/boundary/api"
)

type KeyListResult struct {
	Items    []*Key
	response *api.Response
}

func (n KeyListResult) GetItems() []*Key {
	return n.Items
}

func (n KeyListResult) GetResponse() *api.Response {
	return n.response
}

type KeysRotateResult struct {
	response *api.Response
}

func (n KeysRotateResult) GetResponse() *api.Response {
	return n.response
}

type KeyVersionDestructionJobListResult struct {
	Items    []*KeyVersionDestructionJob
	response *api.Response
}

func (n KeyVersionDestructionJobListResult) GetItems() []*KeyVersionDestructionJob {
	return n.Items
}

func (n KeyVersionDestructionJobListResult) GetResponse() *api.Response {
	return n.response
}

type KeyVersionDestructionResult struct {
	State    string
	response *api.Response
}

func (n KeyVersionDestructionResult) GetResponse() *api.Response {
	return n.response
}

func (c *Client) ListKeys(ctx context.Context, scopeId string, opt ...Option) (*KeyListResult, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("empty scopeId value passed into ListKeys request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", "scopes/"+url.PathEscape(scopeId)+":list-keys", nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating ListKeys request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during ListKeys call: %w", err)
	}

	target := new(KeyListResult)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, fmt.Errorf("error decoding ListKeys response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}

func (c *Client) RotateKeys(ctx context.Context, scopeId string, rewrapKeys bool, opt ...Option) (*KeysRotateResult, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("empty scopeId value passed into RotateKeys request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	opts.postMap["scope_id"] = scopeId
	opts.postMap["rewrap"] = rewrapKeys

	req, err := c.client.NewRequest(ctx, "POST", "scopes:rotate-keys", opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating RotateKeys request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during RotateKeys call: %w", err)
	}

	apiErr, err := resp.Decode(nil)
	if err != nil {
		return nil, fmt.Errorf("error decoding RotateKeys response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}

	target := &KeysRotateResult{
		response: resp,
	}
	return target, nil
}

func (c *Client) ListKeyVersionDestructionJobs(ctx context.Context, scopeId string, opt ...Option) (*KeyVersionDestructionJobListResult, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("empty scopeId value passed into ListKeyVersionDestructionJobs request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", "scopes/"+url.PathEscape(scopeId)+":list-key-version-destruction-jobs", nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating ListKeyVersionDestructionJobs request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during ListKeyVersionDestructionJobs call: %w", err)
	}

	target := new(KeyVersionDestructionJobListResult)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, fmt.Errorf("error decoding ListKeyVersionDestructionJobs response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}

func (c *Client) DestroyKeyVersion(ctx context.Context, scopeId string, keyVersionId string, opt ...Option) (*KeyVersionDestructionResult, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("empty scopeId value passed into DestroyKeyVersion request")
	}
	if keyVersionId == "" {
		return nil, fmt.Errorf("empty keyVersionId value passed into DestroyKeyVersion request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)
	opts.postMap["scope_id"] = scopeId
	opts.postMap["key_version_id"] = keyVersionId

	req, err := c.client.NewRequest(ctx, "POST", "scopes:destroy-key-version", opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating RotateKeys request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during DestroyKeyVersion call: %w", err)
	}

	target := new(KeyVersionDestructionResult)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, fmt.Errorf("error decoding DestroyKeyVersion response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}

type (
	AttachStoragePolicyResult = ScopeReadResult
	DetachStoragePolicyResult = ScopeReadResult
)

// AttachStoragePolicy attaches the provided storagePolicyId to the provided scopeId.
func (c *Client) AttachStoragePolicy(ctx context.Context, scopeId string, version uint32, storagePolicyId string, opt ...Option) (*AttachStoragePolicyResult, error) {
	if scopeId == "" {
		return nil, errors.New("empty scopeId value passed into AttachStoragePolicy request")
	}
	if storagePolicyId == "" {
		return nil, errors.New("empty storagePolicyId value passed into AttachStoragePolicy request")
	}
	if c.client == nil {
		return nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into AttachStoragePolicy request")
		}
		existingScope, existingErr := c.Read(ctx, scopeId, append([]Option{WithSkipCurlOutput(true)}, opt...)...)
		if existingErr != nil {
			if api.AsServerError(existingErr) != nil {
				return nil, fmt.Errorf("error from controller when performing initial check-and-set read: %w", existingErr)
			}
			return nil, fmt.Errorf("error performing initial check-and-set read: %w", existingErr)
		}
		if existingScope == nil {
			return nil, errors.New("nil resource response found when performing initial check-and-set read")
		}
		if existingScope.Item == nil {
			return nil, errors.New("nil resource found when performing initial check-and-set read")
		}
		version = existingScope.Item.Version
	}

	opts.postMap["version"] = version
	opts.postMap["storage_policy_id"] = storagePolicyId

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("scopes/%s:attach-storage-policy", url.PathEscape(scopeId)), opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating AttachStoragePolicy request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during AttachStoragePolicy call: %w", err)
	}

	s := new(AttachStoragePolicyResult)
	s.Item = new(Scope)
	apiErr, err := resp.Decode(s.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding AttachStoragePolicyResult response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	s.Response = resp
	return s, nil
}

// DetachStoragePolicy detaches storage policy from the provided scopeId if one is attached.
func (c *Client) DetachStoragePolicy(ctx context.Context, scopeId string, version uint32, opt ...Option) (*AttachStoragePolicyResult, error) {
	if scopeId == "" {
		return nil, errors.New("empty scopeId value passed into DetachStoragePolicy request")
	}
	if c.client == nil {
		return nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into DetachStoragePolicy request")
		}
		existingScope, existingErr := c.Read(ctx, scopeId, append([]Option{WithSkipCurlOutput(true)}, opt...)...)
		if existingErr != nil {
			if api.AsServerError(existingErr) != nil {
				return nil, fmt.Errorf("error from controller when performing initial check-and-set read: %w", existingErr)
			}
			return nil, fmt.Errorf("error performing initial check-and-set read: %w", existingErr)
		}
		if existingScope == nil {
			return nil, errors.New("nil resource response found when performing initial check-and-set read")
		}
		if existingScope.Item == nil {
			return nil, errors.New("nil resource found when performing initial check-and-set read")
		}
		version = existingScope.Item.Version
	}

	opts.postMap["version"] = version

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("scopes/%s:detach-storage-policy", url.PathEscape(scopeId)), opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating DetachStoragePolicy request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during DetachStoragePolicy call: %w", err)
	}

	s := new(DetachStoragePolicyResult)
	s.Item = new(Scope)
	apiErr, err := resp.Decode(s.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding DetachStoragePolicyResult response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	s.Response = resp
	return s, nil
}
