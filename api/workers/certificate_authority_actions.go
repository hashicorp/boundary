// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package workers

import (
	"context"
	"fmt"
	"net/url"
)

type CertificateAuthorityReinitializeResult = CertificateAuthorityReadResult

func (c *Client) ReinitializeCA(ctx context.Context, scopeId string, opt ...Option) (*CertificateAuthorityReinitializeResult, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("empty scopeId value passed into ReinitializeCA request")
	}

	opts, apiOpts := getOpts(opt...)

	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}
	opts.queryMap["scope_id"] = scopeId

	req, err := c.client.NewRequest(ctx, "POST", "workers:reinitialize-certificate-authority", nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating ReinitializeCA request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during ReinitializeCA call: %w", err)
	}

	target := new(CertificateAuthorityReinitializeResult)
	target.Item = new(CertificateAuthority)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding ReinitializeCA response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.Response = resp
	return target, nil
}

func (c *Client) ReadCA(ctx context.Context, scopeId string, opt ...Option) (*CertificateAuthorityReadResult, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("empty scopeId value passed into ReadCA request")
	}

	opts, apiOpts := getOpts(opt...)
	opts.queryMap["scope_id"] = scopeId

	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	req, err := c.client.NewRequest(ctx, "GET", "workers:read-certificate-authority", nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating ReadCA request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during ReadCA call: %w", err)
	}

	target := new(CertificateAuthorityReadResult)
	target.Item = new(CertificateAuthority)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding ReadCA response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.Response = resp
	return target, nil
}
