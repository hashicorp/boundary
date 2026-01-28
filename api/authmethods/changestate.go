// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package authmethods

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/api"
)

const (
	versionPostBodyKey    = "version"
	attributesPostBodyKey = "attributes"
	statePostBodyKey      = "state"
)

func (c *Client) ChangeState(ctx context.Context, authMethodId string, version uint32, state string, opt ...Option) (*AuthMethodUpdateResult, error) {
	if authMethodId == "" {
		return nil, fmt.Errorf("empty authMethodId value passed into ChangeState request")
	}
	if state == "" {
		return nil, fmt.Errorf("empty state value passed into ChangeState request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client in ChangeState request")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into ChangeState request and automatic versioning not specified")
		}
		existingTarget, existingErr := c.Read(ctx, authMethodId, opt...)
		if existingErr != nil {
			if api.AsServerError(existingErr) != nil {
				return nil, fmt.Errorf("error from controller when performing initial check-and-set read: %w", existingErr)
			}
			return nil, fmt.Errorf("error performing initial check-and-set read: %w", existingErr)
		}
		if existingTarget == nil {
			return nil, errors.New("nil resource found when performing initial check-and-set read")
		}
		version = existingTarget.Item.Version
	}

	reqBody := opts.postMap
	reqBody[versionPostBodyKey] = version
	attrMap, ok := reqBody[attributesPostBodyKey].(map[string]any)
	if !ok {
		attrMap = make(map[string]any)
		reqBody[attributesPostBodyKey] = attrMap
	}
	attrMap[statePostBodyKey] = state

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("auth-methods/%s:change-state", authMethodId), reqBody, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating ChangeState request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during ChangeState call: %w", err)
	}

	target := new(AuthMethodUpdateResult)
	target.Item = new(AuthMethod)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding ChangeState response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.Response = resp
	return target, nil
}
