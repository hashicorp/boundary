// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package accounts

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/api"
)

func (c *Client) SetPassword(ctx context.Context, accountId, password string, version uint32, opt ...Option) (*AccountUpdateResult, error) {
	if accountId == "" {
		return nil, fmt.Errorf("empty accountId value passed into SetPassword request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client in SetPassword request")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into Update request and automatic versioning not specified")
		}
		existingTarget, existingErr := c.Read(ctx, accountId, opt...)
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

	reqBody := map[string]any{
		"version":  version,
		"password": password,
	}

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("accounts/%s:set-password", accountId), reqBody, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating SetPassword request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during SetPassword call: %w", err)
	}

	target := new(AccountUpdateResult)
	target.Item = new(Account)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding SetPassword response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.Response = resp
	return target, nil
}
