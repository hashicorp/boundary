// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package accounts

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/api"
)

func (c *Client) ChangePassword(ctx context.Context, accountId, currentPassword, newPassword string, version uint32, opt ...Option) (*AccountUpdateResult, error) {
	if accountId == "" {
		return nil, fmt.Errorf("empty accountId value passed into ChangePassword request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client in ChangePassword request")
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
		"version":          version,
		"current_password": currentPassword,
		"new_password":     newPassword,
	}

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("accounts/%s:change-password", accountId), reqBody, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating ChangePassword request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during ChangePassword call: %w", err)
	}

	target := new(AccountUpdateResult)
	target.Item = new(Account)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding ChangePassword response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.Response = resp
	return target, nil
}
