package authmethods

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/api"
)

func (c *Client) ChangeState(ctx context.Context, authMethodId string, version uint32, state string, opt ...Option) (*AuthMethodUpdateResult, error) {
	if authMethodId == "" {
		return nil, fmt.Errorf("empty authMethodId value passed into ChangeState request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client in ChangeState request")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into Update request and automatic versioning not specified")
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

	reqBody := map[string]interface{}{
		"version": version,
		"attributes": map[string]interface{}{"state":   state},
	}

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

	return target, nil
}
