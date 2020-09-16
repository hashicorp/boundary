package accounts

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/kr/pretty"
)

func (c *Client) SetPassword(ctx context.Context, accountId, password string, version uint32, opt ...Option) (*AccountUpdateResult, *api.Error, error) {
	if accountId == "" {
		return nil, nil, fmt.Errorf("empty accountId value passed into SetPassword request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client in SetPassword request")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, nil, errors.New("zero version number passed into Update request and automatic versioning not specified")
		}
		existingTarget, existingApiErr, existingErr := c.Read(ctx, accountId, opt...)
		if existingErr != nil {
			return nil, nil, fmt.Errorf("error performing initial check-and-set read: %w", existingErr)
		}
		if existingApiErr != nil {
			return nil, nil, fmt.Errorf("error from controller when performing initial check-and-set read: %s", pretty.Sprint(existingApiErr))
		}
		if existingTarget == nil {
			return nil, nil, errors.New("nil resource found when performing initial check-and-set read")
		}
		version = existingTarget.Item.Version
	}

	reqBody := map[string]interface{}{
		"version":  version,
		"password": password,
	}

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("accounts/%s:set-password", accountId), reqBody, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating SetPassword request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during SetPassword call: %w", err)
	}

	target := new(AccountUpdateResult)
	target.Item = new(Account)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding SetPassword response: %w", err)
	}

	return target, apiErr, nil
}
