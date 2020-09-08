package authmethods

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
)

func (c *Client) Authenticate(ctx context.Context, authMethodId string, credentials map[string]interface{}, opt ...Option) (*authtokens.AuthToken, *api.Error, error) {
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client in Authenticate request")
	}

	_, apiOpts := getOpts(opt...)

	reqBody := map[string]interface{}{
		"credentials": credentials,
	}

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("auth-methods/%s:authenticate", authMethodId), reqBody, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Authenticate request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during Authenticate call: %w", err)
	}

	target := new(authtokens.AuthToken)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Authenticate response: %w", err)
	}

	if target.Token != "" {
		c.client.SetToken(target.Token)
	}

	return target, apiErr, nil
}
