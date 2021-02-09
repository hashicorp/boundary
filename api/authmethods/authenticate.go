package authmethods

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/api/authtokens"
)

func (c *Client) Authenticate(ctx context.Context, authMethodId string, credentials map[string]interface{}, opt ...Option) (*authtokens.AuthTokenReadResult, error) {
	if c.client == nil {
		return nil, fmt.Errorf("nil client in Authenticate request")
	}

	opts, apiOpts := getOpts(opt...)

	reqBody := map[string]interface{}{
		"credentials": credentials,
	}

	var action string
	switch {
	case opts.withSubAction != "":
		action = opts.withSubAction
	case strings.HasPrefix(authMethodId, "ampw"):
		action = "login"
	}

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("auth-methods/%s:authenticate:%s", authMethodId, action), reqBody, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating Authenticate request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during Authenticate call: %w", err)
	}

	target := new(authtokens.AuthTokenReadResult)
	target.Item = new(authtokens.AuthToken)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding Authenticate response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}

	return target, nil
}
