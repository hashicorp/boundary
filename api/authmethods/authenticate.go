package authmethods

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/api/authtokens"
)

// TODO: This will need to be changed when we add Auth Method API to boundary.  We'll also need a better
// way to handle different auth method types.
func (c *AuthMethodsClient) Authenticate(ctx context.Context, authMethodId, loginName, password string, opt ...Option) (r *authtokens.AuthToken, apiErr error, reqErr error) {
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client in Authenticate request")
	}

	_, apiOpts := getOpts(opt...)

	reqBody := map[string]interface{}{
		"credentials": map[string]string{
			"login_name": loginName,
			"password":   password,
		},
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
	apiErr, err = resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Authenticate response: %w", err)
	}

	if target.Token != "" {
		c.client.SetToken(target.Token)
	}

	return target, apiErr, nil
}
