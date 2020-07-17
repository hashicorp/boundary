package scopes

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/authtokens"
)

// TODO: This will need to be changed when we add Auth Method API to watchtower.  We'll also need a better
// way to handle different auth method types.
func (s Org) Authenticate(ctx context.Context, authMethodId, name, password string) (*authtokens.AuthToken, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in Authenticate request")
	}
	if s.Id == "" {
		// Assume the client has been configured with org already and
		// move on
	} else {
		// If it's explicitly set here, override anything that might be in the
		// client
		ctx = context.WithValue(ctx, "org", s.Id)
	}

	reqBody := map[string]interface{}{
		"credentials": map[string]string{
			"name":     name,
			"password": password,
		},
	}

	req, err := s.Client.NewRequest(ctx, "POST", fmt.Sprintf("auth-methods/%s:authenticate", authMethodId), reqBody)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Authenticate request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during Authenticate call: %w", err)
	}

	target := new(authtokens.AuthToken)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Authenticate response: %w", err)
	}

	if target.Token != "" {
		s.Client.SetToken(target.Token)
	}

	return target, apiErr, nil
}
