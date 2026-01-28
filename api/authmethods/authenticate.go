// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package authmethods

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
)

type AuthenticateResult struct {
	Command       string         `json:"-"`
	Attributes    map[string]any `json:"-"`
	attributesRaw json.RawMessage

	response *api.Response
}

func (a *AuthenticateResult) MarshalJSON() ([]byte, error) {
	// Note that a will not be nil per contract of the interface. Using a map
	// here causes Go to sort the resulting JSON, which makes tests easier and
	// output more predictable.
	out := make(map[string]any)
	if a.Command != "" {
		out["command"] = a.Command
	}
	if a.Attributes != nil {
		out["attributes"] = a.Attributes
	}
	return json.Marshal(out)
}

func (a *AuthenticateResult) UnmarshalJSON(inBytes []byte) error {
	type in struct {
		Command    string          `json:"command"`
		Attributes json.RawMessage `json:"attributes"`
	}
	i := new(in)
	if err := json.Unmarshal(inBytes, i); err != nil {
		return err
	}
	a.Command = i.Command
	a.attributesRaw = i.Attributes
	a.Attributes = make(map[string]any)
	if err := json.Unmarshal(i.Attributes, &a.Attributes); err != nil {
		return err
	}
	return nil
}

func (a AuthenticateResult) GetRawAttributes() json.RawMessage {
	return a.attributesRaw
}

func (a AuthenticateResult) GetResponse() *api.Response {
	return a.response
}

// GetAuthToken converts this AuthenticateResult into an AuthToken struct
func (a AuthenticateResult) GetAuthToken() (*authtokens.AuthToken, error) {
	if a.attributesRaw == nil {
		return nil, errors.New("AuthenticateResult does not have a populated raw attributes field")
	}
	token := new(authtokens.AuthToken)
	if err := json.Unmarshal(a.GetRawAttributes(), token); err != nil {
		return nil, err
	}
	return token, nil
}

// Authenticate is a generic authenticate API call that returns a generic
// result. See the documentation for the attributes required for any given auth
// method.
//
// Only some auth methods support multiple commands. If the documentation does
// not specify what command to use when and with which attriubutes, use
// "login".
func (c *Client) Authenticate(ctx context.Context, authMethodId, command string, attributes map[string]any, opt ...Option) (*AuthenticateResult, error) {
	if c.client == nil {
		return nil, fmt.Errorf("nil client in Authenticate request")
	}
	if authMethodId == "" {
		return nil, fmt.Errorf("empty auth method passed into Authenticate request")
	}
	if command == "" {
		return nil, fmt.Errorf("empty command passed into Authenticate request")
	}

	_, apiOpts := getOpts(opt...)

	reqBody := map[string]any{
		"command": command,
	}
	if attributes != nil {
		reqBody["attributes"] = attributes
	}

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("auth-methods/%s:authenticate", authMethodId), reqBody, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating Authenticate request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during Authenticate call: %w", err)
	}

	target := new(AuthenticateResult)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, fmt.Errorf("error decoding Authenticate response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}
