// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package authenticate

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func saveAndOrPrintToken(c *base.Command, result *authmethods.AuthenticateResult) int {
	token := new(authtokens.AuthToken)
	if err := json.Unmarshal(result.GetRawAttributes(), token); err != nil {
		c.PrintCliError(fmt.Errorf("Error trying to decode response as an auth token: %w", err))
		return base.CommandCliError
	}

	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(base.WrapForHelpText([]string{
			"",
			"Authentication information:",
			fmt.Sprintf("  Account ID:      %s", token.AccountId),
			fmt.Sprintf("  Auth Method ID:  %s", token.AuthMethodId),
			fmt.Sprintf("  Expiration Time: %s", token.ExpirationTime.Local().Format(time.RFC1123)),
			fmt.Sprintf("  User ID:         %s", token.UserId),
		}))

	case "json":
		if ok := c.PrintJsonItem(result.GetResponse()); !ok {
			return base.CommandCliError
		}
		return base.CommandSuccess
	}

	c.SaveTokenToKeyring(token)

	switch {
	case c.FlagKeyringType == "none":
		c.UI.Warn("\nStoring the token in a keyring was disabled. The token is:")
		c.UI.Output(token.Token)
		c.UI.Warn("Please be sure to store it safely!")
	}

	return base.CommandSuccess
}

// getPrimaryAuthMethodId iterates over client.List() to find the primary auth method ID for the
// given scopeId. If scope ID is empty or no primary auth method is found, it returns an error.
func getPrimaryAuthMethodId(ctx context.Context, client *authmethods.Client, scopeId, amType string) (string, error) {
	if scopeId == "" {
		return "", fmt.Errorf("Must pass a non empty scope ID string to GetPrimaryAuthMethodId()")
	}
	authMethodListResult, err := client.List(ctx, scopeId)
	if err != nil {
		return "", err
	}

	for _, m := range authMethodListResult.GetItems() {
		if m.IsPrimary {
			if !strings.HasPrefix(m.Id, amType) {
				return "", fmt.Errorf("Error looking up primary auth method in scope '%s': got '%s' but the command requires an auth method prefix of '%s'. Make sure the sub command you're using matches the primary auth method type in the scope being used. For example, if using the password sub command the primary auth method must have a prefix of 'ampw'.\n\nSee 'boundary authenticate -h' for available sub command usage.", scopeId, m.Id, amType)
			}

			return m.Id, nil
		}
	}
	return "", fmt.Errorf("Primary auth method not found for scope ID: '%s'. Please set a primary auth method on this scope or pass one explicitly using an authenticate sub command (see 'boundary authenticate -h') along with the -auth-method-id flag.", scopeId)
}
