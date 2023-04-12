package boundary

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/stretchr/testify/require"
	"testing"
)

// AuthTokenInfo parses the JSON representation of auth-token information`
type AuthTokenInfo struct {
	ID string `json:"id"`
}

// ListAuthTokensCliOutput parses the JSON response from running `boundary auth-tokens list`
type ListAuthTokensCliOutput struct {
	Items []*AuthTokenInfo `json:"items"`
}

// GetAuthenticationTokenIdCli uses the CLI to get an auth-token ID by its name
func GetAuthenticationTokenIdCli(t testing.TB, ctx context.Context, tokenName string) string {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-tokens", "list",
			"-token-name", tokenName,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var authenticationResult ListAuthTokensCliOutput
	err := json.Unmarshal(output.Stdout, &authenticationResult)
	require.NoError(t, err)
	userAuthTokenID := fmt.Sprint(authenticationResult.Items[0].ID)
	t.Logf("Acquired auth-token ID: %s", userAuthTokenID)

	return userAuthTokenID
}
