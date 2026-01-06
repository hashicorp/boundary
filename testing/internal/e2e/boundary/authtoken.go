// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/stretchr/testify/require"
)

// GetAuthenticationTokenIdByTokenNameCli uses the CLI to get an auth-token ID by its name
// The operation is performed by the user associated with the auth-token
func GetAuthenticationTokenIdByTokenNameCli(t testing.TB, ctx context.Context, tokenName string) string {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-tokens", "list",
			"-token-name", tokenName,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var authTokenListResult authtokens.AuthTokenListResult
	err := json.Unmarshal(output.Stdout, &authTokenListResult)
	require.NoError(t, err)
	userAuthTokenID := fmt.Sprint(authTokenListResult.Items[0].Id)
	t.Logf("Retrieved Auth-Token: %s", userAuthTokenID)

	return userAuthTokenID
}
