// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/stretchr/testify/require"
)

// NewApiClient creates a new Api client for the specified Boundary instance and
// attempts to authenticate it. Returns the client.
func NewApiClient() (*api.Client, error) {
	c, err := LoadConfig()
	if err != nil {
		return nil, err
	}

	client, err := api.NewClient(&api.Config{Addr: c.Address})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	authmethodsClient := authmethods.NewClient(client)
	authenticationResult, err := authmethodsClient.Authenticate(ctx, c.AuthMethodId, "login",
		map[string]any{
			"login_name": c.AdminLoginName,
			"password":   c.AdminLoginPassword,
		},
	)
	if err != nil {
		return nil, err
	}

	client.SetToken(fmt.Sprint(authenticationResult.Attributes["token"]))
	return client, err
}

// AuthenticateAdminCli uses the cli to authenticate the specified Boundary instance as an admin
func AuthenticateAdminCli(t testing.TB, ctx context.Context) {
	c, err := LoadConfig()
	require.NoError(t, err)

	AuthenticateCli(t, ctx, c.AuthMethodId, c.AdminLoginName, c.AdminLoginPassword)
}

// AuthenticateCli uses the cli to authenticate the specified Boundary instance
func AuthenticateCli(t testing.TB, ctx context.Context, authMethodId string, loginName string, password string, opt ...e2e.Option) {
	c, err := LoadConfig()
	require.NoError(t, err)

	var options []e2e.Option
	options = append(options,
		e2e.WithArgs(
			"authenticate", "password",
			"-addr", c.Address,
			"-auth-method-id", authMethodId,
			"-login-name", loginName,
			"-password", "env://E2E_TEST_BOUNDARY_PASSWORD",
		),
		e2e.WithEnv("E2E_TEST_BOUNDARY_PASSWORD", password),
	)
	options = append(options, opt...)

	output := e2e.RunCommand(ctx, "boundary", options...)
	require.NoError(t, output.Err, string(output.Stderr))
}

// GetAuthenticationTokenCli uses the cli to get an auth token that can be used in subsequent
// commands
func GetAuthenticationTokenCli(t testing.TB, ctx context.Context, loginName string, password string) string {
	c, err := LoadConfig()
	require.NoError(t, err)

	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"authenticate", "password",
			"-addr", c.Address,
			"-auth-method-id", c.AuthMethodId,
			"-login-name", loginName,
			"-password", "env://E2E_TEST_BOUNDARY_PASSWORD",
			"-format", "json",
		),
		e2e.WithEnv("E2E_TEST_BOUNDARY_PASSWORD", password),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var authenticationResult AuthenticateCliOutput
	err = json.Unmarshal(output.Stdout, &authenticationResult)
	require.NoError(t, err)

	return fmt.Sprint(authenticationResult.Item.Attributes["token"])
}
