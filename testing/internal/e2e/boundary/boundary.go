// Package boundary provides methods for commonly used boundary actions that are used in end-to-end tests.
package boundary

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/kelseyhightower/envconfig"
	"github.com/stretchr/testify/require"
)

type config struct {
	Address            string `envconfig:"BOUNDARY_ADDR"`               // e.g. http://127.0.0.1:9200
	AuthMethodId       string `envconfig:"E2E_PASSWORD_AUTH_METHOD_ID"` // e.g. ampw_1234567890
	AdminLoginName     string `envconfig:"E2E_PASSWORD_ADMIN_LOGIN_NAME" default:"admin"`
	AdminLoginPassword string `envconfig:"E2E_PASSWORD_ADMIN_PASSWORD"`
}

func (c *config) validate() error {
	if c.Address == "" {
		return errors.New("Address is empty. Set environment variable: BOUNDARY_ADDR")
	}
	if c.AuthMethodId == "" {
		return errors.New("AuthMethodId is empty. Set environment variable: E2E_PASSWORD_AUTH_METHOD_ID")
	}
	if c.AdminLoginName == "" {
		return errors.New("AdminLoginName is empty. Set environment variable: E2E_PASSWORD_ADMIN_LOGIN_NAME")
	}
	if c.AdminLoginPassword == "" {
		return errors.New("AdminLoginPassword is empty. Set environment variable: E2E_PASSWORD_ADMIN_PASSWORD")
	}

	return nil
}

func loadConfig() (*config, error) {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	err = c.validate()
	if err != nil {
		return nil, err
	}

	return &c, err
}

// NewApiClient creates a new Api client for the specified Boundary instance and
// attempts to authenticate it. Returns the client.
func NewApiClient() (*api.Client, error) {
	c, err := loadConfig()
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
		map[string]interface{}{
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

// AuthenticateCli uses the cli to authenticate the specified Boundary instance.
func AuthenticateCli(t testing.TB) {
	c, err := loadConfig()
	require.NoError(t, err)

	output := e2e.RunCommand("boundary", "authenticate", "password",
		"-addr", c.Address,
		"-auth-method-id", c.AuthMethodId,
		"-login-name", c.AdminLoginName,
		"-password", "env://E2E_PASSWORD_ADMIN_PASSWORD",
	)
	require.NoError(t, output.Err, string(output.Stderr))
}
