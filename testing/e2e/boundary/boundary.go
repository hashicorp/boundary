package boundary

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/testing/e2e"
	"github.com/kelseyhightower/envconfig"
	"github.com/stretchr/testify/require"
)

type BoundaryVars struct {
	BoundaryAddress            string `envconfig:"BOUNDARY_ADDR" default:"http://127.0.0.1:9200"`
	BoundaryAuthMethodId       string `envconfig:"BOUNDARY_AUTHMETHOD_ID" default:"ampw_1234567890"`
	BoundaryAdminLoginName     string `envconfig:"BOUNDARY_AUTHENTICATE_PASSWORD_LOGIN_NAME" default:"admin"`
	BoundaryAdminLoginPassword string `envconfig:"BOUNDARY_AUTHENTICATE_PASSWORD_PASSWORD"`
}

func NewApiClient(t *testing.T) (*api.Client, error) {
	var config BoundaryVars
	require.NoError(t, envconfig.Process("", &config))

	client, err := api.NewClient(&api.Config{
		Addr: config.BoundaryAddress,
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	authmethodsClient := authmethods.NewClient(client)
	authenticationResult, err := authmethodsClient.Authenticate(ctx, config.BoundaryAuthMethodId, "login",
		map[string]interface{}{
			"login_name": config.BoundaryAdminLoginName,
			"password":   config.BoundaryAdminLoginPassword,
		},
	)
	if err != nil {
		return nil, err
	}

	client.SetToken(fmt.Sprint(authenticationResult.Attributes["token"]))
	return client, err
}

func AuthenticateCli(t *testing.T) e2e.CommandResult {
	var config BoundaryVars
	require.NoError(t, envconfig.Process("", &config))

	return e2e.RunCommand([]string{
		"boundary", "authenticate", "password",
		"-addr", config.BoundaryAddress,
		"-auth-method-id", config.BoundaryAuthMethodId,
		"-login-name", config.BoundaryAdminLoginName,
		"-password", "env://BOUNDARY_AUTHENTICATE_PASSWORD_PASSWORD",
	})
}
