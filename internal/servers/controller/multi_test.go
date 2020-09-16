package controller_test

import (
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticationMulti(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	amId := "ampw_1234567890"
	user := "user"
	password := "passpass"
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		DefaultAuthMethodId: amId,
		DefaultLoginName:    user,
		DefaultPassword:     password,
		Logger:              logger.Named("c1"),
	})
	defer c1.Shutdown()

	c2 := c1.AddClusterControllerMember(t, &controller.TestControllerOpts{
		Logger: logger.Named("c2"),
	})
	defer c2.Shutdown()

	auth := authmethods.NewClient(c1.Client())
	token1Result, apiErr, err := auth.Authenticate(c1.Context(), amId, map[string]interface{}{"login_name": user, "password": password})
	require.Nil(err)
	require.Nil(apiErr)
	token1 := token1Result.Item
	require.NotNil(token1)

	time.Sleep(5 * time.Second)
	auth = authmethods.NewClient(c2.Client())
	token2Result, apiErr, err := auth.Authenticate(c2.Context(), amId, map[string]interface{}{"login_name": user, "password": password})
	require.Nil(err)
	require.Nil(apiErr)
	token2 := token2Result.Item
	require.NotNil(token2)

	assert.NotEqual(token1.Token, token2.Token)

	c1.Client().SetToken(token1.Token)
	c2.Client().SetToken(token1.Token) // Same token, as it should work on both

	// Create a project, read from the other
	org, apiErr, err := scopes.NewClient(c1.Client()).Create(c1.Context(), scope.Global.String())
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(org.Item)

	proj, apiErr, err := scopes.NewClient(c2.Client()).Read(c2.Context(), org.Item.Id)
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(proj.Item)
}
