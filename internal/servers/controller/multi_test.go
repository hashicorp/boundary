package controller_test

import (
	"testing"

	"github.com/hashicorp/watchtower/api/authmethods"
	"github.com/hashicorp/watchtower/api/scopes"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticationMulti(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	amId := "paum_1234567890"
	user := "user"
	password := "passpass"
	orgId := "o_1234567890"

	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		DefaultOrgId:        orgId,
		DefaultAuthMethodId: amId,
		DefaultUsername:     user,
		DefaultPassword:     password,
	})
	defer c1.Shutdown()

	c2 := c1.AddClusterControllerMember(t, &controller.TestControllerOpts{
		Logger: c1.Config().Logger.ResetNamed("controller2"),
	})
	defer c2.Shutdown()

	auth := authmethods.NewAuthMethodsClient(c1.Client())
	token1, apiErr, err := auth.Authenticate(c1.Context(), amId, user, password)
	require.Nil(err)
	require.Nil(apiErr)
	require.NotNil(token1)

	auth = authmethods.NewAuthMethodsClient(c2.Client())
	token2, apiErr, err := auth.Authenticate(c2.Context(), amId, user, password)
	require.Nil(err)
	require.Nil(apiErr)
	require.NotNil(token2)

	assert.NotEqual(token1.Token, token2.Token)

	c1.Client().SetToken(token1.Token)
	c2.Client().SetToken(token1.Token) // Same token, as it should work on both

	// Create a project, read from the other
	proj, apiErr, err := scopes.NewScopesClient(c1.Client()).Create(c1.Context(), orgId)
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(proj)
	projId := proj.Id

	proj, apiErr, err = scopes.NewScopesClient(c2.Client()).Read(c2.Context(), projId)
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(proj)
}
