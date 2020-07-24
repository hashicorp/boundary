package roles_test

import (
	"testing"

	"github.com/hashicorp/watchtower/api2/roles"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRole_Crud(t *testing.T) {
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultOrgId:                 "o_1234567890",
	})
	defer tc.Shutdown()

	client := tc.Client()
	ctx := tc.Context()

	rClient := roles.New(client)
	role, apiErr, err := rClient.Create(ctx)
	require.NoError(t, err)
	require.Nil(t, apiErr)
	t.Logf("Got %#v", role)

	readResource, apiErr, err := rClient.Read(ctx, role.Id)
	require.NoError(t, err)
	require.Nil(t, apiErr)
	assert.Equal(t, role, readResource)

	listedResources, apiErr, err := rClient.List(ctx)
	require.NoError(t, err)
	require.Nil(t, apiErr)
	assert.Contains(t, listedResources, *readResource)

	existed, apiErr, err := rClient.Delete(ctx, role.Id)
	require.NoError(t, err)
	require.Nil(t, apiErr)
	assert.True(t, existed)

	existed, apiErr, err = rClient.Delete(ctx, role.Id)
	require.NoError(t, err)
	require.Nil(t, apiErr)
	assert.False(t, existed)

	_, apiErr, err = rClient.Read(ctx, role.Id)
	require.NoError(t, err)
	require.NotNil(t, apiErr)
}
