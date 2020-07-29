package scopes_test

import (
	"testing"

	"github.com/hashicorp/watchtower/api2/scopes"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScope_ReadAndDelete(t *testing.T) {
	orgId := "o_1234567890"
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultOrgId:                 orgId,
	})
	defer tc.Shutdown()

	client := tc.Client()
	ctx := tc.Context()

	s := scopes.New(client)
	scp, apiErr, err := s.Read(ctx, orgId)
	require.NoError(t, err)
	require.Nil(t, apiErr)
	assert.Equal(t, scp, scp)

	existed, apiErr, err := s.Delete(ctx, scp.Id)
	require.NoError(t, err)
	require.Nil(t, apiErr)
	assert.True(t, existed)

	existed, apiErr, err = s.Delete(ctx, scp.Id)
	require.NoError(t, err)
	require.Nil(t, apiErr)
	assert.False(t, existed)

	_, apiErr, err = s.Read(ctx, scp.Id)
	require.NoError(t, err)
	require.NotNil(t, apiErr)
}
