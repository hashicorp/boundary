package groups_test

import (
	"testing"

	"github.com/hashicorp/watchtower/api2/groups"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGroup_Crud(t *testing.T) {
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultOrgId:                 "o_1234567890",
	})
	defer tc.Shutdown()

	client := tc.Client()
	ctx := tc.Context()

	g := groups.New(client)
	grp, apiErr, err := g.Create(ctx)
	require.NoError(t, err)
	require.Nil(t, apiErr)
	t.Logf("Got %#v", grp)

	readGroup, apiErr, err := g.Read(ctx, grp.Id)
	require.NoError(t, err)
	require.Nil(t, apiErr)
	assert.Equal(t, grp, readGroup)

	gl, apiErr, err := g.List(ctx)
	require.NoError(t, err)
	require.Nil(t, apiErr)
	assert.Equal(t, []groups.Group{*readGroup}, gl)

	existed, apiErr, err := g.Delete(ctx, grp.Id)
	require.NoError(t, err)
	require.Nil(t, apiErr)
	assert.True(t, existed)

	existed, apiErr, err = g.Delete(ctx, grp.Id)
	require.NoError(t, err)
	require.Nil(t, apiErr)
	assert.False(t, existed)

	_, apiErr, err = g.Read(ctx, grp.Id)
	require.NoError(t, err)
	require.NotNil(t, apiErr)
}
