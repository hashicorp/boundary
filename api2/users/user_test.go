package users_test

import (
	"testing"

	"github.com/hashicorp/watchtower/api2/users"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUser_Crud(t *testing.T) {
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultOrgId:                 "o_1234567890",
	})
	defer tc.Shutdown()

	client := tc.Client()
	ctx := tc.Context()

	u := users.New(client)
	user, apiErr, err := u.Create(ctx)
	require.NoError(t, err)
	require.Nil(t, apiErr)
	t.Logf("Got %#v", user)

	readUser, apiErr, err := u.Read(ctx, user.Id)
	require.NoError(t, err)
	require.Nil(t, apiErr)
	assert.Equal(t, user, readUser)

	ul, apiErr, err := u.List(ctx)
	require.NoError(t, err)
	require.Nil(t, apiErr)
	assert.Equal(t, []users.User{*readUser}, ul)

	existed, apiErr, err := u.Delete(ctx, user.Id)
	require.NoError(t, err)
	require.Nil(t, apiErr)
	assert.True(t, existed)

	existed, apiErr, err = u.Delete(ctx, user.Id)
	require.NoError(t, err)
	require.Nil(t, apiErr)
	assert.False(t, existed)

	_, apiErr, err = u.Read(ctx, user.Id)
	require.NoError(t, err)
	require.NotNil(t, apiErr)
}
