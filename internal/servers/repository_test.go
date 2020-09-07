package servers_test

import (
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/recovery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecoveryNonces(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	// Set these low so that we can not have the test run forever
	globals.RecoveryTokenValidityPeriod = 10 * time.Second
	controller.RecoveryNonceCleanupInterval = 20 * time.Second

	wrapper := db.TestWrapper(t)
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		RecoveryKms: wrapper,
	})
	defer tc.Shutdown()

	client := tc.Client()
	repo := tc.ServersRepo()

	// First, validate that we can't use the same token twice. Get two tokens,
	// try to use the first twice (should succeed first time, fail second), then
	// ensure second token works
	token1, err := recovery.GenerateRecoveryToken(tc.Context(), wrapper)
	require.NoError(err)
	token2, err := recovery.GenerateRecoveryToken(tc.Context(), wrapper)
	require.NoError(err)

	// Token 1, try 1
	client.SetToken(token1)
	roleClient := roles.NewClient(client)
	_, apiErr, err := roleClient.Create(tc.Context(), scope.Global.String())
	require.NoError(err)
	assert.Nil(apiErr)
	nonces, err := repo.ListNonces(tc.Context())
	require.NoError(err)
	assert.Len(nonces, 1)

	// Token 1, try 2
	_, apiErr, err = roleClient.Create(tc.Context(), scope.Global.String())
	require.NoError(err)
	assert.NotNil(apiErr)
	nonces, err = repo.ListNonces(tc.Context())
	require.NoError(err)
	assert.Len(nonces, 1)

	// Token 2
	roleClient.ApiClient().SetToken(token2)
	_, apiErr, err = roleClient.Create(tc.Context(), scope.Global.String())
	require.NoError(err)
	assert.Nil(apiErr)
	nonces, err = repo.ListNonces(tc.Context())
	require.NoError(err)
	assert.Len(nonces, 2)

	// Make sure they get cleaned up
	time.Sleep(2 * controller.RecoveryNonceCleanupInterval)
	nonces, err = repo.ListNonces(tc.Context())
	require.NoError(err)
	assert.Len(nonces, 0)

	// And finally, make sure they still can't be used
	for _, token := range []string{token1, token2} {
		roleClient.ApiClient().SetToken(token)
		_, apiErr, err = roleClient.Create(tc.Context(), scope.Global.String())
		require.NoError(err)
		assert.NotNil(apiErr)
		nonces, err = repo.ListNonces(tc.Context())
		require.NoError(err)
		assert.Len(nonces, 0)
	}
}
