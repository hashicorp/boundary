package servers_test

import (
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/recovery"
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
	_, err = roleClient.Create(tc.Context(), scope.Global.String())
	require.NoError(err)
	nonces, err := repo.ListNonces(tc.Context())
	require.NoError(err)
	assert.Len(nonces, 1)

	// Token 1, try 2
	_, err = roleClient.Create(tc.Context(), scope.Global.String())
	require.Error(err)
	nonces, err = repo.ListNonces(tc.Context())
	require.NoError(err)
	assert.Len(nonces, 1)

	// Token 2
	roleClient.ApiClient().SetToken(token2)
	_, err = roleClient.Create(tc.Context(), scope.Global.String())
	require.NoError(err)
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
		_, err = roleClient.Create(tc.Context(), scope.Global.String())
		require.Error(err)
		nonces, err = repo.ListNonces(tc.Context())
		require.NoError(err)
		assert.Len(nonces, 0)
	}
}

func TestTagUpdatingListing(t *testing.T) {
	require := require.New(t)

	wrapper := db.TestWrapper(t)
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		RecoveryKms: wrapper,
	})
	defer tc.Shutdown()

	repo := tc.ServersRepo()
	srv := &servers.Server{
		PrivateId: "test1",
		Type:      "worker",
		Address:   "127.0.0.1",
		Tags: map[string]*servers.TagValues{
			"tag1": {
				Values: []string{"value1", "value2"},
			},
		},
	}
	_, _, err := repo.UpsertServer(tc.Context(), srv, servers.WithUpdateTags(true))
	require.NoError(err)

	srv = &servers.Server{
		PrivateId: "test2",
		Type:      "worker",
		Address:   "127.0.0.1",
		Tags: map[string]*servers.TagValues{
			"tag2": {
				Values: []string{"value1", "value2"},
			},
		},
	}
	_, _, err = repo.UpsertServer(tc.Context(), srv, servers.WithUpdateTags(true))
	require.NoError(err)

	tags, err := repo.ListTagsForServers(tc.Context(), []string{"test1", "test2"})
	require.NoError(err)

	// Base case
	exp := []*servers.ServerTag{
		{
			ServerId: "test1",
			Key:      "tag1",
			Value:    "value1",
		},
		{
			ServerId: "test1",
			Key:      "tag1",
			Value:    "value2",
		},
		{
			ServerId: "test2",
			Key:      "tag2",
			Value:    "value1",
		},
		{
			ServerId: "test2",
			Key:      "tag2",
			Value:    "value2",
		},
	}
	require.Equal(exp, tags)

	// Update without saying to update tags
	srv = &servers.Server{
		PrivateId: "test2",
		Type:      "worker",
		Address:   "192.168.1.1",
		Tags: map[string]*servers.TagValues{
			"tag22": {
				Values: []string{"value21", "value22"},
			},
		},
	}
	_, _, err = repo.UpsertServer(tc.Context(), srv)
	require.NoError(err)
	tags, err = repo.ListTagsForServers(tc.Context(), []string{"test1", "test2"})
	require.NoError(err)
	require.Equal(exp, tags)

	// Update tags and test again
	_, _, err = repo.UpsertServer(tc.Context(), srv, servers.WithUpdateTags(true))
	require.NoError(err)
	tags, err = repo.ListTagsForServers(tc.Context(), []string{"test1", "test2"})
	require.NoError(err)
	require.NotEqual(exp, tags)
	// Update and try again
	exp[2] = &servers.ServerTag{
		ServerId: "test2",
		Key:      "tag22",
		Value:    "value21",
	}
	exp[3] = &servers.ServerTag{
		ServerId: "test2",
		Key:      "tag22",
		Value:    "value22",
	}
	require.Equal(exp, tags)
}
