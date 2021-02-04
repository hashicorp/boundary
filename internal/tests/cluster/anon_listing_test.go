package cluster

import (
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestAnonListing(t *testing.T) {
	require := require.New(t)
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	conf, err := config.DevController()
	require.NoError(err)

	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config:                 conf,
		InitialResourcesSuffix: "1234567890",
		Logger:                 logger,
	})
	defer c1.Shutdown()

	// Should get no scopes back because anon user doesn't have permissions
	client := c1.Client()
	scps, err := scopes.NewClient(client).List(c1.Context(), scope.Global.String())
	require.NoError(err)
	require.Len(scps.Items, 0)

	// Authenticate as admin
	client.SetToken(c1.Token().Token)

	// Should get an org scope back
	scps, err = scopes.NewClient(client).List(c1.Context(), scope.Global.String())
	require.NoError(err)
	require.Len(scps.Items, 1)

	// Create a new role, give read action on the scope, add u_anon
	orgId := scps.Items[0].Id
	role, err := roles.NewClient(client).Create(c1.Context(), scope.Global.String())
	require.NoError(err)
	_, err = roles.NewClient(client).AddGrants(c1.Context(), role.Item.Id, 0, []string{fmt.Sprintf("id=%s;actions=read", orgId)}, roles.WithAutomaticVersioning(true))
	require.NoError(err)
	_, err = roles.NewClient(client).AddPrincipals(c1.Context(), role.Item.Id, 0, []string{"u_anon"}, roles.WithAutomaticVersioning(true))
	require.NoError(err)
	// Go back to anonymous
	client.SetToken("")
	scps, err = scopes.NewClient(client).List(c1.Context(), scope.Global.String())
	require.NoError(err)
	require.Len(scps.Items, 1)
}
