package cluster

import (
	"testing"

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

	// Anon user has list and read permissions on scopes by default,
	// verify that list scopes returns expected scope without setting token
	client := c1.Client()
	scps, err := scopes.NewClient(client).List(c1.Context(), scope.Global.String())
	require.NoError(err)
	require.Len(scps.Items, 1)
}
