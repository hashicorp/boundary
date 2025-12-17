// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package controller_test

import (
	"encoding/json"
	"testing"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticationMulti(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Logger: logger.Named("c1"),
	})
	defer c1.Shutdown()

	c2 := c1.AddClusterControllerMember(t, &controller.TestControllerOpts{
		Logger: logger.Named("c2"),
	})
	defer c2.Shutdown()

	auth := authmethods.NewClient(c1.Client())
	token1Result, err := auth.Authenticate(c1.Context(), c1.Server().DevPasswordAuthMethodId, "login", map[string]any{"login_name": c1.Server().DevLoginName, "password": c1.Server().DevPassword})
	require.Nil(err)
	token1 := new(authtokens.AuthToken)
	require.NoError(json.Unmarshal(token1Result.GetRawAttributes(), token1))
	require.NotNil(token1)

	auth = authmethods.NewClient(c2.Client())
	token2Result, err := auth.Authenticate(c2.Context(), c2.Server().DevPasswordAuthMethodId, "login", map[string]any{"login_name": c2.Server().DevLoginName, "password": c2.Server().DevPassword})
	require.Nil(err)
	token2 := new(authtokens.AuthToken)
	require.NoError(json.Unmarshal(token2Result.GetRawAttributes(), token2))
	require.NotNil(token2)

	assert.NotEqual(token1.Token, token2.Token)

	c1.Client().SetToken(token1.Token)
	c2.Client().SetToken(token1.Token) // Same token, as it should work on both

	// Create a project, read from the other
	org, err := scopes.NewClient(c1.Client()).Create(c1.Context(), scope.Global.String())
	require.NoError(err)
	require.NotNil(org.Item)

	proj, err := scopes.NewClient(c2.Client()).Read(c2.Context(), org.Item.Id)
	require.NoError(err)
	require.NotNil(proj.Item)
}
