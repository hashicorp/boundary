// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package parallel

import (
	"strings"
	"testing"

	amapi "github.com/hashicorp/boundary/api/authmethods"
	rolesapi "github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/require"
)

// This test validates the fix for ICU-2301
func TestListAnonymousRecursing(t *testing.T) {
	t.Parallel()

	require := require.New(t)
	tc := controller.NewTestController(t, nil)

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	amClient := amapi.NewClient(client)
	rolesClient := rolesapi.NewClient(client)
	orgScopeId := "o_1234567890"

	// Create a custom role in org scope
	customRole, err := rolesClient.Create(tc.Context(), orgScopeId)
	require.NoError(err)
	customRole, err = rolesClient.AddPrincipals(tc.Context(), customRole.Item.Id, customRole.Item.Version, []string{"u_anon"})
	require.NoError(err)
	_, err = rolesClient.AddGrants(tc.Context(), customRole.Item.Id, customRole.Item.Version, []string{"ids=*;type=auth-method;actions=list,authenticate"})
	require.NoError(err)

	// Create an auth method in org scope for the test
	am, err := amClient.Create(tc.Context(), "password", orgScopeId)
	require.NoError(err)
	require.NotNil(am)

	// We expect to see all four with the normal token
	l, err := amClient.List(tc.Context(), scope.Global.String(), amapi.WithRecursive(true))
	require.NoError(err)
	require.NotNil(l)
	require.Len(l.GetItems(), 4)

	// Originally we also expect to see all four as anon user
	amClient.ApiClient().SetToken("")
	l, err = amClient.List(tc.Context(), scope.Global.String(), amapi.WithRecursive(true))
	require.NoError(err)
	require.NotNil(l)
	require.Len(l.GetItems(), 4)

	// Find the global roles and delete them
	rl, err := rolesClient.List(tc.Context(), scope.Global.String())
	require.NoError(err)
	require.NotNil(rl)
	require.Len(rl.GetItems(), 3)

	// Find the non-admin one and delete that first
	adminRoleId := ""
	for _, role := range rl.GetItems() {
		if strings.Contains(role.Name, "Admin") {
			adminRoleId = role.Id
		} else {
			_, err = rolesClient.Delete(tc.Context(), role.Id)
			require.NoError(err)
		}
	}
	_, err = rolesClient.Delete(tc.Context(), adminRoleId)
	require.NoError(err)

	// Make sure we can't list in global
	_, err = amClient.List(tc.Context(), scope.Global.String())
	require.Error(err)

	// But we can still see 1 when recursing, from the org scope
	l, err = amClient.List(tc.Context(), scope.Global.String(), amapi.WithRecursive(true))
	require.NoError(err)
	require.NotNil(l)
	ams := l.GetItems()
	require.Len(ams, 1)
	require.Equal(orgScopeId, ams[0].ScopeId)
}
