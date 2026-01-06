// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authtokens_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestList(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	token := tc.Token()
	client := tc.Client()
	client.SetToken(token.Token)

	org := iam.TestOrg(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	amClient := authmethods.NewClient(client)
	amResult, err := amClient.Create(tc.Context(), "password", org.GetPublicId())
	require.NoError(err)
	require.NotNil(amResult)
	amId := amResult.Item.Id

	scopeClient := scopes.NewClient(client)
	scopeResult, err := scopeClient.Update(tc.Context(), org.PublicId, org.Version, scopes.WithAutomaticVersioning(true), scopes.WithPrimaryAuthMethodId(amId))
	require.NoError(err)
	require.NotNil(scopeResult)
	require.Equal(amId, scopeResult.Item.PrimaryAuthMethodId)

	rolesClient := roles.NewClient(client)
	role, err := rolesClient.Create(tc.Context(), org.GetPublicId())
	require.NoError(err)
	require.NotNil(role)
	role, err = rolesClient.AddPrincipals(tc.Context(), role.Item.Id, 0, []string{globals.AnonymousUserId}, roles.WithAutomaticVersioning(true))
	require.NoError(err)
	require.NotNil(role)
	role, err = rolesClient.AddGrants(tc.Context(), role.Item.Id, 0, []string{"ids=*;type=auth-method;actions=authenticate"}, roles.WithAutomaticVersioning(true))
	require.NoError(err)
	require.NotNil(role)

	acctClient := accounts.NewClient(client)
	acct, err := acctClient.Create(tc.Context(), amId, accounts.WithPasswordAccountLoginName("user"), accounts.WithPasswordAccountPassword("passpass"))
	require.NoError(err)
	require.NotNil(acct)

	tokens := authtokens.NewClient(client)

	atl, err := tokens.List(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.Empty(atl.Items)

	var expected []*authtokens.AuthToken
	methods := authmethods.NewClient(client)

	result, err := methods.Authenticate(tc.Context(), amId, "login", map[string]any{"login_name": "user", "password": "passpass"})
	require.NoError(err)
	token = new(authtokens.AuthToken)
	require.NoError(json.Unmarshal(result.GetRawAttributes(), token))
	expected = append(expected, token)

	atl, err = tokens.List(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(atl.Items))

	for i := 1; i < 10; i++ {
		result, err = methods.Authenticate(tc.Context(), amId, "login", map[string]any{"login_name": "user", "password": "passpass"})
		require.NoError(err)
		token = new(authtokens.AuthToken)
		require.NoError(json.Unmarshal(result.GetRawAttributes(), token))
		expected = append(expected, token)
	}
	atl, err = tokens.List(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(atl.Items))

	filterItem := atl.Items[3]
	atl, err = tokens.List(tc.Context(), org.GetPublicId(),
		authtokens.WithFilter(fmt.Sprintf(`"/item/id"==%q`, filterItem.Id)))
	require.NoError(err)
	assert.Len(atl.Items, 1)
	assert.Equal(filterItem.Id, atl.Items[0].Id)
}

func comparableResource(i *authtokens.AuthToken) authtokens.AuthToken {
	return authtokens.AuthToken{
		Id:                      i.Id,
		UserId:                  i.UserId,
		AuthMethodId:            i.AuthMethodId,
		CreatedTime:             i.CreatedTime,
		UpdatedTime:             i.UpdatedTime,
		ApproximateLastUsedTime: i.ApproximateLastUsedTime,
		ExpirationTime:          i.ExpirationTime,
	}
}

func comparableSlice(in []*authtokens.AuthToken) []authtokens.AuthToken {
	var filtered []authtokens.AuthToken
	for _, i := range in {
		filtered = append(filtered, comparableResource(i))
	}
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Id < filtered[j].Id
	})
	return filtered
}

func TestCrud(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	tokens := authtokens.NewClient(client)
	methods := authmethods.NewClient(client)

	result, err := methods.Authenticate(tc.Context(), tc.Server().DevPasswordAuthMethodId, "login", map[string]any{"login_name": "user", "password": "passpass"})
	require.NoError(err)
	wantToken := new(authtokens.AuthToken)
	require.NoError(json.Unmarshal(result.GetRawAttributes(), wantToken))

	at, err := tokens.Read(tc.Context(), wantToken.Id)
	require.NoError(err)
	assert.EqualValues(comparableResource(wantToken), comparableResource(at.Item))

	_, err = tokens.Delete(tc.Context(), at.Item.Id)
	require.NoError(err)
}

func TestErrors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	tokens := authtokens.NewClient(client)

	_, err := tokens.Read(tc.Context(), globals.AuthTokenPrefix+"_doesntexis")
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = tokens.Read(tc.Context(), "invalid id")
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
}
