// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package aliases_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/aliases"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
)

func TestList(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	scopeId := "global"

	client := tc.Client()
	require.NotNil(client)
	token := tc.Token()
	require.NotNil(token)
	client.SetToken(token.Token)

	aliasClient := aliases.NewClient(client)

	lr, err := aliasClient.List(tc.Context(), scopeId)
	require.NoError(err)
	expected := lr.Items
	assert.Len(expected, 0)

	cr, err := aliasClient.Create(tc.Context(), "target", scopeId, aliases.WithValue("alias0"))
	require.NoError(err)
	require.NotNil(cr)
	expected = append(expected, cr.Item)

	ulResult, err := aliasClient.List(tc.Context(), scopeId)
	require.NoError(err)
	assert.ElementsMatch(comparableSlice(expected[:1]), comparableSlice(ulResult.Items))

	for i := 1; i < 10; i++ {
		newAcctResult, err := aliasClient.Create(tc.Context(), "target", scopeId, aliases.WithValue(fmt.Sprintf("alias%d", i)))
		require.NoError(err)
		expected = append(expected, newAcctResult.Item)
	}
	ulResult, err = aliasClient.List(tc.Context(), scopeId)
	require.NoError(err)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(ulResult.Items))

	filterItem := expected[3]

	ulResult, err = aliasClient.List(tc.Context(), scopeId, aliases.WithFilter(fmt.Sprintf(`"/item/value"==%q`, filterItem.Value)))
	require.NoError(err)
	require.Len(ulResult.Items, 1)
	assert.Equal(filterItem.Id, ulResult.Items[0].Id)
}

func comparableSlice(in []*aliases.Alias) []aliases.Alias {
	var filtered []aliases.Alias
	for _, i := range in {
		p := aliases.Alias{
			Id:          i.Id,
			Name:        i.Name,
			Description: i.Description,
			CreatedTime: i.CreatedTime,
			UpdatedTime: i.UpdatedTime,
			Attributes:  i.Attributes,
		}
		filtered = append(filtered, p)
	}
	return filtered
}

func TestCrud(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	scopeId := "global"

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)

	tarResp, err := targets.NewClient(client).Create(tc.Context(), "tcp", "p_1234567890", targets.WithName("target"), targets.WithTcpTargetDefaultPort(22))
	require.NoError(err)
	require.NotNil(tarResp)
	tar := tarResp.Item

	aliasClient := aliases.NewClient(client)

	checkAlias := func(step string, u *aliases.Alias, err error, wantedName string, wantedVersion uint32) {
		assert.NoError(err, step)
		require.NotNil(u, "returned no resource", step)
		gotValue := ""
		if u.Value != "" {
			gotValue = u.Value
		}
		assert.Equal(wantedName, gotValue, step)
		assert.EqualValues(wantedVersion, u.Version)
	}

	u, err := aliasClient.Create(tc.Context(), "target", scopeId,
		aliases.WithValue("alias.value"),
		aliases.WithDestinationId(tar.Id),
		aliases.WithTargetAliasAuthorizeSessionArgumentsHostId("hst_1234567890"))
	assert.NoError(err)
	require.NotNil(u)
	checkAlias("create", u.Item, err, "alias.value", 1)

	attrs, err := aliases.AttributesMapToTargetAliasAttributes(u.Item.Attributes)
	assert.NoError(err)
	require.NotNil(attrs)
	require.NotNil(attrs.AuthorizeSessionArguments)
	assert.Equal("hst_1234567890", attrs.AuthorizeSessionArguments.HostId)

	u, err = aliasClient.Read(tc.Context(), u.Item.Id)
	checkAlias("read", u.Item, err, "alias.value", 1)

	u, err = aliasClient.Update(tc.Context(), u.Item.Id, u.Item.Version, aliases.WithValue("bar"), aliases.WithTargetAliasAuthorizeSessionArgumentsHostId("hst_0987654321"))
	assert.NoError(err)
	require.NotNil(u)
	checkAlias("update", u.Item, err, "bar", 2)
	attrs, err = aliases.AttributesMapToTargetAliasAttributes(u.Item.Attributes)
	assert.NoError(err)
	require.NotNil(attrs)
	require.NotNil(attrs.AuthorizeSessionArguments)
	assert.Equal("hst_0987654321", attrs.AuthorizeSessionArguments.HostId)

	u, err = aliasClient.Update(tc.Context(), u.Item.Id, u.Item.Version, aliases.WithValue("bar"), aliases.DefaultTargetAliasAuthorizeSessionArgumentsHostId())
	assert.NoError(err)
	require.NotNil(u)
	checkAlias("update", u.Item, err, "bar", 3)
	assert.Nil(u.Item.Attributes)

	_, err = aliasClient.Delete(tc.Context(), u.Item.Id)
	require.NoError(err)
}

func TestErrors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	scopeId := "global"

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	aliasClient := aliases.NewClient(client)

	u, err := aliasClient.Create(tc.Context(), "target", scopeId, aliases.WithValue("first"))
	require.NoError(err)
	assert.NotNil(u)

	// Creating an alias of an unknown type
	_, err = aliasClient.Create(tc.Context(), "unknown", scopeId, aliases.WithValue("first"))
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
	require.Len(apiErr.Details.RequestFields, 1)
	assert.Equal(apiErr.Details.RequestFields[0].Name, "type")

	// A malformed id is processed as the id and not a different path to the api.
	_, err = aliasClient.Read(tc.Context(), fmt.Sprintf("%s/../", u.Item.Id))
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
	require.Len(apiErr.Details.RequestFields, 1)
	assert.Equal(apiErr.Details.RequestFields[0].Name, "id")

	// Updating the wrong version should fail.
	_, err = aliasClient.Update(tc.Context(), u.Item.Id, 73, aliases.WithValue("anything"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	// Removing the value completely should fail.
	_, err = aliasClient.Update(tc.Context(), u.Item.Id, u.Item.Version, aliases.DefaultValue())
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())

	// Create another resource with the same name.
	_, err = aliasClient.Create(tc.Context(), "target", scopeId)
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)

	_, err = aliasClient.Read(tc.Context(), globals.TargetAliasPrefix+"_doesntexis")
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = aliasClient.Read(tc.Context(), "invalid id")
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())

	_, err = aliasClient.Update(tc.Context(), u.Item.Id, u.Item.Version)
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
}
