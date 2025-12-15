// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package managedgroups_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/managedgroups"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListOidc(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	require.NotNil(client)
	token := tc.Token()
	require.NotNil(token)
	client.SetToken(token.Token)
	org := iam.TestOrg(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	amClient := authmethods.NewClient(client)

	amResult, err := amClient.Create(tc.Context(), "oidc", org.PublicId,
		authmethods.WithName("foo"),
		authmethods.WithOidcAuthMethodApiUrlPrefix("https://api.com"),
		authmethods.WithOidcAuthMethodIssuer("https://example.com"),
		authmethods.WithOidcAuthMethodClientSecret("secret"),
		authmethods.WithOidcAuthMethodClientId("client-id"))
	require.NoError(err)
	require.NotNil(amResult)
	am := amResult.Item

	managedgroupClient := managedgroups.NewClient(client)

	lr, err := managedgroupClient.List(tc.Context(), am.Id)
	require.NoError(err)
	expected := lr.Items
	assert.Len(expected, 0)

	cr, err := managedgroupClient.Create(tc.Context(), am.Id,
		managedgroups.WithOidcManagedGroupFilter("subject==subject0"))
	require.NoError(err)
	expected = append(expected, cr.Item)

	ulResult, err := managedgroupClient.List(tc.Context(), am.Id)
	require.NoError(err)
	assert.ElementsMatch(comparableSlice(expected[:1]), comparableSlice(ulResult.Items))

	for i := 1; i < 10; i++ {
		newManagedGroupResult, err := managedgroupClient.Create(tc.Context(), am.Id,
			managedgroups.WithOidcManagedGroupFilter(fmt.Sprintf("subject==subject%d", i)))
		require.NoError(err)
		expected = append(expected, newManagedGroupResult.Item)
	}
	ulResult, err = managedgroupClient.List(tc.Context(), am.Id)
	require.NoError(err)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(ulResult.Items))

	filterItem := expected[3]
	ulResult, err = managedgroupClient.List(tc.Context(), am.Id,
		managedgroups.WithFilter(fmt.Sprintf(`"/item/attributes/filter"==%q`, filterItem.Attributes["filter"])))
	require.NoError(err)
	require.Len(ulResult.Items, 1)
	assert.Equal(filterItem.Id, ulResult.Items[0].Id)
}

func comparableSlice(in []*managedgroups.ManagedGroup) []managedgroups.ManagedGroup {
	var filtered []managedgroups.ManagedGroup
	for _, i := range in {
		p := managedgroups.ManagedGroup{
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

func TestCrudOidc(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	amClient := authmethods.NewClient(client)
	amResult, err := amClient.Create(tc.Context(), "oidc", "global",
		authmethods.WithName("foo"),
		authmethods.WithOidcAuthMethodApiUrlPrefix("https://api.com"),
		authmethods.WithOidcAuthMethodIssuer("https://example.com"),
		authmethods.WithOidcAuthMethodClientSecret("secret"),
		authmethods.WithOidcAuthMethodClientId("client-id"))
	require.NoError(err)
	require.NotNil(amResult)
	amId := amResult.Item.Id

	managedgroupClient := managedgroups.NewClient(client)

	checkmanagedgroup := func(step string, u *managedgroups.ManagedGroup, err error, wantedName string, wantedVersion uint32) {
		assert.NoError(err, step)
		require.NotNil(u, "returned no resource", step)
		gotName := ""
		if u.Name != "" {
			gotName = u.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.EqualValues(wantedVersion, u.Version)
	}

	u, err := managedgroupClient.Create(tc.Context(), amId, managedgroups.WithName("foo"),
		managedgroups.WithOidcManagedGroupFilter("subject==subject0"))
	checkmanagedgroup("create", u.Item, err, "foo", 1)

	u, err = managedgroupClient.Read(tc.Context(), u.Item.Id)
	checkmanagedgroup("read", u.Item, err, "foo", 1)

	u, err = managedgroupClient.Update(tc.Context(), u.Item.Id, u.Item.Version, managedgroups.WithName("bar"))
	checkmanagedgroup("update", u.Item, err, "bar", 2)

	u, err = managedgroupClient.Update(tc.Context(), u.Item.Id, u.Item.Version, managedgroups.DefaultName())
	checkmanagedgroup("update", u.Item, err, "", 3)

	_, err = managedgroupClient.Delete(tc.Context(), u.Item.Id)
	require.NoError(err)
}

func TestErrors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	amId := token.AuthMethodId
	managedgroupClient := managedgroups.NewClient(client)

	// amIs is a password authmethod, password does not have managed groups
	_, err := managedgroupClient.Create(tc.Context(), amId)
	require.Error(err)

	_, err = managedgroupClient.Read(tc.Context(), "invalid id")
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
}

func TestErrorsOidc(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)

	amClient := authmethods.NewClient(client)
	amResult, err := amClient.Create(tc.Context(), "oidc", "global",
		authmethods.WithName("foo"),
		authmethods.WithOidcAuthMethodApiUrlPrefix("https://api.com"),
		authmethods.WithOidcAuthMethodIssuer("https://example.com"),
		authmethods.WithOidcAuthMethodClientSecret("secret"),
		authmethods.WithOidcAuthMethodClientId("client-id"))
	require.NoError(err)
	require.NotNil(amResult)
	amId := amResult.Item.Id

	managedgroupClient := managedgroups.NewClient(client)

	u, err := managedgroupClient.Create(tc.Context(), amId,
		managedgroups.WithName("foo"),
		managedgroups.WithOidcManagedGroupFilter("subject==subject1"))
	require.NoError(err)
	assert.NotNil(u)

	// A malformed id is processed as the id and not a different path to the api.
	_, err = managedgroupClient.Read(tc.Context(), fmt.Sprintf("%s/../", u.Item.Id))
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
	require.Len(apiErr.Details.RequestFields, 1)
	assert.Equal(apiErr.Details.RequestFields[0].Name, "id")

	// Updating the wrong version should fail.
	_, err = managedgroupClient.Update(tc.Context(), u.Item.Id, 73, managedgroups.WithName("anything"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	// Create another resource with the same name.
	_, err = managedgroupClient.Create(tc.Context(), amId,
		managedgroups.WithName("foo"),
		managedgroups.WithOidcManagedGroupFilter("subject==subject1"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)

	_, err = managedgroupClient.Read(tc.Context(), globals.OidcManagedGroupPrefix+"_doesntexis")
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = managedgroupClient.Read(tc.Context(), "invalid id")
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())

	_, err = managedgroupClient.Update(tc.Context(), u.Item.Id, u.Item.Version)
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
}
