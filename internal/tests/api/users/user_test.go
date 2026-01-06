// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package users_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/api/aliases"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const global = "global"

func TestAddSetRemoveAccounts(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	uClient := users.NewClient(client)
	aClient := accounts.NewClient(client)
	amClient := authmethods.NewClient(client)

	userAm, err := amClient.Create(tc.Context(), "password", global,
		authmethods.WithName("bar"))
	require.NoError(err)

	usr1, err := uClient.Create(tc.Context(), global)
	require.NoError(err)

	acct1, err := aClient.Create(tc.Context(), token.AuthMethodId, accounts.WithPasswordAccountLoginName("accountname"))
	require.NoError(err)
	acct2, err := aClient.Create(tc.Context(), userAm.Item.Id, accounts.WithPasswordAccountLoginName("accountname2"))
	require.NoError(err)

	addResult, err := uClient.AddAccounts(tc.Context(), usr1.Item.Id, 0, []string{acct1.Item.Id, acct2.Item.Id}, users.WithAutomaticVersioning(true))
	assert.NoError(err)
	assert.ElementsMatch([]string{acct1.Item.Id, acct2.Item.Id}, addResult.Item.AccountIds)

	// Add the account to the default user
	_, err = uClient.AddAccounts(tc.Context(), token.UserId, 0, []string{acct1.Item.Id}, users.WithAutomaticVersioning(true))
	assert.Error(err)

	remResult, err := uClient.RemoveAccounts(tc.Context(), usr1.Item.Id, 0, []string{acct1.Item.Id}, users.WithAutomaticVersioning(true))
	assert.NoError(err)
	assert.ElementsMatch([]string{acct2.Item.Id}, remResult.Item.AccountIds)

	// Cannot remove an account that isn't associated with a user.
	_, err = uClient.RemoveAccounts(tc.Context(), usr1.Item.Id, 0, []string{acct1.Item.Id}, users.WithAutomaticVersioning(true))
	assert.Error(err)

	setResult, err := uClient.SetAccounts(tc.Context(), usr1.Item.Id, 0, []string{acct1.Item.Id, acct2.Item.Id}, users.WithAutomaticVersioning(true))
	assert.NoError(err)
	assert.ElementsMatch([]string{acct1.Item.Id, acct2.Item.Id}, setResult.Item.AccountIds)
}

func TestList(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	org := iam.TestOrg(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	userClient := users.NewClient(client)

	ul, err := userClient.List(tc.Context(), org.GetPublicId())
	assert.NoError(err)
	assert.Empty(ul.Items)

	var expected []*users.User
	for i := 0; i < 10; i++ {
		expected = append(expected, &users.User{Name: fmt.Sprint(i)})
	}

	ucr, err := userClient.Create(tc.Context(), org.GetPublicId(), users.WithName(expected[0].Name))
	assert.NoError(err)
	expected[0] = ucr.Item

	ul, err = userClient.List(tc.Context(), org.GetPublicId())
	assert.NoError(err)
	assert.ElementsMatch(comparableSlice(expected[:1]), comparableSlice(ul.Items))

	for i := 1; i < 10; i++ {
		ucr, err = userClient.Create(tc.Context(), org.GetPublicId(), users.WithName(expected[i].Name))
		assert.NoError(err)
		expected[i] = ucr.Item
	}
	ul, err = userClient.List(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(ul.Items))

	filterItem := ul.Items[3]
	ul, err = userClient.List(tc.Context(), org.GetPublicId(),
		users.WithFilter(fmt.Sprintf(`"/item/id"==%q`, filterItem.Id)))
	require.NoError(err)
	assert.Len(ul.Items, 1)
	assert.Equal(filterItem.Id, ul.Items[0].Id)
}

func comparableSlice(in []*users.User) []users.User {
	var filtered []users.User
	for _, i := range in {
		p := users.User{
			Id:          i.Id,
			Name:        i.Name,
			Description: i.Description,
			CreatedTime: i.CreatedTime,
			UpdatedTime: i.UpdatedTime,
		}
		filtered = append(filtered, p)
	}
	return filtered
}

func TestCrud(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	org := iam.TestOrg(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	userClient := users.NewClient(client)

	checkUser := func(step string, u *users.User, err error, wantedName string, wantedVersion uint32) {
		assert.NoError(err, step)
		assert.NotNil(u, "returned no resource", step)
		gotName := ""
		if u.Name != "" {
			gotName = u.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.EqualValues(wantedVersion, u.Version)
	}

	u, err := userClient.Create(tc.Context(), org.GetPublicId(), users.WithName("foo"))
	checkUser("create", u.Item, err, "foo", 1)

	u, err = userClient.Read(tc.Context(), u.Item.Id)
	checkUser("read", u.Item, err, "foo", 1)

	u, err = userClient.Update(tc.Context(), u.Item.Id, u.Item.Version, users.WithName("bar"))
	checkUser("update", u.Item, err, "bar", 2)

	u, err = userClient.Update(tc.Context(), u.Item.Id, u.Item.Version, users.DefaultName())
	checkUser("update", u.Item, err, "", 3)

	_, err = userClient.Delete(tc.Context(), u.Item.Id)
	require.NoError(err)

	_, err = userClient.Delete(tc.Context(), u.Item.Id)
	require.Error(err)
	apiErr := api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())
}

func TestListResolvableAliases(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)

	{
		tarClient := targets.NewClient(client)
		resp, err := tarClient.List(tc.Context(), "global", targets.WithRecursive(true))
		require.NoError(err)
		require.Len(resp.Items, 2)
		firstTargetId := resp.Items[0].Id
		secondTargetId := resp.Items[1].Id

		// Delete the old authenticated user grants
		rclient := roles.NewClient(client)
		rresp, err := rclient.List(tc.Context(), "global", roles.WithRecursive(true))
		require.NoError(err)
		require.NotEmpty(t, rresp.Items)
		for _, r := range rresp.Items {
			if r.Name == "Authenticated User Grants" {
				_, err = rclient.Delete(tc.Context(), r.Id)
				require.NoError(err)
				break
			}
		}

		// add 1 grant to the unauthorized user for only a single target
		newR, err := rclient.Create(tc.Context(), "global", roles.WithName("my role"))
		require.NoError(err)
		_, err = rclient.AddPrincipals(tc.Context(), newR.Item.Id, 0, []string{tc.UnprivilegedToken().UserId}, roles.WithAutomaticVersioning(true))
		require.NoError(err)
		roleAfterGrants, err := rclient.AddGrants(tc.Context(), newR.Item.Id, 0, []string{
			"ids={{.User.Id}};type=user;actions=list-resolvable-aliases",
			fmt.Sprintf("ids=%s;type=target;actions=read", firstTargetId),
		}, roles.WithAutomaticVersioning(true))
		require.NoError(err)
		require.NotNil(t, roleAfterGrants)
		_, err = rclient.SetGrantScopes(tc.Context(), newR.Item.Id, 0, []string{"this", "descendants"}, roles.WithAutomaticVersioning(true))
		require.NoError(err)

		aliasClient := aliases.NewClient(client)
		aliasResp, err := aliasClient.Create(tc.Context(), "target", "global", aliases.WithValue("second"), aliases.WithDestinationId(secondTargetId))
		require.NoError(err)
		assert.NotNil(aliasResp)
		aliasResp, err = aliasClient.Create(tc.Context(), "target", "global", aliases.WithValue("first"), aliases.WithDestinationId(firstTargetId))
		require.NoError(err)
		assert.NotNil(aliasResp)
	}

	// request as admin for admin
	userClient := users.NewClient(client)
	resp, err := userClient.ListResolvableAliases(tc.Context(), token.UserId)
	require.NoError(err)
	assert.Len(resp.Items, 2)
	assert.Equal("first", resp.Items[0].Value)
	assert.NotEmpty(resp.Items[0].DestinationId)
	assert.Equal("second", resp.Items[1].Value)
	assert.NotEmpty(resp.Items[1].DestinationId)

	// request as admin for unprivileged
	resp, err = userClient.ListResolvableAliases(tc.Context(), tc.UnprivilegedToken().UserId)
	require.NoError(err)
	assert.Len(resp.Items, 1)
	assert.Equal("first", resp.Items[0].Value)
	assert.NotEmpty(resp.Items[0].DestinationId)

	// Request as unprivileged for unprivileged
	client.SetToken(tc.UnprivilegedToken().Token)
	upUserClient := users.NewClient(client)
	resp, err = upUserClient.ListResolvableAliases(tc.Context(), tc.UnprivilegedToken().UserId)
	require.NoError(err)
	assert.Len(resp.Items, 1)
	assert.Equal("first", resp.Items[0].Value)
	assert.NotEmpty(resp.Items[0].DestinationId)

	// Request as unprivileged for admin
	_, err = upUserClient.ListResolvableAliases(tc.Context(), tc.Token().UserId)
	require.Error(err)
	apiErr := api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusForbidden, apiErr.Response().StatusCode())
}

func TestErrors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	org := iam.TestOrg(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	userClient := users.NewClient(client)

	u, err := userClient.Create(tc.Context(), org.GetPublicId(), users.WithName("first"))
	require.NoError(err)
	assert.NotNil(u)

	// A malformed id is processed as the id and not a different path to the api.
	_, err = userClient.Read(tc.Context(), fmt.Sprintf("%s/../", u.Item.Id))
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
	require.Len(apiErr.Details.RequestFields, 1)
	assert.Equal(apiErr.Details.RequestFields[0].Name, "id")

	// Updating the wrong version should fail.
	_, err = userClient.Update(tc.Context(), u.Item.Id, 73, users.WithName("anything"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	// Create another resource with the same name.
	_, err = userClient.Create(tc.Context(), org.GetPublicId(), users.WithName("first"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)

	_, err = userClient.Read(tc.Context(), globals.UserPrefix+"_doesntexis")
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = userClient.Read(tc.Context(), "invalid id")
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())

	_, err = userClient.Update(tc.Context(), u.Item.Id, u.Item.Version)
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
}
