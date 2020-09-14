package authtokens_test

import (
	"net/http"
	"sort"
	"testing"

	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestList(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	amId := "ampw_1234567890"
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DefaultAuthMethodId: amId,
		DefaultLoginName:    "user",
		DefaultPassword:     "passpass",
	})
	defer tc.Shutdown()

	token := tc.Token()
	client := tc.Client()
	client.SetToken(token.Token)

	org := iam.TestOrg(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	amClient := authmethods.NewClient(client)
	amResult, apiErr, err := amClient.Create(tc.Context(), "password", org.GetPublicId())
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(amResult)
	amId = amResult.Item.Id

	rolesClient := roles.NewClient(client)
	role, apiErr, err := rolesClient.Create(tc.Context(), org.GetPublicId())
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(role)
	role, apiErr, err = rolesClient.AddPrincipals(tc.Context(), role.Item.Id, 0, []string{"u_anon"}, roles.WithAutomaticVersioning(true))
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(role)
	role, apiErr, err = rolesClient.AddGrants(tc.Context(), role.Item.Id, 0, []string{"type=auth-method;actions=authenticate"}, roles.WithAutomaticVersioning(true))
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(role)

	acctClient := accounts.NewClient(client)
	acct, apiErr, err := acctClient.Create(tc.Context(), amId, accounts.WithPasswordAccountLoginName("user"), accounts.WithPasswordAccountPassword("passpass"))
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(acct)

	tokens := authtokens.NewClient(client)

	atl, apiErr, err := tokens.List(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.Nil(apiErr)
	assert.Empty(atl.Items)

	var expected []*authtokens.AuthToken
	methods := authmethods.NewClient(client)

	at, apiErr, err := methods.Authenticate(tc.Context(), amId, map[string]interface{}{"login_name": "user", "password": "passpass"})
	require.NoError(err)
	assert.Nil(apiErr)
	expected = append(expected, at.Item)

	atl, apiErr, err = tokens.List(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(atl.Items))

	for i := 1; i < 10; i++ {
		at, apiErr, err = methods.Authenticate(tc.Context(), amId, map[string]interface{}{"login_name": "user", "password": "passpass"})
		require.NoError(err)
		assert.Nil(apiErr)
		expected = append(expected, at.Item)
	}
	atl, apiErr, err = tokens.List(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(atl.Items))
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
	amId := "ampw_1234567890"
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DefaultAuthMethodId: amId,
		DefaultLoginName:    "user",
		DefaultPassword:     "passpass",
	})
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	tokens := authtokens.NewClient(client)
	methods := authmethods.NewClient(client)

	want, apiErr, err := methods.Authenticate(tc.Context(), amId, map[string]interface{}{"login_name": "user", "password": "passpass"})
	require.NoError(err)
	assert.Empty(apiErr)

	at, apiErr, err := tokens.Read(tc.Context(), want.Item.Id)
	require.NoError(err)
	assert.Nil(apiErr)
	assert.EqualValues(comparableResource(want.Item), comparableResource(at.Item))

	_, _, err = tokens.Delete(tc.Context(), at.Item.Id)
	require.NoError(err)
	assert.Nil(apiErr)
}

func TestErrors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	tokens := authtokens.NewClient(client)

	_, apiErr, err := tokens.Read(tc.Context(), authtoken.AuthTokenPrefix+"_doesntexis")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Status)

	_, apiErr, err = tokens.Read(tc.Context(), "invalid id")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Status)
}
