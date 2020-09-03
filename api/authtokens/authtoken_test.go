package authtokens_test

import (
	"net/http"
	"sort"
	"testing"

	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthTokens_List(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
	})
	defer tc.Shutdown()
	client := tc.Client()
	org := iam.TestOrg(t, tc.IamRepo())
	client.SetScopeId(org.GetPublicId())
	amClient := authmethods.NewClient(client)
	am, apiErr, err := amClient.Create(tc.Context(), "password")
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(am)
	amId := am.Id

	acctClient := accounts.NewClient(client)
	acct, apiErr, err := acctClient.Create(tc.Context(), amId, accounts.WithPasswordAccountLoginName("user"), accounts.WithPasswordAccountPassword("passpass"))
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(acct)

	tokens := authtokens.NewClient(client)
	methods := authmethods.NewClient(client)

	atl, apiErr, err := tokens.List(tc.Context())
	require.NoError(err)
	assert.Nil(apiErr)
	assert.Empty(atl)

	var expected []*authtokens.AuthToken

	at, apiErr, err := methods.Authenticate(tc.Context(), amId, "user", "passpass")
	require.NoError(err)
	assert.Nil(apiErr)
	expected = append(expected, at)

	atl, apiErr, err = tokens.List(tc.Context())
	require.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(atl))

	for i := 1; i < 10; i++ {
		at, apiErr, err = methods.Authenticate(tc.Context(), amId, "user", "passpass")
		require.NoError(err)
		assert.Nil(apiErr)
		expected = append(expected, at)
	}
	atl, apiErr, err = tokens.List(tc.Context())
	require.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(atl))
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

func TestAuthToken_Crud(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	amId := "ampw_1234567890"
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultAuthMethodId:          amId,
		DefaultLoginName:             "user",
		DefaultPassword:              "passpass",
	})
	defer tc.Shutdown()

	client := tc.Client()
	tokens := authtokens.NewClient(client)
	methods := authmethods.NewClient(client)

	want, apiErr, err := methods.Authenticate(tc.Context(), amId, "user", "passpass")
	require.NoError(err)
	assert.Empty(apiErr)

	at, apiErr, err := tokens.Read(tc.Context(), want.Id)
	require.NoError(err)
	assert.Nil(apiErr)
	assert.EqualValues(comparableResource(want), comparableResource(at))

	existed, _, err := tokens.Delete(tc.Context(), at.Id)
	require.NoError(err)
	assert.Nil(apiErr)
	assert.True(existed, "Expected existing token when deleted, but it wasn't.")
}

func TestAuthToken_Errors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	amId := "ampw_1234567890"
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultAuthMethodId:          amId,
		DefaultLoginName:             "user",
		DefaultPassword:              "passpass",
	})
	defer tc.Shutdown()

	client := tc.Client()
	tokens := authtokens.NewClient(client)

	_, apiErr, err := tokens.Read(tc.Context(), authtoken.AuthTokenPrefix+"_doesntexis")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusForbidden, apiErr.Status)

	_, apiErr, err = tokens.Read(tc.Context(), "invalid id")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Status)
}
