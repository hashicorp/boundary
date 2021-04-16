package authmethods_test

import (
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/servers/controller"
	capoidc "github.com/hashicorp/cap/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const global = "global"

func TestCrud(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	amClient := authmethods.NewClient(client)

	checkAuthMethod := func(step string, u *authmethods.AuthMethod, wantedName string, wantedVersion uint32) {
		require.NotNil(u, "returned no resource", step)
		gotName := ""
		if u.Name != "" {
			gotName = u.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.EqualValues(wantedVersion, u.Version)
	}

	u, err := amClient.Create(tc.Context(), "password", global,
		authmethods.WithName("bar"))
	require.NoError(err)
	checkAuthMethod("create", u.Item, "bar", 1)

	u, err = amClient.Read(tc.Context(), u.Item.Id)
	require.NoError(err)
	checkAuthMethod("read", u.Item, "bar", 1)

	u, err = amClient.Update(tc.Context(), u.Item.Id, u.Item.Version, authmethods.WithName("buz"))
	require.NoError(err)
	checkAuthMethod("update", u.Item, "buz", 2)

	u, err = amClient.Update(tc.Context(), u.Item.Id, u.Item.Version, authmethods.DefaultName())
	require.NoError(err)
	checkAuthMethod("update", u.Item, "", 3)

	_, err = amClient.Delete(tc.Context(), u.Item.Id)
	require.NoError(err)

	// OIDC auth methods
	u, err = amClient.Create(tc.Context(), "oidc", global,
		authmethods.WithName("foo"),
		authmethods.WithOidcAuthMethodApiUrlPrefix("https://api.com"),
		authmethods.WithOidcAuthMethodIssuer("https://example.com"),
		authmethods.WithOidcAuthMethodClientSecret("secret"),
		authmethods.WithOidcAuthMethodClientId("client-id"))
	require.NoError(err)
	checkAuthMethod("create", u.Item, "foo", 1)

	u, err = amClient.Read(tc.Context(), u.Item.Id)
	require.NoError(err)
	checkAuthMethod("read", u.Item, "foo", 1)

	u, err = amClient.Update(tc.Context(), u.Item.Id, u.Item.Version, authmethods.WithName("bar"))
	require.NoError(err)
	checkAuthMethod("update", u.Item, "bar", 2)

	u, err = amClient.Update(tc.Context(), u.Item.Id, u.Item.Version, authmethods.DefaultName())
	require.NoError(err)
	checkAuthMethod("update", u.Item, "", 3)

	_, err = amClient.Delete(tc.Context(), u.Item.Id)
	require.NoError(err)
}

func TestCustomMethods(t *testing.T) {
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)

	amClient := authmethods.NewClient(client)

	tp := capoidc.StartTestProvider(t)
	tpClientId := "alice-rp"
	tpClientSecret := "her-dog's-name"
	tp.SetClientCreds(tpClientId, tpClientSecret)

	u, err := amClient.Create(tc.Context(), "oidc", global,
		authmethods.WithName("foo"),
		authmethods.WithOidcAuthMethodIssuer(tp.Addr()),
		authmethods.WithOidcAuthMethodApiUrlPrefix("https://example.com"),
		authmethods.WithOidcAuthMethodClientSecret("secret"),
		authmethods.WithOidcAuthMethodClientId("client-id"),
		authmethods.WithOidcAuthMethodSigningAlgorithms([]string{string("EdDSA")}),
		authmethods.WithOidcAuthMethodIdpCaCerts([]string{tp.CACert()}))
	require.NoError(t, err)

	const newState = "active-private"
	nilU, err := amClient.ChangeState(tc.Context(), u.Item.Id, u.Item.Version, newState)
	require.Error(t, err)
	assert.Nil(t, nilU)

	u, err = amClient.ChangeState(tc.Context(), u.Item.Id, u.Item.Version, newState, authmethods.WithOidcAuthMethodDisableDiscoveredConfigValidation(true))
	require.NoError(t, err)
	assert.NotNil(t, u)
	assert.Equal(t, newState, u.Item.Attributes["state"])

	_, err = amClient.ChangeState(tc.Context(), u.Item.Id, u.Item.Version, "", authmethods.WithOidcAuthMethodDisableDiscoveredConfigValidation(true))
	assert.Error(t, err)
}

func TestErrors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	amClient := authmethods.NewClient(client)

	u, err := amClient.Create(tc.Context(), "password", global,
		authmethods.WithName("foo"))
	require.NoError(err)
	assert.NotNil(u)

	// Updating the wrong version should fail.
	_, err = amClient.Update(tc.Context(), u.Item.Id, 73, authmethods.WithName("anything"))
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	// Create another resource with the same name.
	_, err = amClient.Create(tc.Context(), "password", global,
		authmethods.WithName("foo"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)

	// TODO: Confirm that we can't create an oidc auth method with the same name.

	_, err = amClient.Read(tc.Context(), password.AuthMethodPrefix+"_doesntexis")
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = amClient.Read(tc.Context(), "invalid id")
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())

	_, err = amClient.Update(tc.Context(), u.Item.Id, u.Item.Version)
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
}
