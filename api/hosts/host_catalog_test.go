package hosts_test

import (
	"net/http"
	"testing"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/hosts"
	"github.com/hashicorp/watchtower/api/scopes"
	"github.com/hashicorp/watchtower/internal/host/static"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCatalogs_Crud(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	orgId := "o_1234567890"
	amId := "paum_1234567890"
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultOrgId:                 orgId,
		DefaultAuthMethodId:          amId,
		DefaultUsername:              "user",
		DefaultPassword:              "passpass",
	})
	defer tc.Shutdown()

	client := tc.Client()

	proj, apiErr, err := scopes.NewScopesClient(client).Create(tc.Context(), orgId)
	require.NoError(err)
	require.Nil(apiErr)

	projClient := client.Clone()
	projClient.SetScopeId(proj.Id)

	checkCatalog := func(step string, hc *hosts.HostCatalog, apiErr *api.Error, err error, wantedName string, wantVersion uint32) {
		require.NoError(err, step)
		if !assert.Nil(apiErr, step) && apiErr.Message != "" {
			t.Errorf("ApiError message: %q", apiErr.Message)
		}
		assert.NotNil(hc, "returned no resource", step)
		gotName := ""
		if hc.Name != "" {
			gotName = hc.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.Equal(wantVersion, hc.Version)
	}

	hcClient := hosts.NewHostCatalogsClient(projClient)

	hc, apiErr, err := hcClient.Create(tc.Context(), hosts.WithName("foo"), hosts.WithType("static"))
	checkCatalog("create", hc, apiErr, err, "foo", 1)

	hc, apiErr, err = hcClient.Read(tc.Context(), hc.Id)
	checkCatalog("read", hc, apiErr, err, "foo", 1)

	hc, apiErr, err = hcClient.Update(tc.Context(), hc.Id, hc.Version, hosts.WithName("bar"))
	checkCatalog("update", hc, apiErr, err, "bar", 2)

	hc, apiErr, err = hcClient.Update(tc.Context(), hc.Id, hc.Version, hosts.DefaultName())
	checkCatalog("update", hc, apiErr, err, "", 3)

	existed, apiErr, err := hcClient.Delete(tc.Context(), hc.Id)
	assert.NoError(err)
	assert.True(existed, "Expected existing catalog when deleted, but it wasn't.")

	existed, apiErr, err = hcClient.Delete(tc.Context(), hc.Id)
	assert.NoError(err)
	assert.False(existed, "Expected catalog to not exist when deleted, but it did.")
}

// TODO: Get better coverage for expected errors and error formats.
func TestCatalogs_Errors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	orgId := "o_1234567890"
	amId := "paum_1234567890"
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultOrgId:                 orgId,
		DefaultAuthMethodId:          amId,
		DefaultUsername:              "user",
		DefaultPassword:              "passpass",
	})
	defer tc.Shutdown()

	client := tc.Client()

	proj, apiErr, err := scopes.NewScopesClient(client).Create(tc.Context(), orgId)
	require.NoError(err)
	require.Nil(apiErr)

	client.SetScopeId(proj.Id)
	pc := hosts.NewHostCatalogsClient(client)

	hc, apiErr, err := pc.Create(tc.Context(), hosts.WithType("static"))
	require.NoError(err)
	assert.Nil(apiErr)
	assert.NotNil(hc)

	_, apiErr, err = pc.Create(tc.Context())
	require.NoError(err)
	assert.NotNil(apiErr)

	_, apiErr, err = pc.Read(tc.Context(), static.HostCatalogPrefix+"_doesntexis")
	require.NoError(err)
	// TODO: Should this be nil instead of just a catalog that has no values set
	assert.NotNil(apiErr)
	assert.EqualValues(apiErr.Status, http.StatusNotFound)

	_, apiErr, err = pc.Read(tc.Context(), "invalid id")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusForbidden, apiErr.Status)

	_, apiErr, err = pc.Update(tc.Context(), hc.Id, hc.Version, hosts.WithType("Cant Update"))
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Status)
}
