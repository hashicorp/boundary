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
	tc := controller.NewTestController(t, &controller.TestControllerOpts{DisableAuthorizationFailures: true})
	defer tc.Shutdown()

	client := tc.Client()
	org := &scopes.Org{
		Client: client,
	}
	p, apiErr, err := org.CreateProject(tc.Context(), &scopes.Project{})
	require.NoError(t, err)
	require.Nil(t, apiErr)
	require.NotNil(t, p)

	checkCatalog := func(step string, hc *hosts.HostCatalog, apiErr *api.Error, err error, wantedName string) {
		assert := assert.New(t)
		assert.NoError(err, step)
		if !assert.Nil(apiErr, step) && apiErr.Message != "" {
			t.Errorf("ApiError message: %q", apiErr.Message)
		}
		assert.NotNil(hc, "returned no resource", step)
		gotName := ""
		if hc.Name != nil {
			gotName = *hc.Name
		}
		assert.Equal(wantedName, gotName, step)
	}

	hc, apiErr, err := p.CreateHostCatalog(tc.Context(), &hosts.HostCatalog{Name: api.String("foo"), Type: api.String("Static")})
	checkCatalog("create", hc, apiErr, err, "foo")

	hc, apiErr, err = p.ReadHostCatalog(tc.Context(), &hosts.HostCatalog{Id: hc.Id})
	checkCatalog("read", hc, apiErr, err, "foo")

	hc = &hosts.HostCatalog{Id: hc.Id}
	hc.Name = api.String("bar")
	hc, apiErr, err = p.UpdateHostCatalog(tc.Context(), hc)
	checkCatalog("update", hc, apiErr, err, "bar")

	hc = &hosts.HostCatalog{Id: hc.Id}
	hc.SetDefault("name")
	hc, apiErr, err = p.UpdateHostCatalog(tc.Context(), hc)
	checkCatalog("update", hc, apiErr, err, "")

	existed, apiErr, err := p.DeleteHostCatalog(tc.Context(), hc)
	assert.NoError(t, err)
	assert.True(t, existed, "Expected existing catalog when deleted, but it wasn't.")

	existed, apiErr, err = p.DeleteHostCatalog(tc.Context(), hc)
	assert.NoError(t, err)
	assert.False(t, existed, "Expected catalog to not exist when deleted, but it did.")
}

// TODO: Get better coverage for expected errors and error formats.
func TestCatalogs_Errors(t *testing.T) {
	assert := assert.New(t)
	tc := controller.NewTestController(t, &controller.TestControllerOpts{DisableAuthorizationFailures: true})
	defer tc.Shutdown()
	ctx := tc.Context()

	client := tc.Client()
	org := &scopes.Org{
		Client: client,
	}
	p, apiErr, err := org.CreateProject(ctx, &scopes.Project{})
	assert.NoError(err)
	assert.NotNil(p)
	assert.Nil(apiErr)

	hc, apiErr, err := p.CreateHostCatalog(ctx, &hosts.HostCatalog{Type: api.String("Static")})
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.NotNil(hc)

	_, apiErr, err = p.CreateHostCatalog(ctx, &hosts.HostCatalog{})
	assert.NoError(err)
	assert.NotNil(apiErr)

	_, apiErr, err = p.ReadHostCatalog(ctx, &hosts.HostCatalog{Id: static.HostCatalogPrefix + "_doesntexis"})
	assert.NoError(err)
	// TODO: Should this be nil instead of just a catalog that has no values set
	assert.NotNil(apiErr)
	assert.EqualValues(apiErr.Status, http.StatusNotFound)

	_, apiErr, err = p.ReadHostCatalog(ctx, &hosts.HostCatalog{Id: "invalid id"})
	assert.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(apiErr.Status, http.StatusBadRequest)

	_, apiErr, err = p.UpdateHostCatalog(ctx, &hosts.HostCatalog{Id: hc.Id, Type: api.String("Cant Update")})
	assert.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(apiErr.Status, http.StatusBadRequest)
}
