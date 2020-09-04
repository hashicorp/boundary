package hostcatalogs_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestList(t *testing.T) {
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
	_, proj := iam.TestScopes(t, tc.IamRepo())
	catalogClient := hostcatalogs.NewClient(client)

	ul, apiErr, err := catalogClient.List2(tc.Context(), proj.GetPublicId())
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.Empty(ul)

	var expected []*hostcatalogs.HostCatalog
	for i := 0; i < 10; i++ {
		expected = append(expected, &hostcatalogs.HostCatalog{Name: fmt.Sprint(i)})
	}

	expected[0], apiErr, err = catalogClient.Create2(tc.Context(), "static", proj.GetPublicId(), hostcatalogs.WithName(expected[0].Name))
	assert.NoError(err)
	assert.Nil(apiErr)

	ul, apiErr, err = catalogClient.List2(tc.Context(), proj.GetPublicId())
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableCatalogSlice(expected[:1]), comparableCatalogSlice(ul))

	for i := 1; i < 10; i++ {
		expected[i], apiErr, err = catalogClient.Create2(tc.Context(), "static", proj.GetPublicId(), hostcatalogs.WithName(expected[i].Name))
		assert.NoError(err)
		assert.Nil(apiErr)
	}
	ul, apiErr, err = catalogClient.List2(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableCatalogSlice(expected), comparableCatalogSlice(ul))
}

func comparableCatalogSlice(in []*hostcatalogs.HostCatalog) []hostcatalogs.HostCatalog {
	var filtered []hostcatalogs.HostCatalog
	for _, i := range in {
		p := hostcatalogs.HostCatalog{
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
	amId := "ampw_1234567890"
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultAuthMethodId:          amId,
		DefaultLoginName:             "user",
		DefaultPassword:              "passpass",
	})
	defer tc.Shutdown()

	client := tc.Client()
	_, proj := iam.TestScopes(t, tc.IamRepo())

	checkCatalog := func(step string, hc *hostcatalogs.HostCatalog, apiErr *api.Error, err error, wantedName string, wantVersion uint32) {
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

	hcClient := hostcatalogs.NewClient(client)

	hc, apiErr, err := hcClient.Create2(tc.Context(), "static", proj.GetPublicId(), hostcatalogs.WithName("foo"))
	checkCatalog("create", hc, apiErr, err, "foo", 1)

	hc, apiErr, err = hcClient.Read2(tc.Context(), hc.Id)
	checkCatalog("read", hc, apiErr, err, "foo", 1)

	hc, apiErr, err = hcClient.Update2(tc.Context(), hc.Id, hc.Version, hostcatalogs.WithName("bar"))
	checkCatalog("update", hc, apiErr, err, "bar", 2)

	hc, apiErr, err = hcClient.Update2(tc.Context(), hc.Id, hc.Version, hostcatalogs.DefaultName())
	checkCatalog("update", hc, apiErr, err, "", 3)

	existed, apiErr, err := hcClient.Delete2(tc.Context(), hc.Id)
	assert.NoError(err)
	assert.True(existed, "Expected existing catalog when deleted, but it wasn't.")

	existed, apiErr, err = hcClient.Delete2(tc.Context(), hc.Id)
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusForbidden, apiErr.Status)
}

// TODO: Get better coverage for expected errors and error formats.
func TestErrors(t *testing.T) {
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
	_, proj := iam.TestScopes(t, tc.IamRepo())
	pc := hostcatalogs.NewClient(client)

	hc, apiErr, err := pc.Create2(tc.Context(), "static", proj.GetPublicId(), hostcatalogs.WithName("foo"))
	require.NoError(err)
	assert.Nil(apiErr)
	assert.NotNil(hc)

	_, apiErr, err = pc.Create2(tc.Context(), "static", proj.GetPublicId(), hostcatalogs.WithName("foo"))
	require.NoError(err)
	assert.NotNil(apiErr)

	_, apiErr, err = pc.Read2(tc.Context(), static.HostCatalogPrefix+"_doesntexis")
	require.NoError(err)
	// TODO: Should this be nil instead of just a catalog that has no values set
	assert.NotNil(apiErr)
	assert.EqualValues(apiErr.Status, http.StatusForbidden)

	_, apiErr, err = pc.Read2(tc.Context(), "invalid id")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Status)
}
