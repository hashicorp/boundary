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
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	catalogClient := hostcatalogs.NewClient(client)

	ul, apiErr, err := catalogClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	require.Nil(apiErr)
	assert.Empty(ul.Items)

	var expected []*hostcatalogs.HostCatalog
	for i := 0; i < 10; i++ {
		expected = append(expected, &hostcatalogs.HostCatalog{Name: fmt.Sprint(i)})
	}

	cr, apiErr, err := catalogClient.Create(tc.Context(), "static", proj.GetPublicId(), hostcatalogs.WithName(expected[0].Name))
	require.NoError(err)
	require.Nil(apiErr)
	expected[0] = cr.Item

	ul, apiErr, err = catalogClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	require.Nil(apiErr)
	assert.ElementsMatch(comparableCatalogSlice(expected[:1]), comparableCatalogSlice(ul.Items))

	for i := 1; i < 10; i++ {
		cr, apiErr, err = catalogClient.Create(tc.Context(), "static", proj.GetPublicId(), hostcatalogs.WithName(expected[i].Name))
		require.NoError(err)
		require.Nil(apiErr)
		expected[i] = cr.Item
	}
	ul, apiErr, err = catalogClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableCatalogSlice(expected), comparableCatalogSlice(ul.Items))
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
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

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

	hc, apiErr, err := hcClient.Create(tc.Context(), "static", proj.GetPublicId(), hostcatalogs.WithName("foo"))
	checkCatalog("create", hc.Item, apiErr, err, "foo", 1)

	hc, apiErr, err = hcClient.Read(tc.Context(), hc.Item.Id)
	checkCatalog("read", hc.Item, apiErr, err, "foo", 1)

	hc, apiErr, err = hcClient.Update(tc.Context(), hc.Item.Id, hc.Item.Version, hostcatalogs.WithName("bar"))
	checkCatalog("update", hc.Item, apiErr, err, "bar", 2)

	hc, apiErr, err = hcClient.Update(tc.Context(), hc.Item.Id, hc.Item.Version, hostcatalogs.DefaultName())
	checkCatalog("update", hc.Item, apiErr, err, "", 3)

	_, apiErr, err = hcClient.Delete(tc.Context(), hc.Item.Id)
	assert.NoError(err)
	assert.Nil(apiErr)

	_, apiErr, err = hcClient.Delete(tc.Context(), hc.Item.Id)
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Status)
}

// TODO: Get better coverage for expected errors and error formats.
func TestErrors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	pc := hostcatalogs.NewClient(client)

	hc, apiErr, err := pc.Create(tc.Context(), "static", proj.GetPublicId(), hostcatalogs.WithName("foo"))
	require.NoError(err)
	assert.Nil(apiErr)
	assert.NotNil(hc)

	_, apiErr, err = pc.Create(tc.Context(), "static", proj.GetPublicId(), hostcatalogs.WithName("foo"))
	require.NoError(err)
	assert.NotNil(apiErr)

	_, apiErr, err = pc.Read(tc.Context(), static.HostCatalogPrefix+"_doesntexis")
	require.NoError(err)
	// TODO: Should this be nil instead of just a catalog that has no values set
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Status)

	_, apiErr, err = pc.Read(tc.Context(), "invalid id")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Status)
}
