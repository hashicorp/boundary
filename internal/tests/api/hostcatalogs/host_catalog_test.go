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

	ul, err := catalogClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	assert.Empty(ul.Items)

	var expected []*hostcatalogs.HostCatalog
	for i := 0; i < 10; i++ {
		expected = append(expected, &hostcatalogs.HostCatalog{Name: fmt.Sprint(i)})
	}

	cr, err := catalogClient.Create(tc.Context(), "static", proj.GetPublicId(), hostcatalogs.WithName(expected[0].Name))
	require.NoError(err)
	expected[0] = cr.Item

	ul, err = catalogClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	assert.ElementsMatch(comparableCatalogSlice(expected[:1]), comparableCatalogSlice(ul.Items))

	for i := 1; i < 10; i++ {
		cr, err = catalogClient.Create(tc.Context(), "static", proj.GetPublicId(), hostcatalogs.WithName(expected[i].Name))
		require.NoError(err)
		expected[i] = cr.Item
	}
	ul, err = catalogClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	assert.ElementsMatch(comparableCatalogSlice(expected), comparableCatalogSlice(ul.Items))

	filterItem := ul.Items[3]
	ul, err = catalogClient.List(tc.Context(), proj.GetPublicId(),
		hostcatalogs.WithFilter(fmt.Sprintf(`"/item/id"==%q`, filterItem.Id)))
	require.NoError(err)
	assert.Len(ul.Items, 1)
	assert.Equal(filterItem.Id, ul.Items[0].Id)
}

func TestList_Plugin(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	catalogClient := hostcatalogs.NewClient(client)

	ul, err := catalogClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	assert.Empty(ul.Items)

	var expected []*hostcatalogs.HostCatalog
	for i := 0; i < 10; i++ {
		expected = append(expected, &hostcatalogs.HostCatalog{Name: fmt.Sprint(i)})
	}

	cr, err := catalogClient.Create(tc.Context(), "plugin", proj.GetPublicId(),
		hostcatalogs.WithName(expected[0].Name), hostcatalogs.WithPluginId("pl_1234567890"))
	require.NoError(err)
	expected[0] = cr.Item

	ul, err = catalogClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	assert.ElementsMatch(comparableCatalogSlice(expected[:1]), comparableCatalogSlice(ul.Items))

	for i := 1; i < 10; i++ {
		cr, err = catalogClient.Create(tc.Context(), "static", proj.GetPublicId(), hostcatalogs.WithName(expected[i].Name))
		require.NoError(err)
		expected[i] = cr.Item
	}
	ul, err = catalogClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	assert.ElementsMatch(comparableCatalogSlice(expected), comparableCatalogSlice(ul.Items))

	filterItem := ul.Items[3]
	ul, err = catalogClient.List(tc.Context(), proj.GetPublicId(),
		hostcatalogs.WithFilter(fmt.Sprintf(`"/item/id"==%q`, filterItem.Id)))
	require.NoError(err)
	assert.Len(ul.Items, 1)
	assert.Equal(filterItem.Id, ul.Items[0].Id)
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

	checkCatalog := func(step string, hc *hostcatalogs.HostCatalog, err error, wantedName string, wantVersion uint32) {
		require.NoError(err, step)
		assert.NotNil(hc, "returned no resource", step)
		gotName := ""
		if hc.Name != "" {
			gotName = hc.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.Equal(wantVersion, hc.Version)
	}

	hcClient := hostcatalogs.NewClient(client)

	hc, err := hcClient.Create(tc.Context(), "static", proj.GetPublicId(), hostcatalogs.WithName("foo"))
	checkCatalog("create", hc.Item, err, "foo", 1)

	hc, err = hcClient.Read(tc.Context(), hc.Item.Id)
	checkCatalog("read", hc.Item, err, "foo", 1)

	hc, err = hcClient.Update(tc.Context(), hc.Item.Id, hc.Item.Version, hostcatalogs.WithName("bar"))
	checkCatalog("update", hc.Item, err, "bar", 2)

	hc, err = hcClient.Update(tc.Context(), hc.Item.Id, hc.Item.Version, hostcatalogs.DefaultName())
	checkCatalog("update", hc.Item, err, "", 3)

	_, err = hcClient.Delete(tc.Context(), hc.Item.Id)
	assert.NoError(err)

	_, err = hcClient.Delete(tc.Context(), hc.Item.Id)
	require.Error(err)
	apiErr := api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	// Plugin catalogs
	c, err := hcClient.Create(tc.Context(), "plugin", proj.GetPublicId(), hostcatalogs.WithName("pluginfoo"), hostcatalogs.WithPluginId("pl_1234567890"),
		hostcatalogs.WithAttributes(map[string]interface{}{"foo": "bar"}))
	require.NoError(err)

	c, err = hcClient.Update(tc.Context(), c.Item.Id, c.Item.Version, hostcatalogs.WithName("bar"),
		hostcatalogs.WithAttributes(map[string]interface{}{"key": "val", "foo": nil}),
		hostcatalogs.WithSecrets(map[string]interface{}{"secretkey": "secretval"}))
	checkCatalog("update", c.Item, err, "bar", 2)
	assert.Contains(c.Item.Attributes, "key")
	assert.NotContains(c.Item.Attributes, "foo")
	assert.Empty(c.Item.Secrets)

	c, err = hcClient.Update(tc.Context(), c.Item.Id, c.Item.Version, hostcatalogs.DefaultName())
	checkCatalog("update", c.Item, err, "", 3)

	c, err = hcClient.Read(tc.Context(), c.Item.Id)
	assert.NoError(err)

	_, err = hcClient.Delete(tc.Context(), c.Item.Id)
	assert.NoError(err)

	_, err = hcClient.Delete(tc.Context(), c.Item.Id)
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())
}

func TestErrors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	pc := hostcatalogs.NewClient(client)

	hc, err := pc.Create(tc.Context(), "static", proj.GetPublicId(), hostcatalogs.WithName("foo"))
	require.NoError(err)
	apiErr := api.AsServerError(err)
	assert.Nil(apiErr)
	assert.NotNil(hc)

	// Updating the wrong version should fail.
	_, err = pc.Update(tc.Context(), hc.Item.Id, 73, hostcatalogs.WithName("anything"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = pc.Create(tc.Context(), "static", proj.GetPublicId(), hostcatalogs.WithName("foo"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)

	_, err = pc.Read(tc.Context(), static.HostCatalogPrefix+"_doesntexis")
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = pc.Read(tc.Context(), "invalid id")
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
}
