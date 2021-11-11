package hostsets_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustom(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	hc, err := hostcatalogs.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(err)

	hClient := hosts.NewClient(client)
	h1, err := hClient.Create(tc.Context(), hc.Item.Id, hosts.WithStaticHostAddress("someaddress"))
	require.NoError(err)
	h2, err := hClient.Create(tc.Context(), hc.Item.Id, hosts.WithStaticHostAddress("someaddress"))
	require.NoError(err)

	hSetClient := hostsets.NewClient(client)
	hSet, err := hSetClient.Create(tc.Context(), hc.Item.Id)
	require.NoError(err)

	hSet, err = hSetClient.AddHosts(tc.Context(), hSet.Item.Id, hSet.Item.Version, []string{h1.Item.Id, h2.Item.Id})
	require.NoError(err)
	assert.Contains(hSet.Item.HostIds, h1.Item.Id, h2.Item.Id)

	hSet, err = hSetClient.SetHosts(tc.Context(), hSet.Item.Id, hSet.Item.Version, []string{h1.Item.Id})
	require.NoError(err)
	assert.ElementsMatch([]string{h1.Item.Id}, hSet.Item.HostIds)

	hSet, err = hSetClient.RemoveHosts(tc.Context(), hSet.Item.Id, hSet.Item.Version, []string{h1.Item.Id})
	require.NoError(err)
	assert.Empty(hSet.Item.HostIds)
}

func TestList(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	hc, err := hostcatalogs.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(err)
	require.NotNil(hc)

	hClient := hostsets.NewClient(client)

	ul, err := hClient.List(tc.Context(), hc.Item.Id)
	require.NoError(err)
	assert.Empty(ul.Items)

	var expected []*hostsets.HostSet
	for i := 0; i < 10; i++ {
		expected = append(expected, &hostsets.HostSet{Name: fmt.Sprint(i)})
	}

	hcr, err := hClient.Create(tc.Context(), hc.Item.Id, hostsets.WithName(expected[0].Name))
	require.NoError(err)
	expected[0] = hcr.Item

	ul, err = hClient.List(tc.Context(), hc.Item.Id)
	require.NoError(err)
	assert.ElementsMatch(comparableSetSlice(expected[:1]), comparableSetSlice(ul.Items))

	for i := 1; i < 10; i++ {
		hcr, err = hClient.Create(tc.Context(), hc.Item.Id, hostsets.WithName(expected[i].Name))
		require.NoError(err)
		expected[i] = hcr.Item
	}
	ul, err = hClient.List(tc.Context(), hc.Item.Id)
	require.NoError(err)
	assert.ElementsMatch(comparableSetSlice(expected), comparableSetSlice(ul.Items))

	filterItem := ul.Items[3]
	ul, err = hClient.List(tc.Context(), hc.Item.Id,
		hostsets.WithFilter(fmt.Sprintf(`"/item/id"==%q`, filterItem.Id)))
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

	hc, err := hostcatalogs.NewClient(client).Create(tc.Context(), "plugin", proj.GetPublicId(),
		hostcatalogs.WithPluginId("pl_1234567890"))
	require.NoError(err)
	require.NotNil(hc)

	hClient := hostsets.NewClient(client)

	ul, err := hClient.List(tc.Context(), hc.Item.Id)
	require.NoError(err)
	assert.Empty(ul.Items)

	var expected []*hostsets.HostSet
	for i := 0; i < 10; i++ {
		expected = append(expected, &hostsets.HostSet{Name: fmt.Sprint(i)})
	}

	hcr, err := hClient.Create(tc.Context(), hc.Item.Id, hostsets.WithName(expected[0].Name))
	require.NoError(err)
	expected[0] = hcr.Item

	ul, err = hClient.List(tc.Context(), hc.Item.Id)
	require.NoError(err)
	assert.ElementsMatch(comparableSetSlice(expected[:1]), comparableSetSlice(ul.Items))

	for i := 1; i < 10; i++ {
		hcr, err = hClient.Create(tc.Context(), hc.Item.Id, hostsets.WithName(expected[i].Name))
		require.NoError(err)
		expected[i] = hcr.Item
	}
	ul, err = hClient.List(tc.Context(), hc.Item.Id)
	require.NoError(err)
	assert.ElementsMatch(comparableSetSlice(expected), comparableSetSlice(ul.Items))

	filterItem := ul.Items[3]
	ul, err = hClient.List(tc.Context(), hc.Item.Id,
		hostsets.WithFilter(fmt.Sprintf(`"/item/id"==%q`, filterItem.Id)))
	require.NoError(err)
	assert.Len(ul.Items, 1)
	assert.Equal(filterItem.Id, ul.Items[0].Id)
}

func comparableSetSlice(in []*hostsets.HostSet) []hostsets.HostSet {
	var filtered []hostsets.HostSet
	for _, i := range in {
		p := hostsets.HostSet{
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

	hcClient := hostcatalogs.NewClient(client)
	hc, err := hcClient.Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(err)
	require.NotNil(hc)

	checkHost := func(t *testing.T, step string, h *hostsets.HostSet, err error, wantedName string, wantVersion uint32) {
		t.Helper()
		require.NoError(err, step)
		assert.NotNil(h, "returned no resource", step)
		gotName := ""
		if h.Name != "" {
			gotName = h.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.Equal(wantVersion, h.Version)
	}

	hClient := hostsets.NewClient(client)

	h, err := hClient.Create(tc.Context(), hc.Item.Id, hostsets.WithName("foo"))
	checkHost(t, "create", h.Item, err, "foo", 1)

	h, err = hClient.Read(tc.Context(), h.Item.Id)
	checkHost(t, "read", h.Item, err, "foo", 1)

	h, err = hClient.Update(tc.Context(), h.Item.Id, h.Item.Version, hostsets.WithName("bar"))
	checkHost(t, "update", h.Item, err, "bar", 2)

	h, err = hClient.Update(tc.Context(), h.Item.Id, h.Item.Version, hostsets.DefaultName())
	checkHost(t, "update", h.Item, err, "", 3)

	_, err = hClient.Delete(tc.Context(), h.Item.Id)
	assert.NoError(err)
	_, err = hClient.Delete(tc.Context(), h.Item.Id)
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	// Plugin Sets
	c, err := hcClient.Create(tc.Context(), "plugin", proj.GetPublicId(), hostcatalogs.WithName("pluginfoo"), hostcatalogs.WithPluginId("pl_1234567890"),
		hostcatalogs.WithAttributes(map[string]interface{}{"foo": "bar"}))
	require.NoError(err)

	h, err = hClient.Create(tc.Context(), c.Item.Id, hostsets.WithName("foo"),
		hostsets.WithAttributes(map[string]interface{}{"foo": "bar"}), hostsets.WithPreferredEndpoints([]string{"dns:test"}))
	checkHost(t, "create", h.Item, err, "foo", 1)

	h, err = hClient.Read(tc.Context(), h.Item.Id)
	checkHost(t, "read", h.Item, err, "foo", 1)

	h, err = hClient.Update(tc.Context(), h.Item.Id, h.Item.Version, hostsets.WithName("bar"),
		hostsets.WithAttributes(map[string]interface{}{"foo": nil, "key": "val"}),
		hostsets.WithPreferredEndpoints([]string{"dns:update"}))
	checkHost(t, "update", h.Item, err, "bar", 2)

	assert.Equal(h.Item.Attributes, map[string]interface{}{"key": "val"})
	assert.Equal(h.Item.PreferredEndpoints, []string{"dns:update"})

	_, err = hClient.Delete(tc.Context(), h.Item.Id)
	assert.NoError(err)
	_, err = hClient.Delete(tc.Context(), h.Item.Id)
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())
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

	hc, err := hostcatalogs.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(err)
	require.NotNil(hc)

	hClient := hostsets.NewClient(client)

	h, err := hClient.Create(tc.Context(), hc.Item.Id, hostsets.WithName("foo"))
	require.NoError(err)
	assert.NotNil(h)

	// Updating the wrong version should fail.
	_, err = hClient.Update(tc.Context(), h.Item.Id, 73, hostsets.WithName("anything"))
	require.Error(err)
	apiErr := api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	h, err = hClient.Create(tc.Context(), hc.Item.Id, hostsets.WithName("foo"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.Nil(h)

	_, err = hClient.Read(tc.Context(), static.HostSetPrefix+"_doesntexis")
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = hClient.Read(tc.Context(), "invalid id")
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
}
