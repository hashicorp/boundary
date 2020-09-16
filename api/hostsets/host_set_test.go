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
	"github.com/kr/pretty"
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

	hc, apiErr, err := hostcatalogs.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(err)
	require.Nil(apiErr)

	hClient := hosts.NewClient(client)
	h1, apiErr, err := hClient.Create(tc.Context(), hc.Item.Id, hosts.WithStaticHostAddress("someaddress"))
	require.NoError(err)
	require.Nil(apiErr)
	h2, apiErr, err := hClient.Create(tc.Context(), hc.Item.Id, hosts.WithStaticHostAddress("someaddress"))
	require.NoError(err)
	require.Nil(apiErr)

	hSetClient := hostsets.NewClient(client)
	hSet, apiErr, err := hSetClient.Create(tc.Context(), hc.Item.Id)
	require.NoError(err)
	require.Nil(apiErr)

	hSet, apiErr, err = hSetClient.AddHosts(tc.Context(), hSet.Item.Id, hSet.Item.Version, []string{h1.Item.Id, h2.Item.Id})
	require.NoError(err)
	require.Nil(apiErr)
	assert.Contains(hSet.Item.HostIds, h1.Item.Id, h2.Item.Id)

	hSet, apiErr, err = hSetClient.SetHosts(tc.Context(), hSet.Item.Id, hSet.Item.Version, []string{h1.Item.Id})
	require.NoError(err)
	require.Nil(apiErr, pretty.Sprint(apiErr))
	assert.ElementsMatch([]string{h1.Item.Id}, hSet.Item.HostIds)

	hSet, apiErr, err = hSetClient.RemoveHosts(tc.Context(), hSet.Item.Id, hSet.Item.Version, []string{h1.Item.Id})
	require.NoError(err)
	require.Nil(apiErr)
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

	hc, apiErr, err := hostcatalogs.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(hc)

	hClient := hostsets.NewClient(client)

	ul, apiErr, err := hClient.List(tc.Context(), hc.Item.Id)
	require.NoError(err)
	require.Nil(apiErr)
	assert.Empty(ul.Items)

	var expected []*hostsets.HostSet
	for i := 0; i < 10; i++ {
		expected = append(expected, &hostsets.HostSet{Name: fmt.Sprint(i)})
	}

	hcr, apiErr, err := hClient.Create(tc.Context(), hc.Item.Id, hostsets.WithName(expected[0].Name))
	require.NoError(err)
	require.Nil(apiErr)
	expected[0] = hcr.Item

	ul, apiErr, err = hClient.List(tc.Context(), hc.Item.Id)
	require.NoError(err)
	require.Nil(apiErr)
	assert.ElementsMatch(comparableSetSlice(expected[:1]), comparableSetSlice(ul.Items))

	for i := 1; i < 10; i++ {
		hcr, apiErr, err = hClient.Create(tc.Context(), hc.Item.Id, hostsets.WithName(expected[i].Name))
		require.NoError(err)
		require.Nil(apiErr)
		expected[i] = hcr.Item
	}
	ul, apiErr, err = hClient.List(tc.Context(), hc.Item.Id)
	require.NoError(err)
	require.Nil(apiErr)
	assert.ElementsMatch(comparableSetSlice(expected), comparableSetSlice(ul.Items))
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

	hc, apiErr, err := hostcatalogs.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(hc)

	checkHost := func(t *testing.T, step string, h *hostsets.HostSet, apiErr *api.Error, err error, wantedName string, wantVersion uint32) {
		t.Helper()
		require.NoError(err, step)
		if !assert.Nil(apiErr, step) && apiErr.Message != "" {
			t.Errorf("ApiError message: %q", apiErr.Message)
		}
		assert.NotNil(h, "returned no resource", step)
		gotName := ""
		if h.Name != "" {
			gotName = h.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.Equal(wantVersion, h.Version)
	}

	hClient := hostsets.NewClient(client)

	h, apiErr, err := hClient.Create(tc.Context(), hc.Item.Id, hostsets.WithName("foo"))
	checkHost(t, "create", h.Item, apiErr, err, "foo", 1)

	h, apiErr, err = hClient.Read(tc.Context(), h.Item.Id)
	checkHost(t, "read", h.Item, apiErr, err, "foo", 1)

	h, apiErr, err = hClient.Update(tc.Context(), h.Item.Id, h.Item.Version, hostsets.WithName("bar"))
	checkHost(t, "update", h.Item, apiErr, err, "bar", 2)

	h, apiErr, err = hClient.Update(tc.Context(), h.Item.Id, h.Item.Version, hostsets.DefaultName())
	checkHost(t, "update", h.Item, apiErr, err, "", 3)

	_, apiErr, err = hClient.Delete(tc.Context(), h.Item.Id)
	assert.NoError(err)
	assert.Nil(apiErr)
	_, apiErr, err = hClient.Delete(tc.Context(), h.Item.Id)
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

	hc, apiErr, err := hostcatalogs.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(hc)

	hClient := hostsets.NewClient(client)

	h, apiErr, err := hClient.Create(tc.Context(), hc.Item.Id, hostsets.WithName("foo"))
	require.NoError(err)
	require.Nil(apiErr)
	assert.NotNil(h)

	h, apiErr, err = hClient.Create(tc.Context(), hc.Item.Id, hostsets.WithName("foo"))
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.Nil(h)

	_, apiErr, err = hClient.Read(tc.Context(), static.HostSetPrefix+"_doesntexis")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Status)

	_, apiErr, err = hClient.Read(tc.Context(), "invalid id")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Status)
}
