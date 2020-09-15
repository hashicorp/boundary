package hosts_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hosts"
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

	hc, apiErr, err := hostcatalogs.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(hc)

	hClient := hosts.NewClient(client)

	ul, apiErr, err := hClient.List(tc.Context(), hc.Item.Id)
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.Empty(ul.Items)

	var expected []*hosts.Host
	for i := 0; i < 10; i++ {
		expected = append(expected, &hosts.Host{Name: fmt.Sprint(i)})
	}

	hcr, apiErr, err := hClient.Create(tc.Context(), hc.Item.Id, hosts.WithName(expected[0].Name), hosts.WithStaticHostAddress("someaddress"))
	assert.NoError(err)
	assert.Nil(apiErr)
	expected[0] = hcr.Item

	ul, apiErr, err = hClient.List(tc.Context(), hc.Item.Id)
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableHostSlice(expected[:1]), comparableHostSlice(ul.Items))

	for i := 1; i < 10; i++ {
		hcr, apiErr, err = hClient.Create(tc.Context(), hc.Item.Id, hosts.WithName(expected[i].Name), hosts.WithStaticHostAddress("someaddress"))
		assert.NoError(err)
		assert.Nil(apiErr)
		expected[i] = hcr.Item
	}
	ul, apiErr, err = hClient.List(tc.Context(), hc.Item.Id)
	require.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableHostSlice(expected), comparableHostSlice(ul.Items))
}

func comparableHostSlice(in []*hosts.Host) []hosts.Host {
	var filtered []hosts.Host
	for _, i := range in {
		p := hosts.Host{
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

	checkHost := func(step string, h *hosts.Host, apiErr *api.Error, err error, wantedName string, wantVersion uint32) {
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

	hClient := hosts.NewClient(client)

	h, apiErr, err := hClient.Create(tc.Context(), hc.Item.Id, hosts.WithName("foo"), hosts.WithStaticHostAddress("someaddress"))
	checkHost("create", h.Item, apiErr, err, "foo", 1)

	h, apiErr, err = hClient.Read(tc.Context(), h.Item.Id)
	checkHost("read", h.Item, apiErr, err, "foo", 1)

	h, apiErr, err = hClient.Update(tc.Context(), h.Item.Id, h.Item.Version, hosts.WithName("bar"))
	checkHost("update", h.Item, apiErr, err, "bar", 2)

	h, apiErr, err = hClient.Update(tc.Context(), h.Item.Id, h.Item.Version, hosts.DefaultName())
	checkHost("update", h.Item, apiErr, err, "", 3)

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

	hClient := hosts.NewClient(client)

	h, apiErr, err := hClient.Create(tc.Context(), hc.Item.Id, hosts.WithName("foo"), hosts.WithStaticHostAddress("someaddress"))
	require.NoError(err)
	require.Nil(apiErr)
	assert.NotNil(h)

	_, apiErr, err = hClient.Create(tc.Context(), hc.Item.Id, hosts.WithName("foo"), hosts.WithStaticHostAddress("someaddress"))
	require.NoError(err)
	assert.NotNil(apiErr)

	_, apiErr, err = hClient.Read(tc.Context(), static.HostPrefix+"_doesntexis")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Status)

	_, apiErr, err = hClient.Read(tc.Context(), "invalid id")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Status)
}
