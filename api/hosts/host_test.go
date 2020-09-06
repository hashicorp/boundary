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

	hc, apiErr, err := hostcatalogs.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(hc)

	hClient := hosts.NewClient(client)

	ul, apiErr, err := hClient.List(tc.Context(), hc.Id)
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.Empty(ul)

	var expected []*hosts.Host
	for i := 0; i < 10; i++ {
		expected = append(expected, &hosts.Host{Name: fmt.Sprint(i)})
	}

	expected[0], apiErr, err = hClient.Create(tc.Context(), hc.Id, hosts.WithName(expected[0].Name), hosts.WithStaticHostAddress("someaddress"))
	assert.NoError(err)
	assert.Nil(apiErr)

	ul, apiErr, err = hClient.List(tc.Context(), hc.Id)
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableHostSlice(expected[:1]), comparableHostSlice(ul))

	for i := 1; i < 10; i++ {
		expected[i], apiErr, err = hClient.Create(tc.Context(), hc.Id, hosts.WithName(expected[i].Name), hosts.WithStaticHostAddress("someaddress"))
		assert.NoError(err)
		assert.Nil(apiErr)
	}
	ul, apiErr, err = hClient.List(tc.Context(), hc.Id)
	require.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableHostSlice(expected), comparableHostSlice(ul))
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

	h, apiErr, err := hClient.Create(tc.Context(), hc.Id, hosts.WithName("foo"), hosts.WithStaticHostAddress("someaddress"))
	checkHost("create", h, apiErr, err, "foo", 1)

	h, apiErr, err = hClient.Read(tc.Context(), h.Id)
	checkHost("read", h, apiErr, err, "foo", 1)

	h, apiErr, err = hClient.Update(tc.Context(), h.Id, h.Version, hosts.WithName("bar"))
	checkHost("update", h, apiErr, err, "bar", 2)

	h, apiErr, err = hClient.Update(tc.Context(), h.Id, h.Version, hosts.DefaultName())
	checkHost("update", h, apiErr, err, "", 3)

	existed, apiErr, err := hClient.Delete(tc.Context(), h.Id)
	assert.NoError(err)
	assert.True(existed, "Expected existing catalog when deleted, but it wasn't.")

	existed, apiErr, err = hClient.Delete(tc.Context(), h.Id)
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
	client.SetScopeId(proj.GetPublicId())

	hc, apiErr, err := hostcatalogs.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(hc)

	hClient := hosts.NewClient(client)

	h, apiErr, err := hClient.Create(tc.Context(), hc.Id, hosts.WithName("foo"), hosts.WithStaticHostAddress("someaddress"))
	require.NoError(err)
	require.Nil(apiErr)
	assert.NotNil(h)

	_, apiErr, err = hClient.Create(tc.Context(), hc.Id, hosts.WithName("foo"), hosts.WithStaticHostAddress("someaddress"))
	require.NoError(err)
	assert.NotNil(apiErr)

	_, apiErr, err = hClient.Read(tc.Context(), static.HostPrefix+"_doesntexis")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(apiErr.Status, http.StatusForbidden)

	_, apiErr, err = hClient.Read(tc.Context(), "invalid id")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Status)
}
