package hosts_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustom(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	amId := "paum_1234567890"
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultAuthMethodId:          amId,
		DefaultLoginName:             "user",
		DefaultPassword:              "passpass",
	})
	defer tc.Shutdown()

	_, proj := iam.TestScopes(t, tc.IamRepo())
	client := tc.Client().Clone()
	client.SetScopeId(proj.GetPublicId())

	hc, apiErr, err := hosts.NewHostCatalogsClient(client).Create(tc.Context(), "static")
	require.NoError(err)
	require.Nil(apiErr)

	hClient := hosts.NewHostsClient(client)
	h1, apiErr, err := hClient.Create(tc.Context(), hc.Id, hosts.WithStaticHostAddress("someaddress"))
	require.NoError(err)
	require.Nil(apiErr)
	h2, apiErr, err := hClient.Create(tc.Context(), hc.Id, hosts.WithStaticHostAddress("someaddress"))
	require.NoError(err)
	require.Nil(apiErr)

	hSetClient := hosts.NewHostSetsClient(client)
	hSet, apiErr, err := hSetClient.Create(tc.Context(), hc.Id)
	require.NoError(err)
	require.Nil(apiErr)

	hSet, apiErr, err = hSetClient.AddHosts(tc.Context(), hc.Id, hSet.Id, hSet.Version, []string{h1.Id, h2.Id})
	require.NoError(err)
	require.Nil(apiErr)
	assert.Contains(hSet.HostIds, h1.Id, h2.Id)

	hSet, apiErr, err = hSetClient.SetHosts(tc.Context(), hc.Id, hSet.Id, hSet.Version, []string{h1.Id})
	require.NoError(err)
	require.Nil(apiErr)
	assert.ElementsMatch([]string{h1.Id}, hSet.HostIds)

	hSet, apiErr, err = hSetClient.RemoveHosts(tc.Context(), hc.Id, hSet.Id, hSet.Version, []string{h1.Id})
	require.NoError(err)
	require.Nil(apiErr)
	assert.Empty(hSet.HostIds)
}

func TestSet_List(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	amId := "paum_1234567890"
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

	hc, apiErr, err := hosts.NewHostCatalogsClient(client).Create(tc.Context(), "static")
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(hc)

	hClient := hosts.NewHostSetsClient(client)

	ul, apiErr, err := hClient.List(tc.Context(), hc.Id)
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.Empty(ul)

	var expected []*hosts.HostSet
	for i := 0; i < 10; i++ {
		expected = append(expected, &hosts.HostSet{Name: fmt.Sprint(i)})
	}

	expected[0], apiErr, err = hClient.Create(tc.Context(), hc.Id, hosts.WithName(expected[0].Name))
	assert.NoError(err)
	assert.Nil(apiErr)

	ul, apiErr, err = hClient.List(tc.Context(), hc.Id)
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableSetSlice(expected[:1]), comparableSetSlice(ul))

	for i := 1; i < 10; i++ {
		expected[i], apiErr, err = hClient.Create(tc.Context(), hc.Id, hosts.WithName(expected[i].Name))
		assert.NoError(err)
		assert.Nil(apiErr)
	}
	ul, apiErr, err = hClient.List(tc.Context(), hc.Id)
	require.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableSetSlice(expected), comparableSetSlice(ul))
}

func comparableSetSlice(in []*hosts.HostSet) []hosts.HostSet {
	var filtered []hosts.HostSet
	for _, i := range in {
		p := hosts.HostSet{
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

func TestSet_Crud(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	amId := "paum_1234567890"
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultAuthMethodId:          amId,
		DefaultLoginName:             "user",
		DefaultPassword:              "passpass",
	})
	defer tc.Shutdown()

	client := tc.Client()
	org, proj := iam.TestScopes(t, tc.IamRepo())
	client.SetScopeId(org.GetPublicId())
	projClient := client.Clone()
	projClient.SetScopeId(proj.GetPublicId())

	hc, apiErr, err := hosts.NewHostCatalogsClient(projClient).Create(tc.Context(), "static")
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(hc)

	checkHost := func(step string, h *hosts.HostSet, apiErr *api.Error, err error, wantedName string, wantVersion uint32) {
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

	hClient := hosts.NewHostSetsClient(projClient)

	h, apiErr, err := hClient.Create(tc.Context(), hc.Id, hosts.WithName("foo"))
	checkHost("create", h, apiErr, err, "foo", 1)

	h, apiErr, err = hClient.Read(tc.Context(), hc.Id, h.Id)
	checkHost("read", h, apiErr, err, "foo", 1)

	h, apiErr, err = hClient.Update(tc.Context(), hc.Id, h.Id, h.Version, hosts.WithName("bar"))
	checkHost("update", h, apiErr, err, "bar", 2)

	h, apiErr, err = hClient.Update(tc.Context(), hc.Id, h.Id, h.Version, hosts.DefaultName())
	checkHost("update", h, apiErr, err, "", 3)

	existed, apiErr, err := hClient.Delete(tc.Context(), hc.Id, h.Id)
	assert.NoError(err)
	assert.True(existed, "Expected existing catalog when deleted, but it wasn't.")

	existed, apiErr, err = hClient.Delete(tc.Context(), hc.Id, h.Id)
	assert.NoError(err)
	assert.False(existed, "Expected catalog to not exist when deleted, but it did.")
}

// TODO: Get better coverage for expected errors and error formats.
func TestSet_Errors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	amId := "paum_1234567890"
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

	hc, apiErr, err := hosts.NewHostCatalogsClient(client).Create(tc.Context(), "static")
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(hc)

	hClient := hosts.NewHostSetsClient(client)

	h, apiErr, err := hClient.Create(tc.Context(), hc.Id, hosts.WithName("foo"))
	require.NoError(err)
	require.Nil(apiErr)
	assert.NotNil(h)

	_, apiErr, err = hClient.Create(tc.Context(), hc.Id, hosts.WithName("foo"))
	require.NoError(err)
	assert.NotNil(apiErr)

	_, apiErr, err = hClient.Read(tc.Context(), hc.Id, static.HostSetPrefix+"_doesntexis")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(apiErr.Status, http.StatusNotFound)

	_, apiErr, err = hClient.Read(tc.Context(), hc.Id, "invalid id")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusForbidden, apiErr.Status)
}
