package hosts_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCatalog_List(t *testing.T) {
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
	catalogClient := hosts.NewHostCatalogsClient(client)

	ul, apiErr, err := catalogClient.List(tc.Context())
	assert.NoError(err)
	assert.NoError(apiErr)
	assert.Empty(ul)

	var expected []*hosts.HostCatalog
	for i := 0; i < 10; i++ {
		expected = append(expected, &hosts.HostCatalog{Name: fmt.Sprint(i)})
	}

	expected[0], apiErr, err = catalogClient.Create(tc.Context(), "static", hosts.WithName(expected[0].Name))
	assert.NoError(err)
	assert.NoError(apiErr)

	ul, apiErr, err = catalogClient.List(tc.Context())
	assert.NoError(err)
	assert.NoError(apiErr)
	assert.ElementsMatch(comparableSlice(expected[:1]), comparableSlice(ul))

	for i := 1; i < 10; i++ {
		expected[i], apiErr, err = catalogClient.Create(tc.Context(), "static", hosts.WithName(expected[i].Name))
		assert.NoError(err)
		assert.NoError(apiErr)
	}
	ul, apiErr, err = catalogClient.List(tc.Context())
	require.NoError(err)
	assert.NoError(apiErr)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(ul))
}

func comparableSlice(in []*hosts.HostCatalog) []hosts.HostCatalog {
	var filtered []hosts.HostCatalog
	for _, i := range in {
		p := hosts.HostCatalog{
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

func TestCatalogs_Crud(t *testing.T) {
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

	checkCatalog := func(step string, hc *hosts.HostCatalog, apiErr error, err error, wantedName string, wantVersion uint32) {
		require.NoError(err, step)
		assert.NoError(apiErr, step)
		assert.NotNil(hc, "returned no resource", step)
		gotName := ""
		if hc.Name != "" {
			gotName = hc.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.Equal(wantVersion, hc.Version)
	}

	hcClient := hosts.NewHostCatalogsClient(projClient)

	hc, apiErr, err := hcClient.Create(tc.Context(), "static", hosts.WithName("foo"))
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
	pc := hosts.NewHostCatalogsClient(client)

	hc, apiErr, err := pc.Create(tc.Context(), "static", hosts.WithName("foo"))
	require.NoError(err)
	assert.NoError(apiErr)
	assert.NotNil(hc)

	_, apiErr, err = pc.Create(tc.Context(), "static", hosts.WithName("foo"))
	require.NoError(err)
	assert.Error(apiErr)

	_, apiErr, err = pc.Create(tc.Context(), "unknown", hosts.WithName("bar"))
	require.NoError(err)
	assert.Error(apiErr)

	_, apiErr, err = pc.Read(tc.Context(), static.HostCatalogPrefix+"_doesntexis")
	require.NoError(err)
	// TODO: Should this be nil instead of just a catalog that has no values set
	assert.Error(apiErr)
	assert.True(errors.Is(apiErr, api.ErrNotFound))

	_, apiErr, err = pc.Read(tc.Context(), "invalid id")
	require.NoError(err)
	assert.Error(apiErr)
	assert.True(errors.Is(apiErr, api.ErrForbidden))
}
