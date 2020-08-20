package hosts_test

import (
	"errors"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHost_Crud(t *testing.T) {
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

	checkHost := func(step string, h *hosts.Host, apiErr error, err error, wantedName string, wantVersion uint32) {
		require.NoError(err, step)
		assert.NoError(apiErr, step)
		assert.NotNil(h, "returned no resource", step)
		gotName := ""
		if h.Name != "" {
			gotName = h.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.Equal(wantVersion, h.Version)
	}

	hClient := hosts.NewHostsClient(projClient)

	h, apiErr, err := hClient.Create(tc.Context(), hc.Id, hosts.WithName("foo"), hosts.WithStaticHostAddress("someaddress"))
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
func TestHost_Errors(t *testing.T) {
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

	hClient := hosts.NewHostsClient(client)

	h, apiErr, err := hClient.Create(tc.Context(), hc.Id, hosts.WithName("foo"), hosts.WithStaticHostAddress("someaddress"))
	require.NoError(err)
	require.NoError(apiErr)
	assert.NotNil(h)

	_, apiErr, err = hClient.Create(tc.Context(), hc.Id, hosts.WithName("foo"), hosts.WithStaticHostAddress("someaddress"))
	require.NoError(err)
	assert.Error(apiErr)

	_, apiErr, err = hClient.Read(tc.Context(), hc.Id, static.HostPrefix+"_doesntexis")
	require.NoError(err)
	assert.Error(apiErr)
	assert.True(errors.Is(apiErr, api.ErrNotFound))

	_, apiErr, err = hClient.Read(tc.Context(), hc.Id, "invalid id")
	require.NoError(err)
	assert.Error(apiErr)
	assert.True(errors.Is(apiErr, api.ErrForbidden))
}
