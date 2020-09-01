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
	for _, newStyle := range []bool{false} {
		assert, require := assert.New(t), require.New(t)
		tc := controller.NewTestController(t, nil)
		defer tc.Shutdown()

		token := tc.Token()
		_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))
		client := tc.Client().Clone()
		client.SetScopeId(proj.GetPublicId())

		hc, apiErr, err := hostcatalogs.NewClient(client).Create(tc.Context(), "static")
		require.NoError(err)
		require.Nil(apiErr)

		hClient := hosts.NewClient(client)
		h1, apiErr, err := hClient.Create(tc.Context(), hc.Id, hosts.WithStaticHostAddress("someaddress"))
		require.NoError(err)
		require.Nil(apiErr)
		h2, apiErr, err := hClient.Create(tc.Context(), hc.Id, hosts.WithStaticHostAddress("someaddress"))
		require.NoError(err)
		require.Nil(apiErr)

		hSetClient := hostsets.NewClient(client)
		var hSet *hostsets.HostSet
		if newStyle {
			hSet, apiErr, err = hSetClient.Create2(tc.Context(), hc.Id)
		} else {
			hSet, apiErr, err = hSetClient.Create(tc.Context(), hc.Id)
		}
		require.NoError(err)
		require.Nil(apiErr)

		if newStyle {
			hSet, apiErr, err = hSetClient.AddHosts(tc.Context(), hc.Id, hSet.Id, hSet.Version, []string{h1.Id, h2.Id})
		} else {
			hSet, apiErr, err = hSetClient.AddHosts2(tc.Context(), hSet.Id, hSet.Version, []string{h1.Id, h2.Id})
		}
		require.NoError(err)
		require.Nil(apiErr)
		assert.Contains(hSet.HostIds, h1.Id, h2.Id)

		if newStyle {
			hSet, apiErr, err = hSetClient.SetHosts(tc.Context(), hc.Id, hSet.Id, hSet.Version, []string{h1.Id})
		} else {
			hSet, apiErr, err = hSetClient.SetHosts2(tc.Context(), hc.Id, hSet.Version, []string{h1.Id})
		}
		require.NoError(err)
		require.Nil(apiErr)
		assert.ElementsMatch([]string{h1.Id}, hSet.HostIds)

		if newStyle {
			hSet, apiErr, err = hSetClient.RemoveHosts(tc.Context(), hc.Id, hSet.Id, hSet.Version, []string{h1.Id})
		} else {
			hSet, apiErr, err = hSetClient.RemoveHosts2(tc.Context(), hc.Id, hSet.Version, []string{h1.Id})
		}
		require.NoError(err)
		require.Nil(apiErr)
		assert.Empty(hSet.HostIds)
	}
}

func TestSet_List(t *testing.T) {
	for _, newStyle := range []bool{false, true} {
		assert, require := assert.New(t), require.New(t)
		tc := controller.NewTestController(t, nil)
		defer tc.Shutdown()

		client := tc.Client()
		token := tc.Token()
		_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))
		client.SetScopeId(proj.GetPublicId())

		hc, apiErr, err := hostcatalogs.NewClient(client).Create(tc.Context(), "static")
		require.NoError(err)
		require.Nil(apiErr)
		require.NotNil(hc)

		hClient := hostsets.NewClient(client)
		var ul []*hostsets.HostSet

		if newStyle {
			ul, apiErr, err = hClient.List2(tc.Context(), hc.Id)
		} else {
			ul, apiErr, err = hClient.List(tc.Context(), hc.Id)
		}
		require.NoError(err)
		require.Nil(apiErr)
		assert.Empty(ul)

		var expected []*hostsets.HostSet
		for i := 0; i < 10; i++ {
			expected = append(expected, &hostsets.HostSet{Name: fmt.Sprint(i)})
		}

		expected[0], apiErr, err = hClient.Create(tc.Context(), hc.Id, hostsets.WithName(expected[0].Name))
		require.NoError(err)
		require.Nil(apiErr)

		if newStyle {
			ul, apiErr, err = hClient.List2(tc.Context(), hc.Id)
		} else {
			ul, apiErr, err = hClient.List(tc.Context(), hc.Id)
		}
		require.NoError(err)
		require.Nil(apiErr)
		assert.ElementsMatch(comparableSetSlice(expected[:1]), comparableSetSlice(ul))

		for i := 1; i < 10; i++ {
			expected[i], apiErr, err = hClient.Create(tc.Context(), hc.Id, hostsets.WithName(expected[i].Name))
			require.NoError(err)
			require.Nil(apiErr)
		}
		if newStyle {
			ul, apiErr, err = hClient.List2(tc.Context(), hc.Id)
		} else {
			ul, apiErr, err = hClient.List(tc.Context(), hc.Id)
		}
		require.NoError(err)
		require.Nil(apiErr)
		assert.ElementsMatch(comparableSetSlice(expected), comparableSetSlice(ul))
	}
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

func TestSet_Crud(t *testing.T) {
	for _, newStyle := range []bool{true} {
		assert, require := assert.New(t), require.New(t)
		tc := controller.NewTestController(t, nil)
		defer tc.Shutdown()

		client := tc.Client()
		token := tc.Token()
		org, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))
		client.SetScopeId(org.GetPublicId())
		projClient := client.Clone()
		projClient.SetScopeId(proj.GetPublicId())

		hc, apiErr, err := hostcatalogs.NewClient(projClient).Create(tc.Context(), "static")
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

		hClient := hostsets.NewClient(projClient)

		var h *hostsets.HostSet
		if newStyle {
			h, apiErr, err = hClient.Create2(tc.Context(), hc.Id, hostsets.WithName("foo"))
		} else {
			h, apiErr, err = hClient.Create(tc.Context(), hc.Id, hostsets.WithName("foo"))
		}
		checkHost(t, "create", h, apiErr, err, "foo", 1)

		if newStyle {
			h, apiErr, err = hClient.Read2(tc.Context(), h.Id)
		} else {
			h, apiErr, err = hClient.Read(tc.Context(), hc.Id, h.Id)
		}
		checkHost(t, "read", h, apiErr, err, "foo", 1)

		if newStyle {
			h, apiErr, err = hClient.Update2(tc.Context(), h.Id, h.Version, hostsets.WithName("bar"))
		} else {
			h, apiErr, err = hClient.Update(tc.Context(), hc.Id, h.Id, h.Version, hostsets.WithName("bar"))
		}
		checkHost(t, "update", h, apiErr, err, "bar", 2)

		if newStyle {
			h, apiErr, err = hClient.Update2(tc.Context(), h.Id, h.Version, hostsets.DefaultName())
		} else {
			h, apiErr, err = hClient.Update(tc.Context(), hc.Id, h.Id, h.Version, hostsets.DefaultName())
		}
		checkHost(t, "update", h, apiErr, err, "", 3)

		var existed bool
		if newStyle {
			existed, apiErr, err = hClient.Delete2(tc.Context(), h.Id)
		} else {
			existed, apiErr, err = hClient.Delete(tc.Context(), hc.Id, h.Id)
		}
		assert.NoError(err)
		assert.True(existed, "Expected existing catalog when deleted, but it wasn't.")

		if newStyle {
			existed, apiErr, err = hClient.Delete2(tc.Context(), h.Id)
		} else {
			existed, apiErr, err = hClient.Delete(tc.Context(), hc.Id, h.Id)
		}
		assert.NoError(err)
		assert.False(existed, "Expected catalog to not exist when deleted, but it did.")
	}
}

// TODO: Get better coverage for expected errors and error formats.
func TestSet_Errors(t *testing.T) {
	for _, newStyle := range []bool{false, true} {
		assert, require := assert.New(t), require.New(t)
		tc := controller.NewTestController(t, nil)
		defer tc.Shutdown()

		client := tc.Client()
		token := tc.Token()
		_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))
		client.SetScopeId(proj.GetPublicId())

		hc, apiErr, err := hostcatalogs.NewClient(client).Create(tc.Context(), "static")
		require.NoError(err)
		require.Nil(apiErr)
		require.NotNil(hc)

		hClient := hostsets.NewClient(client)

		var h *hostsets.HostSet
		if newStyle {
			h, apiErr, err = hClient.Create2(tc.Context(), hc.Id, hostsets.WithName("foo"))
		} else {
			h, apiErr, err = hClient.Create(tc.Context(), hc.Id, hostsets.WithName("foo"))
		}
		require.NoError(err)
		require.Nil(apiErr)
		assert.NotNil(h)

		if newStyle {
			h, apiErr, err = hClient.Create2(tc.Context(), hc.Id, hostsets.WithName("foo"))
		} else {
			h, apiErr, err = hClient.Create(tc.Context(), hc.Id, hostsets.WithName("foo"))
		}
		require.NoError(err)
		assert.NotNil(apiErr)
		assert.Nil(h)

		if newStyle {
			_, apiErr, err = hClient.Read2(tc.Context(), static.HostSetPrefix+"_doesntexis")
		} else {
			_, apiErr, err = hClient.Read(tc.Context(), hc.Id, static.HostSetPrefix+"_doesntexis")
		}
		require.NoError(err)
		assert.NotNil(apiErr)
		assert.EqualValues(http.StatusForbidden, apiErr.Status)

		if newStyle {
			_, apiErr, err = hClient.Read2(tc.Context(), "invalid id")
		} else {
			_, apiErr, err = hClient.Read(tc.Context(), hc.Id, "invalid id")
		}
		require.NoError(err)
		assert.NotNil(apiErr)
		assert.EqualValues(http.StatusBadRequest, apiErr.Status)
	}
}
