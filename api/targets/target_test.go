package targets_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustom(t *testing.T) {
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
	org, proj := iam.TestScopes(t, tc.IamRepo())
	client.SetScopeId(org.GetPublicId())
	projClient := client.Clone()
	projClient.SetScopeId(proj.GetPublicId())

	tarClient := targets.NewTargetsClient(projClient)

	hasSet := func(tar *targets.Target, setId string) bool {
		var foundInHostSets bool
		var foundInHostSetIds bool
		for _, v := range tar.HostSets {
			if v.Id == setId {
				foundInHostSets = true
			}
		}
		for _, v := range tar.HostSetIds {
			if v == setId {
				foundInHostSetIds = true
			}
		}
		return foundInHostSets && foundInHostSetIds
	}

	hc, apiErr, err := hostcatalogs.NewClient(projClient).Create(tc.Context(), "static")
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(hc)

	hs1, apiErr, err := hostsets.NewClient(projClient).Create(tc.Context(), hc.Id)
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(hs1)

	hs2, apiErr, err := hostsets.NewClient(projClient).Create(tc.Context(), hc.Id)
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(hs2)

	version := 1
	tar, apiErr, err := tarClient.Create(tc.Context(), "tcp", targets.WithName("test target"))
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(tar)
	assert.EqualValues(version, tar.Version)
	version++

	tar, apiErr, err = tarClient.AddHostSets(tc.Context(), tar.Id, tar.Version, []string{hs1.Id})
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(tar)
	assert.EqualValues(version, tar.Version)
	assert.True(hasSet(tar, hs1.Id))
	version++

	tar, apiErr, err = tarClient.SetHostSets(tc.Context(), tar.Id, tar.Version, []string{hs2.Id})
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(tar)
	assert.EqualValues(version, tar.Version)
	assert.True(hasSet(tar, hs2.Id))
	version++

	tar, apiErr, err = tarClient.RemoveHostSets(tc.Context(), tar.Id, tar.Version, []string{hs2.Id})
	require.NoError(err)
	require.Nil(apiErr, "Got error ", apiErr)
	assert.EqualValues(version, tar.Version)
	assert.Empty(tar.HostSets)
}

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
	org, proj := iam.TestScopes(t, tc.IamRepo())
	client.SetScopeId(org.GetPublicId())
	projClient := client.Clone()
	projClient.SetScopeId(proj.GetPublicId())

	tarClient := targets.NewTargetsClient(projClient)
	p1, apiErr, err := tarClient.List(tc.Context())
	require.NoError(err)
	assert.Nil(apiErr)
	require.Len(p1, 0)

	var expected []*targets.Target
	for i := 0; i < 10; i++ {
		expected = append(expected, &targets.Target{Name: fmt.Sprint(i)})
	}

	expected[0], apiErr, err = tarClient.Create(tc.Context(), "tcp", targets.WithName(expected[0].Name), targets.WithDefaultPort(1))
	require.NoError(err)
	assert.Nil(apiErr)

	p2, apiErr, err := tarClient.List(tc.Context())
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableSlice(expected[:1]), comparableSlice(p2))

	for i := 1; i < 10; i++ {
		expected[i], apiErr, err = tarClient.Create(tc.Context(), "tcp", targets.WithName(expected[i].Name), targets.WithDefaultPort(uint32(i+1)))
		assert.NoError(err)
		assert.Nil(apiErr)
	}
	p3, apiErr, err := tarClient.List(tc.Context())
	require.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(p3))
}

func comparableSlice(in []*targets.Target) []targets.Target {
	var filtered []targets.Target
	for _, i := range in {
		p := targets.Target{
			Id:          i.Id,
			Name:        i.Name,
			Description: i.Description,
			CreatedTime: i.CreatedTime,
			UpdatedTime: i.UpdatedTime,
			HostSets:    i.HostSets,
			HostSetIds:  i.HostSetIds,
			DefaultPort: i.DefaultPort,
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
	org, proj := iam.TestScopes(t, tc.IamRepo())
	client.SetScopeId(org.GetPublicId())
	projClient := client.Clone()
	projClient.SetScopeId(proj.GetPublicId())

	checkTarget := func(step string, r *targets.Target, apiErr *api.Error, err error, wantedName string, wantedVersion uint32) {
		assert.NoError(err, step)
		if !assert.Nil(apiErr, step) && apiErr.Message != "" {
			t.Errorf("ApiError message: %q", apiErr.Message)
		}
		assert.NotNil(r, "returned no resource", step)
		gotName := ""
		if r.Name != "" {
			gotName = r.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.EqualValues(wantedVersion, r.Version)
	}

	tarClient := targets.NewTargetsClient(projClient)
	g, apiErr, err := tarClient.Create(tc.Context(), "tcp", targets.WithName("foo"))
	checkTarget("create", g, apiErr, err, "foo", 1)

	g, apiErr, err = tarClient.Read(tc.Context(), g.Id)
	checkTarget("read", g, apiErr, err, "foo", 1)

	g, apiErr, err = tarClient.Update(tc.Context(), g.Id, g.Version, targets.WithName("bar"))
	checkTarget("update", g, apiErr, err, "bar", 2)

	existed, apiErr, err := tarClient.Delete(tc.Context(), g.Id)
	require.NoError(err)
	assert.Nil(apiErr)
	assert.True(existed, "Expected existing target when deleted, but it wasn't.")

	existed, apiErr, err = tarClient.Delete(tc.Context(), g.Id)
	require.NoError(err)
	assert.Nil(apiErr)
	assert.False(existed, "Expected target to not exist when deleted, but it did.")
}

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
	org, proj := iam.TestScopes(t, tc.IamRepo())
	client.SetScopeId(org.GetPublicId())
	projClient := client.Clone()
	projClient.SetScopeId(proj.GetPublicId())

	tarClient := targets.NewTargetsClient(projClient)
	u, apiErr, err := tarClient.Create(tc.Context(), "tcp", targets.WithName("first"))
	require.NoError(err)
	assert.Nil(apiErr)
	assert.NotNil(u)

	// Create another resource with the same name.
	_, apiErr, err = tarClient.Create(tc.Context(), "tcp", targets.WithName("first"))
	require.NoError(err)
	assert.NotNil(apiErr)

	_, apiErr, err = tarClient.Read(tc.Context(), "ttcp_doesntexis")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Status)

	_, apiErr, err = tarClient.Update(tc.Context(), u.Id, u.Version, targets.DefaultName())
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Status)

	_, apiErr, err = tarClient.Read(tc.Context(), "invalid id")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusForbidden, apiErr.Status)

	_, apiErr, err = tarClient.Update(tc.Context(), u.Id, u.Version)
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Status)
}
