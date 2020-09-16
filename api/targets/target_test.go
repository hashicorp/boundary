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
	"github.com/hashicorp/boundary/internal/target"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustom(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	token := tc.Token()
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	client := tc.Client().Clone()
	client.SetToken(token.Token)

	hc, apiErr, err := hostcatalogs.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(err)
	require.Nil(apiErr)

	hSetClient := hostsets.NewClient(client)
	hSet, apiErr, err := hSetClient.Create(tc.Context(), hc.Item.Id)
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(hSet)
	hSet2, apiErr, err := hSetClient.Create(tc.Context(), hc.Item.Id)
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(hSet2)

	tarClient := targets.NewClient(client)
	tar, apiErr, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("foo"))
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(tar)
	assert.Empty(tar.Item.HostSetIds)

	tar, apiErr, err = tarClient.AddHostSets(tc.Context(), tar.Item.Id, tar.Item.Version, []string{hSet.Item.Id})
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(tar)
	assert.ElementsMatch(tar.Item.HostSetIds, []string{hSet.Item.Id})

	tar, apiErr, err = tarClient.SetHostSets(tc.Context(), tar.Item.Id, tar.Item.Version, []string{hSet2.Item.Id})
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(tar)
	assert.ElementsMatch(tar.Item.HostSetIds, []string{hSet2.Item.Id})

	tar, apiErr, err = tarClient.RemoveHostSets(tc.Context(), tar.Item.Id, tar.Item.Version, []string{hSet2.Item.Id})
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(tar)
	assert.Empty(tar.Item.HostSetIds)
}

func TestList(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	tarClient := targets.NewClient(client)
	ul, apiErr, err := tarClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	require.Nil(apiErr)
	assert.Empty(ul.Items)

	var expected []*targets.Target
	for i := 0; i < 10; i++ {
		expected = append(expected, &targets.Target{Name: fmt.Sprint(i)})
	}

	tcr, apiErr, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName(expected[0].Name))
	require.NoError(err)
	require.Nil(apiErr)
	expected[0] = tcr.Item

	ul, apiErr, err = tarClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	require.Nil(apiErr)
	assert.ElementsMatch(comparableSlice(expected[:1]), comparableSlice(ul.Items))

	for i := 1; i < 10; i++ {
		tcr, apiErr, err = tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName(expected[i].Name))
		require.NoError(err)
		require.Nil(apiErr)
		expected[i] = tcr.Item
	}
	ul, apiErr, err = tarClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	require.Nil(apiErr)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(ul.Items))
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

	checkResource := func(t *testing.T, step string, h *targets.Target, apiErr *api.Error, err error, wantedName string, wantVersion uint32) {
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

	tarClient := targets.NewClient(client)

	tar, apiErr, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("foo"))
	checkResource(t, "create", tar.Item, apiErr, err, "foo", 1)

	tar, apiErr, err = tarClient.Read(tc.Context(), tar.Item.Id)
	checkResource(t, "read", tar.Item, apiErr, err, "foo", 1)

	tar, apiErr, err = tarClient.Update(tc.Context(), tar.Item.Id, tar.Item.Version, targets.WithName("bar"))
	checkResource(t, "update", tar.Item, apiErr, err, "bar", 2)

	_, apiErr, err = tarClient.Delete(tc.Context(), tar.Item.Id)
	assert.NoError(err)
	assert.Nil(apiErr)

	_, apiErr, err = tarClient.Delete(tc.Context(), tar.Item.Id)
	assert.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Status)
}

// TODO: Get better coverage for expected errors and error formats.
func TestSet_Errors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	tarClient := targets.NewClient(client)

	tar, apiErr, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("foo"))
	require.NoError(err)
	require.Nil(apiErr)
	assert.NotNil(tar)
	tar, apiErr, err = tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("foo"))
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.Nil(tar)

	_, apiErr, err = tarClient.Read(tc.Context(), target.TcpTargetPrefix+"_doesntexis")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Status)

	_, apiErr, err = tarClient.Read(tc.Context(), "invalid id")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Status)
}
