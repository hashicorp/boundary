// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package hostsets_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/iam"
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
	assert.Empty(
		cmp.Diff(
			comparableSetSlice(expected[:1]),
			comparableSetSlice(ul.Items),
			cmpopts.IgnoreUnexported(hostsets.HostSet{}),
			cmpopts.IgnoreFields(hostsets.HostSet{}, "Version", "UpdatedTime"),
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
		),
	)

	for i := 1; i < 10; i++ {
		hcr, err = hClient.Create(tc.Context(), hc.Item.Id, hostsets.WithName(expected[i].Name))
		require.NoError(err)
		expected[i] = hcr.Item
	}
	ul, err = hClient.List(tc.Context(), hc.Item.Id)
	require.NoError(err)
	assert.Empty(
		cmp.Diff(
			expected,
			ul.Items,
			cmpopts.IgnoreUnexported(hostsets.HostSet{}),
			cmpopts.IgnoreFields(hostsets.HostSet{}, "Version", "UpdatedTime"),
			cmpopts.SortSlices(func(x, y *hostsets.HostSet) bool {
				return x.Id < y.Id
			}),
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
		),
	)

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

	retryableUpdate := func(c *hostsets.Client, hcId string, version uint32, opts ...hostsets.Option) *hostsets.HostSetUpdateResult {
		h, err := c.Update(tc.Context(), hcId, version, opts...)
		if err != nil && strings.Contains(err.Error(), "set version mismatch") {
			// Got a version mismatch, this happens because the sync set job runs in the background
			// and can increment the version between operations in this test, try again
			h, err = c.Update(tc.Context(), hcId, version+1, opts...)
		}
		require.NoError(err)
		assert.NotNil(h)
		return h
	}

	hClient := hostsets.NewClient(client)

	h, err := hClient.Create(tc.Context(), hc.Item.Id, hostsets.WithName("foo"))
	require.NoError(err)
	assert.Equal("foo", h.Item.Name)
	assert.Equal(uint32(1), h.Item.Version)

	h, err = hClient.Read(tc.Context(), h.Item.Id)
	require.NoError(err)
	assert.Equal("foo", h.Item.Name)
	assert.Equal(uint32(1), h.Item.Version)

	h, err = hClient.Update(tc.Context(), h.Item.Id, h.Item.Version, hostsets.WithName("bar"))
	require.NoError(err)
	assert.Equal("bar", h.Item.Name)
	assert.Equal(uint32(2), h.Item.Version)

	h, err = hClient.Update(tc.Context(), h.Item.Id, h.Item.Version, hostsets.DefaultName())
	require.NoError(err)
	assert.Equal("", h.Item.Name)
	assert.Equal(uint32(3), h.Item.Version)

	_, err = hClient.Delete(tc.Context(), h.Item.Id)
	assert.NoError(err)
	_, err = hClient.Delete(tc.Context(), h.Item.Id)
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	// Plugin Sets
	c, err := hcClient.Create(tc.Context(), "plugin", proj.GetPublicId(), hostcatalogs.WithName("pluginfoo"), hostcatalogs.WithPluginId("pl_1234567890"),
		hostcatalogs.WithAttributes(map[string]any{"foo": "bar"}))
	require.NoError(err)

	h, err = hClient.Create(tc.Context(), c.Item.Id, hostsets.WithName("foo"),
		hostsets.WithAttributes(map[string]any{"foo": "bar"}), hostsets.WithPreferredEndpoints([]string{"dns:test"}),
		hostsets.WithSyncIntervalSeconds(-1))
	require.NoError(err)
	assert.Equal("foo", h.Item.Name)
	assert.Equal(uint32(1), h.Item.Version)

	h, err = hClient.Read(tc.Context(), h.Item.Id)
	require.NoError(err)
	assert.Equal("foo", h.Item.Name)
	// If the plugin set has synced after creation, its version will be 2; otherwise it will be 1.
	assert.Contains([]uint32{1, 2}, h.Item.Version)

	h = retryableUpdate(hClient, h.Item.Id, h.Item.Version, hostsets.WithName("bar"),
		hostsets.WithAttributes(map[string]any{"foo": nil, "key": "val"}),
		hostsets.WithPreferredEndpoints([]string{"dns:update"}))
	assert.Equal("bar", h.Item.Name)
	// If the plugin set has synced since creation, its version will be 3; otherwise it will be 2.
	assert.Contains([]uint32{2, 3}, h.Item.Version)

	assert.Equal(h.Item.Attributes, map[string]any{"key": "val"})
	assert.Equal(h.Item.PreferredEndpoints, []string{"dns:update"})

	h = retryableUpdate(hClient, h.Item.Id, h.Item.Version, hostsets.WithSyncIntervalSeconds(42))
	require.NoError(err)
	require.NotNil(h)
	assert.Equal(int32(42), h.Item.SyncIntervalSeconds)

	_, err = hClient.Delete(tc.Context(), h.Item.Id)
	assert.NoError(err)
	_, err = hClient.Delete(tc.Context(), h.Item.Id)
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())
}

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

	// A malformed id is processed as the id and not a different path to the api.
	_, err = hClient.Read(tc.Context(), fmt.Sprintf("%s/../", h.Item.Id))
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
	require.Len(apiErr.Details.RequestFields, 1)
	assert.Equal(apiErr.Details.RequestFields[0].Name, "id")

	// Updating the wrong version should fail.
	_, err = hClient.Update(tc.Context(), h.Item.Id, 73, hostsets.WithName("anything"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	h, err = hClient.Create(tc.Context(), hc.Item.Id, hostsets.WithName("foo"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.Nil(h)

	_, err = hClient.Read(tc.Context(), globals.StaticHostSetPrefix+"_doesntexis")
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
