// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package hosts_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

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

	hClient := hosts.NewClient(client)

	ul, err := hClient.List(tc.Context(), hc.Item.Id)
	assert.NoError(err)
	assert.Empty(ul.Items)

	var expected []*hosts.Host
	for i := 0; i < 10; i++ {
		expected = append(expected, &hosts.Host{Name: fmt.Sprint(i)})
	}

	hcr, err := hClient.Create(tc.Context(), hc.Item.Id, hosts.WithName(expected[0].Name), hosts.WithStaticHostAddress("someaddress"))
	require.NoError(err)
	expected[0] = hcr.Item

	ul, err = hClient.List(tc.Context(), hc.Item.Id)
	assert.NoError(err)
	assert.ElementsMatch(comparableHostSlice(expected[:1]), comparableHostSlice(ul.Items))

	for i := 1; i < 10; i++ {
		hcr, err = hClient.Create(tc.Context(), hc.Item.Id, hosts.WithName(expected[i].Name), hosts.WithStaticHostAddress("someaddress"))
		assert.NoError(err)
		expected[i] = hcr.Item
	}
	ul, err = hClient.List(tc.Context(), hc.Item.Id)
	require.NoError(err)
	assert.ElementsMatch(comparableHostSlice(expected), comparableHostSlice(ul.Items))

	filterItem := ul.Items[3]
	ul, err = hClient.List(tc.Context(), hc.Item.Id,
		hosts.WithFilter(fmt.Sprintf(`"/item/id"==%q`, filterItem.Id)))
	require.NoError(err)
	assert.Len(ul.Items, 1)
	assert.Equal(filterItem.Id, ul.Items[0].Id)
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

func TestPluginHosts(t *testing.T) {
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

	hset, err := hostsets.NewClient(client).Create(tc.Context(), hc.Item.Id, hostsets.WithAttributes(map[string]any{
		"host_info": []any{
			map[string]any{
				"external_id":  "test1",
				"ip_addresses": []string{"10.0.0.1", "192.168.1.1"},
				"dns_names":    []string{"foo.hashicorp.com", "boundaryproject.io"},
			},
			map[string]any{
				"external_id":  "test2",
				"ip_addresses": []string{"10.0.0.2", "192.168.1.2"},
				"dns_names":    []string{"foo2.hashicorp.com", "boundaryproject2.io"},
			},
		},
	}))
	require.NoError(err)
	require.NotNil(hset)
	time.Sleep(1 * time.Second)

	hClient := hosts.NewClient(client)
	hl, err := hClient.List(tc.Context(), hc.Item.Id)
	require.NoError(err)
	require.Len(hl.Items, 2)

	h, err := hClient.Read(tc.Context(), hl.Items[0].Id)
	require.NoError(err)
	assert.Empty(
		cmp.Diff(
			hl.Items[0],
			h.Item,
			cmpopts.IgnoreUnexported(hosts.Host{}),
			cmpopts.IgnoreFields(hosts.Host{}, "Version", "UpdatedTime"),
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
		),
	)

	_, err = hClient.Update(tc.Context(), h.Item.Id, h.Item.Version, hosts.WithName("foo"))
	require.Error(err)
	_, err = hClient.Delete(tc.Context(), h.Item.Id)
	require.Error(err)
}

func TestCrud(t *testing.T) {
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

	checkHost := func(step string, h *hosts.Host, err error, wantedName string, wantVersion uint32) {
		require.NoError(err, step)
		assert.NotNil(h, "returned no resource", step)
		gotName := ""
		if h.Name != "" {
			gotName = h.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.Equal(wantVersion, h.Version)
	}

	hClient := hosts.NewClient(client)

	h, err := hClient.Create(tc.Context(), hc.Item.Id, hosts.WithName("foo"), hosts.WithStaticHostAddress("someaddress"))
	checkHost("create", h.Item, err, "foo", 1)

	h, err = hClient.Read(tc.Context(), h.Item.Id)
	checkHost("read", h.Item, err, "foo", 1)

	h, err = hClient.Update(tc.Context(), h.Item.Id, h.Item.Version, hosts.WithName("bar"))
	checkHost("update", h.Item, err, "bar", 2)

	h, err = hClient.Update(tc.Context(), h.Item.Id, h.Item.Version, hosts.DefaultName())
	checkHost("update", h.Item, err, "", 3)

	_, err = hClient.Delete(tc.Context(), h.Item.Id)
	assert.NoError(err)

	_, err = hClient.Delete(tc.Context(), h.Item.Id)
	require.Error(err)
	apiErr := api.AsServerError(err)
	assert.NotNil(apiErr)
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

	hClient := hosts.NewClient(client)

	h, err := hClient.Create(tc.Context(), hc.Item.Id, hosts.WithName("foo"), hosts.WithStaticHostAddress("someaddress"))
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
	_, err = hClient.Update(tc.Context(), h.Item.Id, 73, hosts.WithName("anything"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = hClient.Create(tc.Context(), hc.Item.Id, hosts.WithName("foo"), hosts.WithStaticHostAddress("someaddress"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)

	_, err = hClient.Read(tc.Context(), globals.StaticHostPrefix+"_doesntexis")
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
