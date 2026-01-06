// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package groups_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/groups"
	"github.com/hashicorp/boundary/api/users"
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
	org, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	cases := []struct {
		name    string
		scopeId string
	}{
		{
			name:    "org",
			scopeId: org.GetPublicId(),
		},
		{
			name:    "proj",
			scopeId: proj.GetPublicId(),
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			grps := groups.NewClient(client)
			pl, err := grps.List(tc.Context(), tt.scopeId)
			assert.NoError(err)
			assert.Empty(pl.Items)

			expected := make([]*groups.Group, 10)
			for i := 0; i < 10; i++ {
				createResult, err := grps.Create(tc.Context(), tt.scopeId, groups.WithName(fmt.Sprint(i)))
				require.NoError(err)
				expected[i] = createResult.Item
			}
			pl, err = grps.List(tc.Context(), tt.scopeId)
			require.NoError(err)
			require.NotNil(pl)
			require.Len(pl.Items, 10)
			assert.ElementsMatch(comparableSlice(expected), comparableSlice(pl.Items))

			filterItem := pl.Items[3]
			pl, err = grps.List(tc.Context(), tt.scopeId,
				groups.WithFilter(fmt.Sprintf(`"/item/id"==%q`, filterItem.Id)))
			require.NoError(err)
			assert.Len(pl.Items, 1)
			assert.Equal(filterItem.Id, pl.Items[0].Id)
		})
	}
}

func comparableSlice(in []*groups.Group) []groups.Group {
	var filtered []groups.Group
	for _, i := range in {
		p := groups.Group{
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
	org, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	checkGroup := func(step string, g *groups.Group, err error, wantedName string, wantedVersion uint32, expectedUserIds []string) {
		require.NoError(err, step)
		assert.NotNil(g, "returned no resource", step)
		gotName := ""
		if g.Name != "" {
			gotName = g.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.EqualValues(wantedVersion, g.Version)
		assert.Equal(len(expectedUserIds), len(g.MemberIds))
		if len(expectedUserIds) > 0 {
			assert.EqualValues(expectedUserIds, g.MemberIds)
		}
	}

	cases := []struct {
		name    string
		scopeId string
	}{
		{
			name:    "org",
			scopeId: org.GetPublicId(),
		},
		{
			name:    "proj",
			scopeId: proj.GetPublicId(),
		},
	}

	user1, err := users.NewClient(client).Create(tc.Context(), org.GetPublicId())
	require.NoError(err)

	user2, err := users.NewClient(client).Create(tc.Context(), org.GetPublicId())
	require.NoError(err)

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			groupsClient := groups.NewClient(client)
			g, err := groupsClient.Create(tc.Context(), tt.scopeId, groups.WithName("foo"))
			checkGroup("create", g.Item, err, "foo", 1, nil)

			g, err = groupsClient.Read(tc.Context(), g.Item.Id)
			checkGroup("read", g.Item, err, "foo", 1, nil)

			g, err = groupsClient.Update(tc.Context(), g.Item.Id, g.Item.Version, groups.WithName("bar"))
			checkGroup("update", g.Item, err, "bar", 2, nil)

			g, err = groupsClient.Update(tc.Context(), g.Item.Id, g.Item.Version, groups.DefaultName())
			checkGroup("update", g.Item, err, "", 3, nil)

			g, err = groupsClient.AddMembers(tc.Context(), g.Item.Id, g.Item.Version, []string{user1.Item.Id})
			checkGroup("update", g.Item, err, "", 4, []string{user1.Item.Id})

			g, err = groupsClient.SetMembers(tc.Context(), g.Item.Id, g.Item.Version, []string{user2.Item.Id})
			checkGroup("update", g.Item, err, "", 5, []string{user2.Item.Id})

			g, err = groupsClient.RemoveMembers(tc.Context(), g.Item.Id, g.Item.Version, []string{user2.Item.Id})
			checkGroup("update", g.Item, err, "", 6, nil)

			_, err = groupsClient.Delete(tc.Context(), g.Item.Id)
			require.NoError(err)

			_, err = groupsClient.Delete(tc.Context(), g.Item.Id)
			require.Error(err)
			apiErr := api.AsServerError(err)
			require.NotNil(apiErr)
			assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())
		})
	}
}

func TestErrors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	org, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	cases := []struct {
		name    string
		scopeId string
	}{
		{
			name:    "org",
			scopeId: org.GetPublicId(),
		},
		{
			name:    "proj",
			scopeId: proj.GetPublicId(),
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			groupClient := groups.NewClient(client)

			g, err := groupClient.Create(tc.Context(), tt.scopeId, groups.WithName("first"))
			require.NoError(err)
			assert.NotNil(g)

			// A malformed id is processed as the id and not a different path to the api.
			_, err = groupClient.Read(tc.Context(), fmt.Sprintf("%s/../", g.Item.Id))
			require.Error(err)
			apiErr := api.AsServerError(err)
			require.NotNil(apiErr)
			assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
			require.Len(apiErr.Details.RequestFields, 1)
			assert.Equal(apiErr.Details.RequestFields[0].Name, "id")

			// Updating the wrong version should fail.
			_, err = groupClient.Update(tc.Context(), g.Item.Id, 73, groups.WithName("anything"))
			require.Error(err)
			apiErr = api.AsServerError(err)
			require.NotNil(apiErr)
			assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

			// Create another resource with the same name.
			_, err = groupClient.Create(tc.Context(), tt.scopeId, groups.WithName("first"))
			require.Error(err)

			_, err = groupClient.Read(tc.Context(), globals.GroupPrefix+"_doesntexis")
			require.Error(err)
			apiErr = api.AsServerError(err)
			require.NotNil(apiErr)
			assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

			_, err = groupClient.Read(tc.Context(), "invalid id")
			require.Error(err)
			apiErr = api.AsServerError(err)
			require.NotNil(apiErr)
			assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())

			_, err = groupClient.Update(tc.Context(), g.Item.Id, g.Item.Version)
			require.Error(err)
			apiErr = api.AsServerError(err)
			require.NotNil(apiErr)
			assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
		})
	}
}
