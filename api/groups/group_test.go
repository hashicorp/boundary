package groups_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/groups"
	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller"
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
			pl, apiErr, err := grps.List(tc.Context(), tt.scopeId)
			assert.NoError(err)
			assert.Nil(apiErr)
			assert.Empty(pl.Items)

			expected := make([]*groups.Group, 10)
			for i := 0; i < 10; i++ {
				createResult, apiErr, err := grps.Create(tc.Context(), tt.scopeId, groups.WithName(fmt.Sprint(i)))
				require.NoError(err)
				assert.Nil(apiErr)
				expected[i] = createResult.Item
			}
			pl, apiErr, err = grps.List(tc.Context(), tt.scopeId)
			require.NoError(err)
			assert.Nil(apiErr)
			require.NotNil(pl)
			require.Len(pl.Items, 10)
			assert.ElementsMatch(comparableSlice(expected), comparableSlice(pl.Items))
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

	checkGroup := func(step string, g *groups.Group, apiErr *api.Error, err error, wantedName string, wantedVersion uint32, expectedUserIds []string) {
		require.NoError(err, step)
		if !assert.Nil(apiErr, step) && apiErr.Message != "" {
			t.Errorf("ApiError message: %q", apiErr.Message)
		}
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

	user1, apiErr, err := users.NewClient(client).Create(tc.Context(), org.GetPublicId())
	require.NoError(err)
	require.Nil(apiErr)

	user2, apiErr, err := users.NewClient(client).Create(tc.Context(), org.GetPublicId())
	require.NoError(err)
	require.Nil(apiErr)

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			groupsClient := groups.NewClient(client)
			g, apiErr, err := groupsClient.Create(tc.Context(), tt.scopeId, groups.WithName("foo"))
			checkGroup("create", g.Item, apiErr, err, "foo", 1, nil)

			g, apiErr, err = groupsClient.Read(tc.Context(), g.Item.Id)
			checkGroup("read", g.Item, apiErr, err, "foo", 1, nil)

			g, apiErr, err = groupsClient.Update(tc.Context(), g.Item.Id, g.Item.Version, groups.WithName("bar"))
			checkGroup("update", g.Item, apiErr, err, "bar", 2, nil)

			g, apiErr, err = groupsClient.Update(tc.Context(), g.Item.Id, g.Item.Version, groups.DefaultName())
			checkGroup("update", g.Item, apiErr, err, "", 3, nil)

			g, apiErr, err = groupsClient.AddMembers(tc.Context(), g.Item.Id, g.Item.Version, []string{user1.Item.Id})
			checkGroup("update", g.Item, apiErr, err, "", 4, []string{user1.Item.Id})

			g, apiErr, err = groupsClient.SetMembers(tc.Context(), g.Item.Id, g.Item.Version, []string{user2.Item.Id})
			checkGroup("update", g.Item, apiErr, err, "", 5, []string{user2.Item.Id})

			g, apiErr, err = groupsClient.RemoveMembers(tc.Context(), g.Item.Id, g.Item.Version, []string{user2.Item.Id})
			checkGroup("update", g.Item, apiErr, err, "", 6, nil)

			_, apiErr, err = groupsClient.Delete(tc.Context(), g.Item.Id)
			require.NoError(err)
			assert.Nil(apiErr)

			_, apiErr, err = groupsClient.Delete(tc.Context(), g.Item.Id)
			require.NoError(err)
			require.NotNil(apiErr)
			assert.EqualValues(http.StatusNotFound, apiErr.Status)
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

			g, apiErr, err := groupClient.Create(tc.Context(), tt.scopeId, groups.WithName("first"))
			require.NoError(err)
			assert.Nil(apiErr)
			assert.NotNil(g)

			// Create another resource with the same name.
			_, apiErr, err = groupClient.Create(tc.Context(), tt.scopeId, groups.WithName("first"))
			require.NoError(err)
			assert.NotNil(apiErr)

			_, apiErr, err = groupClient.Read(tc.Context(), iam.GroupPrefix+"_doesntexis")
			require.NoError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusNotFound, apiErr.Status)

			_, apiErr, err = groupClient.Read(tc.Context(), "invalid id")
			require.NoError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusBadRequest, apiErr.Status)

			_, apiErr, err = groupClient.Update(tc.Context(), g.Item.Id, g.Item.Version)
			require.NoError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusBadRequest, apiErr.Status)
		})
	}
}
