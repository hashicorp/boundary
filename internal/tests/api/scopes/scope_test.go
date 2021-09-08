package scopes_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
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
	org := iam.TestOrg(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	scps := scopes.NewClient(client)

	pl, err := scps.List(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.Empty(pl.Items)

	expected := make([]*scopes.Scope, 10)
	for i := 0; i < 10; i++ {
		scr, err := scps.Create(tc.Context(), org.GetPublicId(), scopes.WithName(fmt.Sprintf("%d", i)))
		require.NoError(err)
		expected[i] = scr.Item
	}
	pl, err = scps.List(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(pl.Items))

	filterItem := pl.Items[3]
	pl, err = scps.List(tc.Context(), org.GetPublicId(),
		scopes.WithFilter(fmt.Sprintf(`"/item/id"==%q`, filterItem.Id)))
	require.NoError(err)
	assert.Len(pl.Items, 1)
	assert.Equal(filterItem.Id, pl.Items[0].Id)
}

func comparableSlice(in []*scopes.Scope) []scopes.Scope {
	var filtered []scopes.Scope
	for _, i := range in {
		p := scopes.Scope{
			Id:          i.Id,
			ScopeId:     i.ScopeId,
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
	org, _ := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	scps := scopes.NewClient(client)

	checkProject := func(step string, s *scopes.Scope, err error, wantedName string, wantedVersion uint32) {
		require.NoError(err, step)
		assert.NotNil(s, "returned project", step)
		gotName := ""
		if s.Name != "" {
			gotName = s.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.Equal(wantedVersion, s.Version)
	}

	s, err := scps.Create(tc.Context(), org.GetPublicId(), scopes.WithName("foo"))
	checkProject("create", s.Item, err, "foo", 1)

	s, err = scps.Read(tc.Context(), s.Item.Id)
	checkProject("read", s.Item, err, "foo", 1)

	s, err = scps.Update(tc.Context(), s.Item.Id, s.Item.Version, scopes.WithName("bar"))
	checkProject("update", s.Item, err, "bar", 2)

	s, err = scps.Update(tc.Context(), s.Item.Id, s.Item.Version, scopes.DefaultName())
	checkProject("update, unset name", s.Item, err, "", 3)

	_, err = scps.Delete(tc.Context(), s.Item.Id)
	require.NoError(err)

	_, err = scps.Delete(tc.Context(), s.Item.Id)
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
	org, _ := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	scps := scopes.NewClient(client)

	createdProj, err := scps.Create(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.NotNil(createdProj)

	// Updating the wrong version should fail.
	_, err = scps.Update(tc.Context(), createdProj.Item.Id, 73, scopes.WithName("anything"))
	require.Error(err)
	apiErr := api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = scps.Read(tc.Context(), "p_doesntexis")
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = scps.Read(tc.Context(), "invalid id")
	assert.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
}
