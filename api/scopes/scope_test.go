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

	pl, apiErr, err := scps.List(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.Nil(apiErr)
	assert.Empty(pl.Items)

	expected := make([]*scopes.Scope, 10)
	for i := 0; i < 10; i++ {
		scr, apiErr, err := scps.Create(tc.Context(), org.GetPublicId(), scopes.WithName(fmt.Sprintf("%d", i)))
		require.NoError(err)
		assert.Nil(apiErr)
		expected[i] = scr.Item
	}
	pl, apiErr, err = scps.List(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(pl.Items))
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

	checkProject := func(step string, s *scopes.Scope, apiErr *api.Error, err error, wantedName string, wantedVersion uint32) {
		require.NoError(err, step)
		assert.Nil(apiErr, step)
		assert.NotNil(s, "returned project", step)
		gotName := ""
		if s.Name != "" {
			gotName = s.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.Equal(wantedVersion, s.Version)
	}

	s, apiErr, err := scps.Create(tc.Context(), org.GetPublicId(), scopes.WithName("foo"))
	checkProject("create", s.Item, apiErr, err, "foo", 1)

	s, apiErr, err = scps.Read(tc.Context(), s.Item.Id)
	checkProject("read", s.Item, apiErr, err, "foo", 1)

	s, apiErr, err = scps.Update(tc.Context(), s.Item.Id, s.Item.Version, scopes.WithName("bar"))
	checkProject("update", s.Item, apiErr, err, "bar", 2)

	s, apiErr, err = scps.Update(tc.Context(), s.Item.Id, s.Item.Version, scopes.DefaultName())
	checkProject("update, unset name", s.Item, apiErr, err, "", 3)

	_, apiErr, err = scps.Delete(tc.Context(), s.Item.Id)
	require.NoError(err)
	assert.Nil(apiErr)

	_, apiErr, err = scps.Delete(tc.Context(), s.Item.Id)
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Status)
}

// TODO: Get better coverage for expected errors and error formats.
func TestErrors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	org, _ := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	scps := scopes.NewClient(client)

	createdProj, apiErr, err := scps.Create(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.NotNil(createdProj)
	assert.Nil(apiErr)

	_, apiErr, err = scps.Read(tc.Context(), "p_doesntexis")
	require.NoError(err)
	// TODO: Should this be nil instead of just a Project that has no values set
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Status)

	_, apiErr, err = scps.Read(tc.Context(), "invalid id")
	assert.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Status)
}
