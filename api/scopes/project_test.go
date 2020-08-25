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

func TestProjects_List(t *testing.T) {
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
	org := iam.TestOrg(t, tc.IamRepo())
	client.SetScopeId(org.GetPublicId())

	scps := scopes.NewScopesClient(client)

	pl, apiErr, err := scps.List(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.Nil(apiErr)
	assert.Empty(pl)

	expected := make([]*scopes.Scope, 10)
	for i := 0; i < 10; i++ {
		expected[i], apiErr, err = scps.Create(tc.Context(), org.GetPublicId(), scopes.WithName(fmt.Sprintf("%d", i)))
		require.NoError(err)
		assert.Nil(apiErr)
	}
	pl, apiErr, err = scps.List(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(pl))
}

func comparableSlice(in []*scopes.Scope) []scopes.Scope {
	var filtered []scopes.Scope
	for _, i := range in {
		p := scopes.Scope{
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

func TestProjects_Crud(t *testing.T) {
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
	org, _ := iam.TestScopes(t, tc.IamRepo())
	client.SetScopeId(org.GetPublicId())

	scps := scopes.NewScopesClient(client)

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
	checkProject("create", s, apiErr, err, "foo", 1)

	s, apiErr, err = scps.Read(tc.Context(), s.Id)
	checkProject("read", s, apiErr, err, "foo", 1)

	s, apiErr, err = scps.Update(tc.Context(), s.Id, s.Version, scopes.WithName("bar"))
	checkProject("update", s, apiErr, err, "bar", 2)

	s, apiErr, err = scps.Update(tc.Context(), s.Id, s.Version, scopes.DefaultName())
	checkProject("update, unset name", s, apiErr, err, "", 3)

	existed, apiErr, err := scps.Delete(tc.Context(), s.Id)
	require.NoError(err)
	assert.Nil(apiErr)
	assert.True(existed, "Expected existing project when deleted, but it wasn't.")

	_, apiErr, err = scps.Delete(tc.Context(), s.Id)
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusForbidden, apiErr.Status, "Expected project to not exist when deleted, but it did.")
}

// TODO: Get better coverage for expected errors and error formats.
func TestProject_Errors(t *testing.T) {
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
	org, _ := iam.TestScopes(t, tc.IamRepo())
	client.SetScopeId(org.GetPublicId())

	scps := scopes.NewScopesClient(client)

	createdProj, apiErr, err := scps.Create(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.NotNil(createdProj)
	assert.Nil(apiErr)

	_, apiErr, err = scps.Read(tc.Context(), "p_doesntexis")
	require.NoError(err)
	// TODO: Should this be nil instead of just a Project that has no values set
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusForbidden, apiErr.Status)

	_, apiErr, err = scps.Read(tc.Context(), "invalid id")
	assert.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusForbidden, apiErr.Status)
}
