package groups_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/groups"
	"github.com/hashicorp/watchtower/api/scopes"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type groupCrud interface {
	CreateGroup(context.Context, *groups.Group) (*groups.Group, *api.Error, error)
	ReadGroup(context.Context, *groups.Group) (*groups.Group, *api.Error, error)
	UpdateGroup(context.Context, *groups.Group) (*groups.Group, *api.Error, error)
	DeleteGroup(context.Context, *groups.Group) (bool, *api.Error, error)
}

func TestGroup_Crud(t *testing.T) {
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	org := &scopes.Organization{
		Client: client,
	}

	proj, apiErr, err := org.CreateProject(tc.Context(), &scopes.Project{})
	require.NoError(t, err)
	require.Nil(t, apiErr)

	checkGroup := func(step string, g *groups.Group, apiErr *api.Error, err error, wantedName string) {
		assert := assert.New(t)
		assert.NoError(err, step)
		if !assert.Nil(apiErr, step) && apiErr.Message != nil {
			t.Errorf("ApiError message: %q", *apiErr.Message)
		}
		assert.NotNil(g, "returned no resource", step)
		gotName := ""
		if g.Name != nil {
			gotName = *g.Name
		}
		assert.Equal(wantedName, gotName, step)
	}

	cases := []struct {
		name  string
		scope groupCrud
	}{
		{
			name:  "org",
			scope: org,
		},
		{
			name:  "project",
			scope: proj,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {

			g, apiErr, err := tt.scope.CreateGroup(tc.Context(), &groups.Group{Name: api.String("foo")})
			checkGroup("create", g, apiErr, err, "foo")

			g, apiErr, err = tt.scope.ReadGroup(tc.Context(), &groups.Group{Id: g.Id})
			checkGroup("read", g, apiErr, err, "foo")

			g = &groups.Group{Id: g.Id}
			g.Name = api.String("bar")
			g, apiErr, err = tt.scope.UpdateGroup(tc.Context(), g)
			checkGroup("update", g, apiErr, err, "bar")

			g = &groups.Group{Id: g.Id}
			g.SetDefault("name")
			g, apiErr, err = tt.scope.UpdateGroup(tc.Context(), g)
			checkGroup("update", g, apiErr, err, "")

			existed, apiErr, err := tt.scope.DeleteGroup(tc.Context(), g)
			assert.NoError(t, err)
			assert.True(t, existed, "Expected existing user when deleted, but it wasn't.")

			existed, apiErr, err = tt.scope.DeleteGroup(tc.Context(), g)
			assert.NoError(t, err)
			assert.False(t, existed, "Expected user to not exist when deleted, but it did.")

		})
	}
}

func TestGroup_Errors(t *testing.T) {
	assert := assert.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()
	ctx := tc.Context()

	client := tc.Client()
	org := &scopes.Organization{
		Client: client,
	}

	proj, apiErr, err := org.CreateProject(tc.Context(), &scopes.Project{})
	require.NoError(t, err)
	require.Nil(t, apiErr)

	cases := []struct {
		name  string
		scope groupCrud
	}{
		{
			name:  "org",
			scope: org,
		},
		{
			name:  "project",
			scope: proj,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			u, apiErr, err := tt.scope.CreateGroup(ctx, &groups.Group{Name: api.String("first")})
			assert.NoError(err)
			assert.Nil(apiErr)
			assert.NotNil(u)

			// Create another resource with the same name.
			_, apiErr, err = tt.scope.CreateGroup(ctx, &groups.Group{Name: api.String("first")})
			assert.NoError(err)
			assert.NotNil(apiErr)

			_, apiErr, err = tt.scope.ReadGroup(ctx, &groups.Group{Id: iam.GroupPrefix + "_doesntexis"})
			assert.NoError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(*apiErr.Status, http.StatusNotFound)

			_, apiErr, err = tt.scope.ReadGroup(ctx, &groups.Group{Id: "invalid id"})
			assert.NoError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(*apiErr.Status, http.StatusBadRequest)

			_, apiErr, err = tt.scope.UpdateGroup(ctx, &groups.Group{Id: u.Id})
			assert.NoError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(*apiErr.Status, http.StatusBadRequest)
		})
	}
}
