package roles_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/roles"
	"github.com/hashicorp/watchtower/api/scopes"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type roleCrud interface {
	CreateRole(context.Context, *roles.Role) (*roles.Role, *api.Error, error)
	ReadRole(context.Context, *roles.Role) (*roles.Role, *api.Error, error)
	UpdateRole(context.Context, *roles.Role) (*roles.Role, *api.Error, error)
	DeleteRole(context.Context, *roles.Role) (bool, *api.Error, error)
}

func TestRole_Crud(t *testing.T) {
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	org := &scopes.Organization{
		Client: client,
	}

	proj, apiErr, err := org.CreateProject(tc.Context(), &scopes.Project{})
	require.NoError(t, err)
	require.Nil(t, apiErr)

	checkRole := func(step string, g *roles.Role, apiErr *api.Error, err error, wantedName string) {
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
		scope roleCrud
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
			g, apiErr, err := tt.scope.CreateRole(tc.Context(), &roles.Role{Name: api.String("foo")})
			checkRole("create", g, apiErr, err, "foo")

			g, apiErr, err = tt.scope.ReadRole(tc.Context(), &roles.Role{Id: g.Id})
			checkRole("read", g, apiErr, err, "foo")

			g = &roles.Role{Id: g.Id}
			g.Name = api.String("bar")
			g, apiErr, err = tt.scope.UpdateRole(tc.Context(), g)
			checkRole("update", g, apiErr, err, "bar")

			g = &roles.Role{Id: g.Id}
			g.SetDefault("name")
			g, apiErr, err = tt.scope.UpdateRole(tc.Context(), g)
			checkRole("update", g, apiErr, err, "")

			existed, apiErr, err := tt.scope.DeleteRole(tc.Context(), g)
			assert.NoError(t, err)
			assert.True(t, existed, "Expected existing user when deleted, but it wasn't.")

			existed, apiErr, err = tt.scope.DeleteRole(tc.Context(), g)
			assert.NoError(t, err)
			assert.False(t, existed, "Expected user to not exist when deleted, but it did.")
		})
	}
}

func TestRole_Errors(t *testing.T) {
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
		scope roleCrud
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
			u, apiErr, err := tt.scope.CreateRole(ctx, &roles.Role{Name: api.String("first")})
			assert.NoError(err)
			assert.Nil(apiErr)
			assert.NotNil(u)

			// Create another resource with the same name.
			_, apiErr, err = tt.scope.CreateRole(ctx, &roles.Role{Name: api.String("first")})
			assert.NoError(err)
			assert.NotNil(apiErr)

			_, apiErr, err = tt.scope.ReadRole(ctx, &roles.Role{Id: iam.RolePrefix + "_doesntexis"})
			assert.NoError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(*apiErr.Status, http.StatusNotFound)

			_, apiErr, err = tt.scope.ReadRole(ctx, &roles.Role{Id: "invalid id"})
			assert.NoError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(*apiErr.Status, http.StatusBadRequest)

			_, apiErr, err = tt.scope.UpdateRole(ctx, &roles.Role{Id: u.Id})
			assert.NoError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(*apiErr.Status, http.StatusBadRequest)
		})
	}
}
