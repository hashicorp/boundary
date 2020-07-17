package roles_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/groups"
	"github.com/hashicorp/watchtower/api/roles"
	"github.com/hashicorp/watchtower/api/scopes"
	"github.com/hashicorp/watchtower/api/users"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type roleCrud interface {
	CreateGroup(context.Context, *groups.Group) (*groups.Group, *api.Error, error)
	CreateRole(context.Context, *roles.Role) (*roles.Role, *api.Error, error)
	ReadRole(context.Context, *roles.Role) (*roles.Role, *api.Error, error)
	UpdateRole(context.Context, *roles.Role) (*roles.Role, *api.Error, error)
	DeleteRole(context.Context, *roles.Role) (bool, *api.Error, error)
	ListRoles(ctx context.Context) ([]*roles.Role, *api.Error, error)
}

func TestCustom(t *testing.T) {
	tc := controller.NewTestController(t, &controller.TestControllerOpts{DisableAuthorizationFailures: true})
	defer tc.Shutdown()

	client := tc.Client()
	org := &scopes.Org{
		Client: client,
	}
	proj, apiErr, err := org.CreateProject(context.Background(), &scopes.Project{})
	require.NoError(t, err)
	require.Nil(t, apiErr)

	user, apiErr, err := org.CreateUser(context.Background(), &users.User{})
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
			name:  "proj",
			scope: proj,
		},
	}

	hasPrincipal := func(role *roles.Role, principalId string) bool {
		var foundInPrincipals bool
		var foundInPrincipalIds bool
		for _, v := range role.Principals {
			if v.Id == principalId {
				foundInPrincipals = true
			}
		}
		for _, v := range role.PrincipalIds {
			if v == principalId {
				foundInPrincipalIds = true
			}
		}
		return foundInPrincipals && foundInPrincipalIds
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			ctx := context.Background()
			g, apiErr, err := tc.scope.CreateGroup(ctx, &groups.Group{})
			require.NoError(err)
			require.Nil(apiErr)
			require.NotNil(g)

			r, apiErr, err := tc.scope.CreateRole(ctx, &roles.Role{Name: api.String("foo")})
			require.NoError(err)
			require.Nil(apiErr)
			require.NotNil(r)

			updatedRole, apiErr, err := r.AddPrincipals(ctx, []string{g.Id})
			require.NoError(err)
			require.Nil(apiErr, "Got error ", apiErr)
			assert.Equal(t, updatedRole.Version, r.Version+1)
			assert.True(t, hasPrincipal(updatedRole, g.Id))

			r = updatedRole
			updatedRole, apiErr, err = r.SetPrincipals(ctx, []string{user.Id})
			require.NoError(err)
			require.Nil(apiErr, "Got error ", apiErr)
			assert.Equal(t, updatedRole.Version, r.Version+1)
			assert.True(t, hasPrincipal(updatedRole, user.Id))

			r = updatedRole
			updatedRole, apiErr, err = r.RemovePrincipals(ctx, []string{user.Id})
			require.NoError(err)
			require.Nil(apiErr, "Got error ", apiErr)
			assert.Equal(t, updatedRole.Version, r.Version+1)
			assert.Empty(t, updatedRole.Principals)

			r = updatedRole
			updatedRole, apiErr, err = r.AddGrants(ctx, []string{"id=*;actions=read"})
			require.NoError(err)
			require.Nil(apiErr, "Got error ", apiErr)
			assert.Equal(t, updatedRole.Version, r.Version+1)
			assert.Contains(t, updatedRole.GrantStrings, "id=*;actions=read")

			r = updatedRole
			updatedRole, apiErr, err = r.SetGrants(ctx, []string{"id=*;actions=*"})
			require.NoError(err)
			require.Nil(apiErr, "Got error ", apiErr)
			assert.Equal(t, updatedRole.Version, r.Version+1)
			assert.Contains(t, updatedRole.GrantStrings, "id=*;actions=*")

			r = updatedRole
			updatedRole, apiErr, err = r.RemoveGrants(ctx, []string{"id=*;actions=*"})
			require.NoError(err)
			require.Nil(apiErr, "Got error ", apiErr)
			assert.Equal(t, updatedRole.Version, r.Version+1)
			assert.Empty(t, updatedRole.Grants)
		})
	}
}

func TestRole_List(t *testing.T) {
	tc := controller.NewTestController(t, &controller.TestControllerOpts{DisableAuthorizationFailures: true})
	defer tc.Shutdown()

	client := tc.Client()
	org := &scopes.Org{
		Client: client,
	}
	proj, apiErr, err := org.CreateProject(context.Background(), &scopes.Project{})
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
			name:  "proj",
			scope: proj,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()

			p1, apiErr, err := tc.scope.ListRoles(ctx)
			require.NoError(err)
			assert.Nil(apiErr)
			var defaultRoleIds []string
			if tc.name == "org" {
				require.True(2 == len(p1))
				defaultRoleIds = []string{p1[0].Id, p1[1].Id}
			} else {
				require.Empty(p1)
			}

			var expected []*roles.Role
			for i := 0; i < 10; i++ {
				expected = append(expected, &roles.Role{Name: api.String(fmt.Sprint(i))})
			}

			expected[0], apiErr, err = tc.scope.CreateRole(ctx, expected[0])
			require.NoError(err)
			assert.Nil(apiErr)

			p2, apiErr, err := tc.scope.ListRoles(ctx)
			assert.NoError(err)
			assert.Nil(apiErr)
			var p2ForComparison []*roles.Role
			for _, v := range p2 {
				if !strutil.StrListContains(defaultRoleIds, v.Id) {
					p2ForComparison = append(p2ForComparison, v)
				}
			}
			assert.ElementsMatch(comparableSlice(expected[:1]), comparableSlice(p2ForComparison))

			for i := 1; i < 10; i++ {
				expected[i], apiErr, err = tc.scope.CreateRole(ctx, expected[i])
				assert.NoError(err)
				assert.Nil(apiErr)
			}
			p3, apiErr, err := tc.scope.ListRoles(ctx)
			require.NoError(err)
			assert.Nil(apiErr)
			var p3ForComparison []*roles.Role
			for _, v := range p3 {
				if !strutil.StrListContains(defaultRoleIds, v.Id) {
					p3ForComparison = append(p3ForComparison, v)
				}
			}
			assert.ElementsMatch(comparableSlice(expected), comparableSlice(p3ForComparison))
		})
	}
}

func comparableSlice(in []*roles.Role) []roles.Role {
	var filtered []roles.Role
	for _, i := range in {
		p := roles.Role{
			Id:          i.Id,
			Name:        i.Name,
			Description: i.Description,
			CreatedTime: i.CreatedTime,
			UpdatedTime: i.UpdatedTime,
			Disabled:    i.Disabled,
		}
		filtered = append(filtered, p)
	}
	return filtered
}

func TestRole_Crud(t *testing.T) {
	tc := controller.NewTestController(t, &controller.TestControllerOpts{DisableAuthorizationFailures: true})
	defer tc.Shutdown()

	client := tc.Client()
	org := &scopes.Org{
		Client: client,
	}

	proj, apiErr, err := org.CreateProject(tc.Context(), &scopes.Project{})
	require.NoError(t, err)
	require.Nil(t, apiErr)

	checkRole := func(step string, g *roles.Role, apiErr *api.Error, err error, wantedName string) {
		assert := assert.New(t)
		assert.NoError(err, step)
		if !assert.Nil(apiErr, step) && apiErr.Message != "" {
			t.Errorf("ApiError message: %q", apiErr.Message)
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
			assert, require := assert.New(t), require.New(t)
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
			require.NoError(err)
			assert.Nil(apiErr)
			assert.True(existed, "Expected existing user when deleted, but it wasn't.")

			existed, apiErr, err = tt.scope.DeleteRole(tc.Context(), g)
			require.NoError(err)
			assert.Nil(apiErr)
			assert.False(existed, "Expected user to not exist when deleted, but it did.")
		})
	}
}

func TestRole_Errors(t *testing.T) {
	tc := controller.NewTestController(t, &controller.TestControllerOpts{DisableAuthorizationFailures: true})
	defer tc.Shutdown()
	ctx := tc.Context()

	client := tc.Client()
	org := &scopes.Org{
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
			assert, require := assert.New(t), require.New(t)
			u, apiErr, err := tt.scope.CreateRole(ctx, &roles.Role{Name: api.String("first")})
			require.NoError(err)
			assert.Nil(apiErr)
			assert.NotNil(u)

			// Create another resource with the same name.
			_, apiErr, err = tt.scope.CreateRole(ctx, &roles.Role{Name: api.String("first")})
			require.NoError(err)
			assert.NotNil(apiErr)

			_, apiErr, err = tt.scope.ReadRole(ctx, &roles.Role{Id: iam.RolePrefix + "_doesntexis"})
			require.NoError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusNotFound, apiErr.Status)

			_, apiErr, err = tt.scope.ReadRole(ctx, &roles.Role{Id: "invalid id"})
			require.NoError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusBadRequest, apiErr.Status)

			_, apiErr, err = tt.scope.UpdateRole(ctx, &roles.Role{Id: u.Id})
			require.NoError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusBadRequest, apiErr.Status)
		})
	}
}
