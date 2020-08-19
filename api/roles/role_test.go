package roles_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/groups"
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/kr/pretty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustom(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	amId := "paum_1234567890"
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultAuthMethodId:          amId,
		DefaultLoginName:             "user",
		DefaultPassword:              "passpass",
	})
	defer tc.Shutdown()

	client := tc.Client()
	org, proj := iam.TestScopes(t, tc.IamRepo())
	client.SetScopeId(org.GetPublicId())
	projClient := client.Clone()
	projClient.SetScopeId(proj.GetPublicId())

	cases := []struct {
		name        string
		scopeClient *api.Client
	}{
		{
			name:        "org",
			scopeClient: client,
		},
		{
			name:        "proj",
			scopeClient: projClient,
		},
	}

	user, apiErr, err := users.NewUsersClient(client).Create(tc.Context())
	require.NoError(err)
	require.Nil(apiErr)

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

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			g, apiErr, err := groups.NewGroupsClient(tt.scopeClient).Create(tc.Context())
			require.NoError(err)
			require.Nil(apiErr)
			require.NotNil(g)

			rc := roles.NewRolesClient(tt.scopeClient)
			var version uint32 = 1

			r, apiErr, err := rc.Create(tc.Context(), roles.WithName("foo"))
			require.NoError(err)
			require.Nil(apiErr)
			require.NotNil(r)
			require.EqualValues(r.Version, version)
			version++

			updatedRole, apiErr, err := rc.AddPrincipals(tc.Context(), r.Id, r.Version, []string{g.Id})
			require.NoError(err)
			require.Nil(apiErr, "Got error ", pretty.Sprint(apiErr))
			assert.EqualValues(updatedRole.Version, version)
			assert.True(hasPrincipal(updatedRole, g.Id))
			version++

			updatedRole, apiErr, err = rc.SetPrincipals(tc.Context(), updatedRole.Id, updatedRole.Version, []string{user.Id})
			require.NoError(err)
			require.Nil(apiErr, "Got error ", apiErr)
			assert.EqualValues(updatedRole.Version, version)
			assert.True(hasPrincipal(updatedRole, user.Id))
			version++

			updatedRole, apiErr, err = rc.RemovePrincipals(tc.Context(), updatedRole.Id, updatedRole.Version, []string{user.Id})
			require.NoError(err)
			require.Nil(apiErr, "Got error ", apiErr)
			assert.EqualValues(updatedRole.Version, version)
			assert.Empty(updatedRole.Principals)
			version++

			updatedRole, apiErr, err = rc.AddGrants(tc.Context(), updatedRole.Id, updatedRole.Version, []string{"id=*;actions=read"})
			require.NoError(err)
			require.Nil(apiErr, "Got error ", apiErr)
			assert.EqualValues(updatedRole.Version, version)
			assert.Contains(updatedRole.GrantStrings, "id=*;actions=read")
			version++

			updatedRole, apiErr, err = rc.SetGrants(tc.Context(), updatedRole.Id, updatedRole.Version, []string{"id=*;actions=*"})
			require.NoError(err)
			require.Nil(apiErr, "Got error ", apiErr)
			assert.EqualValues(updatedRole.Version, version)
			assert.Contains(updatedRole.GrantStrings, "id=*;actions=*")
			version++

			updatedRole, apiErr, err = rc.RemoveGrants(tc.Context(), updatedRole.Id, updatedRole.Version, []string{"id=*;actions=*"})
			require.NoError(err)
			require.Nil(apiErr, "Got error ", apiErr)
			assert.EqualValues(updatedRole.Version, version)
			assert.Empty(updatedRole.Grants)
			version++
		})
	}
}

func TestRole_List(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	amId := "paum_1234567890"
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultAuthMethodId:          amId,
		DefaultLoginName:             "user",
		DefaultPassword:              "passpass",
	})
	defer tc.Shutdown()

	client := tc.Client()
	org, proj := iam.TestScopes(t, tc.IamRepo())
	client.SetScopeId(org.GetPublicId())
	projClient := client.Clone()
	projClient.SetScopeId(proj.GetPublicId())

	cases := []struct {
		name        string
		scopeClient *api.Client
	}{
		{
			name:        "org",
			scopeClient: client,
		},
		{
			name:        "proj",
			scopeClient: projClient,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			roleClient := roles.NewRolesClient(tt.scopeClient)
			p1, apiErr, err := roleClient.List(tc.Context())
			require.NoError(err)
			assert.Nil(apiErr)
			require.Len(p1, 0)

			var expected []*roles.Role
			for i := 0; i < 10; i++ {
				expected = append(expected, &roles.Role{Name: fmt.Sprint(i)})
			}

			expected[0], apiErr, err = roleClient.Create(tc.Context(), roles.WithName(expected[0].Name))
			require.NoError(err)
			assert.Nil(apiErr)

			p2, apiErr, err := roleClient.List(tc.Context())
			assert.NoError(err)
			assert.Nil(apiErr)
			assert.ElementsMatch(comparableSlice(expected[:1]), comparableSlice(p2))

			for i := 1; i < 10; i++ {
				expected[i], apiErr, err = roleClient.Create(tc.Context(), roles.WithName(expected[i].Name))
				assert.NoError(err)
				assert.Nil(apiErr)
			}
			p3, apiErr, err := roleClient.List(tc.Context())
			require.NoError(err)
			assert.Nil(apiErr)
			assert.ElementsMatch(comparableSlice(expected), comparableSlice(p3))
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
		}
		filtered = append(filtered, p)
	}
	return filtered
}

func TestRole_Crud(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	amId := "paum_1234567890"
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultAuthMethodId:          amId,
		DefaultLoginName:             "user",
		DefaultPassword:              "passpass",
	})
	defer tc.Shutdown()

	client := tc.Client()
	org, proj := iam.TestScopes(t, tc.IamRepo())
	client.SetScopeId(org.GetPublicId())
	projClient := client.Clone()
	projClient.SetScopeId(proj.GetPublicId())

	cases := []struct {
		name        string
		scopeClient *api.Client
	}{
		{
			name:        "org",
			scopeClient: client,
		},
		{
			name:        "proj",
			scopeClient: projClient,
		},
	}

	checkRole := func(step string, g *roles.Role, apiErr *api.Error, err error, wantedName string, wantedVersion uint32) {
		assert.NoError(err, step)
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
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			roleClient := roles.NewRolesClient(tt.scopeClient)
			g, apiErr, err := roleClient.Create(tc.Context(), roles.WithName("foo"))
			checkRole("create", g, apiErr, err, "foo", 1)

			g, apiErr, err = roleClient.Read(tc.Context(), g.Id)
			checkRole("read", g, apiErr, err, "foo", 1)

			g, apiErr, err = roleClient.Update(tc.Context(), g.Id, g.Version, roles.WithName("bar"))
			checkRole("update", g, apiErr, err, "bar", 2)

			g, apiErr, err = roleClient.Update(tc.Context(), g.Id, g.Version, roles.DefaultName())
			checkRole("update", g, apiErr, err, "", 3)

			existed, apiErr, err := roleClient.Delete(tc.Context(), g.Id)
			require.NoError(err)
			assert.Nil(apiErr)
			assert.True(existed, "Expected existing user when deleted, but it wasn't.")

			existed, apiErr, err = roleClient.Delete(tc.Context(), g.Id)
			require.NoError(err)
			assert.Nil(apiErr)
			assert.False(existed, "Expected user to not exist when deleted, but it did.")
		})
	}
}

func TestRole_Errors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	amId := "paum_1234567890"
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultAuthMethodId:          amId,
		DefaultLoginName:             "user",
		DefaultPassword:              "passpass",
	})
	defer tc.Shutdown()

	client := tc.Client()
	org, proj := iam.TestScopes(t, tc.IamRepo())
	client.SetScopeId(org.GetPublicId())
	projClient := client.Clone()
	projClient.SetScopeId(proj.GetPublicId())

	cases := []struct {
		name        string
		scopeClient *api.Client
	}{
		{
			name:        "org",
			scopeClient: client,
		},
		{
			name:        "proj",
			scopeClient: projClient,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			roleClient := roles.NewRolesClient(tt.scopeClient)
			u, apiErr, err := roleClient.Create(tc.Context(), roles.WithName("first"))
			require.NoError(err)
			assert.Nil(apiErr)
			assert.NotNil(u)

			// Create another resource with the same name.
			_, apiErr, err = roleClient.Create(tc.Context(), roles.WithName("first"))
			require.NoError(err)
			assert.NotNil(apiErr)

			_, apiErr, err = roleClient.Read(tc.Context(), iam.RolePrefix+"_doesntexis")
			require.NoError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusNotFound, apiErr.Status)

			_, apiErr, err = roleClient.Read(tc.Context(), "invalid id")
			require.NoError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusForbidden, apiErr.Status)

			_, apiErr, err = roleClient.Update(tc.Context(), u.Id, u.Version)
			require.NoError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusBadRequest, apiErr.Status)
		})
	}
}
