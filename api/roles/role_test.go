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

	user, apiErr, err := users.NewClient(client).Create(tc.Context(), org.GetPublicId())
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
			g, apiErr, err := groups.NewClient(client).Create(tc.Context(), tt.scopeId)
			require.NoError(err)
			require.Nil(apiErr)
			require.NotNil(g)

			rc := roles.NewClient(client)
			var version uint32 = 1

			r, apiErr, err := rc.Create(tc.Context(), tt.scopeId, roles.WithName("foo"))
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
			var expected []*roles.Role

			roleClient := roles.NewClient(client)
			p1, apiErr, err := roleClient.List(tc.Context(), tt.scopeId)
			require.NoError(err)
			assert.Nil(apiErr)
			require.Len(p1, 1)
			expected = append(expected, p1[0])

			for i := 1; i < 11; i++ {
				expected = append(expected, &roles.Role{Name: fmt.Sprint(i)})
			}

			expected[1], apiErr, err = roleClient.Create(tc.Context(), tt.scopeId, roles.WithName(expected[1].Name))
			require.NoError(err)
			assert.Nil(apiErr)

			p2, apiErr, err := roleClient.List(tc.Context(), tt.scopeId)
			assert.NoError(err)
			assert.Nil(apiErr)
			assert.ElementsMatch(comparableSlice(expected[0:2]), comparableSlice(p2))

			for i := 2; i < 11; i++ {
				expected[i], apiErr, err = roleClient.Create(tc.Context(), tt.scopeId, roles.WithName(expected[i].Name))
				assert.NoError(err)
				assert.Nil(apiErr)
			}
			p3, apiErr, err := roleClient.List(tc.Context(), tt.scopeId)
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

func TestCrud(t *testing.T) {
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
			roleClient := roles.NewClient(client)
			g, apiErr, err := roleClient.Create(tc.Context(), tt.scopeId, roles.WithName("foo"))
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
			roleClient := roles.NewClient(client)
			u, apiErr, err := roleClient.Create(tc.Context(), tt.scopeId, roles.WithName("first"))
			require.NoError(err)
			assert.Nil(apiErr)
			assert.NotNil(u)

			// Create another resource with the same name.
			_, apiErr, err = roleClient.Create(tc.Context(), tt.scopeId, roles.WithName("first"))
			require.NoError(err)
			assert.NotNil(apiErr)

			_, apiErr, err = roleClient.Read(tc.Context(), iam.RolePrefix+"_doesntexis")
			require.NoError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusNotFound, apiErr.Status)

			_, apiErr, err = roleClient.Read(tc.Context(), "invalid id")
			require.NoError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusBadRequest, apiErr.Status)

			_, apiErr, err = roleClient.Update(tc.Context(), u.Id, u.Version)
			require.NoError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusBadRequest, apiErr.Status)
		})
	}
}
