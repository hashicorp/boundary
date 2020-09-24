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

	user, err := users.NewClient(client).Create(tc.Context(), org.GetPublicId())
	require.NoError(err)

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
			g, err := groups.NewClient(client).Create(tc.Context(), tt.scopeId)
			require.NoError(err)
			require.NotNil(g)

			rc := roles.NewClient(client)
			var version uint32 = 1

			r, err := rc.Create(tc.Context(), tt.scopeId, roles.WithName("foo"))
			require.NoError(err)
			require.NotNil(r)
			require.EqualValues(r.Item.Version, version)
			version++

			updatedRole, err := rc.AddPrincipals(tc.Context(), r.Item.Id, r.Item.Version, []string{g.Item.Id})
			require.NoError(err)
			assert.EqualValues(updatedRole.Item.Version, version)
			assert.True(hasPrincipal(updatedRole.Item, g.Item.Id))
			version++

			updatedRole, err = rc.SetPrincipals(tc.Context(), updatedRole.Item.Id, updatedRole.Item.Version, []string{user.Item.Id})
			require.NoError(err)
			assert.EqualValues(updatedRole.Item.Version, version)
			assert.True(hasPrincipal(updatedRole.Item, user.Item.Id))
			version++

			updatedRole, err = rc.RemovePrincipals(tc.Context(), updatedRole.Item.Id, updatedRole.Item.Version, []string{user.Item.Id})
			require.NoError(err)
			assert.EqualValues(updatedRole.Item.Version, version)
			assert.Empty(updatedRole.Item.Principals)
			version++

			updatedRole, err = rc.AddGrants(tc.Context(), updatedRole.Item.Id, updatedRole.Item.Version, []string{"id=*;actions=read"})
			require.NoError(err)
			assert.EqualValues(updatedRole.Item.Version, version)
			assert.Contains(updatedRole.Item.GrantStrings, "id=*;actions=read")
			version++

			updatedRole, err = rc.SetGrants(tc.Context(), updatedRole.Item.Id, updatedRole.Item.Version, []string{"id=*;actions=*"})
			require.NoError(err)
			assert.EqualValues(updatedRole.Item.Version, version)
			assert.Contains(updatedRole.Item.GrantStrings, "id=*;actions=*")
			version++

			updatedRole, err = rc.RemoveGrants(tc.Context(), updatedRole.Item.Id, updatedRole.Item.Version, []string{"id=*;actions=*"})
			require.NoError(err)
			assert.EqualValues(updatedRole.Item.Version, version)
			assert.Empty(updatedRole.Item.Grants)
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
			p1, err := roleClient.List(tc.Context(), tt.scopeId)
			require.NoError(err)
			require.Len(p1.Items, 1)
			expected = append(expected, p1.Items[0])

			for i := 1; i < 11; i++ {
				expected = append(expected, &roles.Role{Name: fmt.Sprint(i)})
			}

			rcr, err := roleClient.Create(tc.Context(), tt.scopeId, roles.WithName(expected[1].Name))
			require.NoError(err)
			expected[1] = rcr.Item

			p2, err := roleClient.List(tc.Context(), tt.scopeId)
			require.NoError(err)
			assert.ElementsMatch(comparableSlice(expected[0:2]), comparableSlice(p2.Items))

			for i := 2; i < 11; i++ {
				rcr, err = roleClient.Create(tc.Context(), tt.scopeId, roles.WithName(expected[i].Name))
				assert.NoError(err)
				expected[i] = rcr.Item
			}
			p3, err := roleClient.List(tc.Context(), tt.scopeId)
			require.NoError(err)
			assert.ElementsMatch(comparableSlice(expected), comparableSlice(p3.Items))
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

	checkRole := func(step string, g *roles.Role, err error, wantedName string, wantedVersion uint32) {
		assert.NoError(err, step)
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
			g, err := roleClient.Create(tc.Context(), tt.scopeId, roles.WithName("foo"))
			checkRole("create", g.Item, err, "foo", 1)

			g, err = roleClient.Read(tc.Context(), g.Item.Id)
			checkRole("read", g.Item, err, "foo", 1)

			g, err = roleClient.Update(tc.Context(), g.Item.Id, g.Item.Version, roles.WithName("bar"))
			checkRole("update", g.Item, err, "bar", 2)

			g, err = roleClient.Update(tc.Context(), g.Item.Id, g.Item.Version, roles.DefaultName())
			checkRole("update", g.Item, err, "", 3)

			_, err = roleClient.Delete(tc.Context(), g.Item.Id)
			require.NoError(err)
		})
	}
}

func TestErrors(t *testing.T) {
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
			assert, require := assert.New(t), require.New(t)
			roleClient := roles.NewClient(client)
			u, err := roleClient.Create(tc.Context(), tt.scopeId, roles.WithName("first"))
			require.NoError(err)
			assert.NotNil(u)

			// Updating the wrong version should fail.
			_, err = roleClient.Update(tc.Context(), u.Item.Id, 73, roles.WithName("anything"))
			require.Error(err)
			apiErr := api.AsServerError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusNotFound, apiErr.Status)

			// Create another resource with the same name.
			_, err = roleClient.Create(tc.Context(), tt.scopeId, roles.WithName("first"))
			require.Error(err)
			apiErr = api.AsServerError(err)
			assert.NotNil(apiErr)

			_, err = roleClient.Read(tc.Context(), iam.RolePrefix+"_doesntexis")
			require.Error(err)
			apiErr = api.AsServerError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusNotFound, apiErr.Status)

			_, err = roleClient.Read(tc.Context(), "invalid id")
			require.Error(err)
			apiErr = api.AsServerError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusBadRequest, apiErr.Status)

			_, err = roleClient.Update(tc.Context(), u.Item.Id, u.Item.Version)
			require.Error(err)
			apiErr = api.AsServerError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusBadRequest, apiErr.Status)
		})
	}
}
