// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package roles_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/groups"
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/iam"
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

			updatedRole, err = rc.AddGrants(tc.Context(), updatedRole.Item.Id, updatedRole.Item.Version, []string{"ids=*;type=*;actions=read"})
			require.NoError(err)
			assert.EqualValues(updatedRole.Item.Version, version)
			assert.Contains(updatedRole.Item.GrantStrings, "ids=*;type=*;actions=read")
			version++

			updatedRole, err = rc.SetGrants(tc.Context(), updatedRole.Item.Id, updatedRole.Item.Version, []string{"ids=*;type=*;actions=*"})
			require.NoError(err)
			assert.EqualValues(updatedRole.Item.Version, version)
			assert.Contains(updatedRole.Item.GrantStrings, "ids=*;type=*;actions=*")
			version++

			updatedRole, err = rc.RemoveGrants(tc.Context(), updatedRole.Item.Id, updatedRole.Item.Version, []string{"ids=*;type=*;actions=*"})
			require.NoError(err)
			assert.EqualValues(updatedRole.Item.Version, version)
			assert.Empty(updatedRole.Item.Grants)
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
			var numBuiltIn int
			switch tt.name {
			case "org":
				numBuiltIn = 2
			case "proj":
				numBuiltIn = 2
			}
			require.Len(p1.Items, numBuiltIn)
			expected = append(expected, p1.Items[0:numBuiltIn]...)

			for i := numBuiltIn; i < 10+numBuiltIn; i++ {
				expected = append(expected, &roles.Role{Name: fmt.Sprint(i)})
			}

			rcr, err := roleClient.Create(tc.Context(), tt.scopeId, roles.WithName(expected[numBuiltIn].Name))
			require.NoError(err)
			expected[numBuiltIn] = rcr.Item

			p2, err := roleClient.List(tc.Context(), tt.scopeId)
			require.NoError(err)
			assert.ElementsMatch(comparableSlice(expected[0:numBuiltIn+1]), comparableSlice(p2.Items))

			for i := numBuiltIn + 1; i < 10+numBuiltIn; i++ {
				rcr, err = roleClient.Create(tc.Context(), tt.scopeId, roles.WithName(expected[i].Name))
				assert.NoError(err)
				expected[i] = rcr.Item
			}
			p3, err := roleClient.List(tc.Context(), tt.scopeId)
			require.NoError(err)
			assert.ElementsMatch(comparableSlice(expected), comparableSlice(p3.Items))

			filterItem := p3.Items[3]
			p3, err = roleClient.List(tc.Context(), tt.scopeId,
				roles.WithFilter(fmt.Sprintf(`"/item/id"==%q`, filterItem.Id)))
			require.NoError(err)
			assert.Len(p3.Items, 1)
			assert.Equal(filterItem.Id, p3.Items[0].Id)
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

			// A malformed id is processed as the id and not a different path to the api.
			_, err = roleClient.Read(tc.Context(), fmt.Sprintf("%s/../", u.Item.Id))
			require.Error(err)
			apiErr := api.AsServerError(err)
			require.NotNil(apiErr)
			assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
			require.Len(apiErr.Details.RequestFields, 1)
			assert.Equal(apiErr.Details.RequestFields[0].Name, "id")

			// Updating the wrong version should fail.
			_, err = roleClient.Update(tc.Context(), u.Item.Id, 73, roles.WithName("anything"))
			require.Error(err)
			apiErr = api.AsServerError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

			// Create another resource with the same name.
			_, err = roleClient.Create(tc.Context(), tt.scopeId, roles.WithName("first"))
			require.Error(err)
			apiErr = api.AsServerError(err)
			assert.NotNil(apiErr)

			_, err = roleClient.Read(tc.Context(), globals.RolePrefix+"_doesntexis")
			require.Error(err)
			apiErr = api.AsServerError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

			_, err = roleClient.Read(tc.Context(), "invalid id")
			require.Error(err)
			apiErr = api.AsServerError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())

			_, err = roleClient.Update(tc.Context(), u.Item.Id, u.Item.Version)
			require.Error(err)
			apiErr = api.AsServerError(err)
			assert.NotNil(apiErr)
			assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
		})
	}
}
