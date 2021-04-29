package auth_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchActionSetForId(t *testing.T) {
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	conn := tc.DbConn()
	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	org, _ := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))

	iamRepoFn := func() (*iam.Repository, error) {
		return tc.IamRepo(), nil
	}
	serversRepoFn := func() (*servers.Repository, error) {
		return tc.ServersRepo(), nil
	}
	authTokenRepoFn := func() (*authtoken.Repository, error) {
		return tc.AuthTokenRepo(), nil
	}

	orgRole := iam.TestRole(t, conn, org.GetPublicId())
	iam.TestUserRole(t, conn, orgRole.PublicId, token.UserId)
	iam.TestRoleGrant(t, conn, orgRole.PublicId, "id=foo;actions=read,update")
	iam.TestRoleGrant(t, conn, orgRole.PublicId, "id=bar;actions=read,update,delete,authorize-session")
	iam.TestRoleGrant(t, conn, orgRole.PublicId, "id=*;type=role;actions=add-grants,remove-grants")

	cases := []struct {
		name         string
		id           string
		avail        action.ActionSet
		allowed      action.ActionSet
		typeOverride resource.Type
	}{
		{
			name: "base",
		},
		{
			name:  "no match",
			id:    "zip",
			avail: action.ActionSet{action.Read, action.Update},
		},
		{
			name:    "disjoint match",
			id:      "bar",
			avail:   action.ActionSet{action.Delete, action.AddGrants, action.Read, action.RemoveHostSets},
			allowed: action.ActionSet{action.Delete, action.Read},
		},
		{
			name:         "different type",
			id:           "anything",
			typeOverride: resource.Scope,
		},
		{
			name:         "type match",
			id:           "anything",
			typeOverride: resource.Role,
			avail:        action.ActionSet{action.Read, action.AddGrants},
			allowed:      action.ActionSet{action.AddGrants},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			ctx := auth.NewVerifierContext(
				context.Background(),
				tc.Logger(),
				iamRepoFn,
				authTokenRepoFn,
				serversRepoFn,
				tc.Kms(),
				auth.RequestInfo{
					PublicId:       token.Id,
					EncryptedToken: strings.Split(token.Token, "_")[2],
					TokenFormat:    auth.AuthTokenTypeBearer,
				})
			typ := resource.Target
			if tt.typeOverride != resource.Unknown {
				typ = tt.typeOverride
			}
			res := auth.Verify(ctx, []auth.Option{
				auth.WithId("foo"),
				auth.WithAction(action.Read),
				auth.WithScopeId(org.PublicId),
				auth.WithType(typ),
			}...)
			req.NoError(res.Error)
			assert.Equal(t, tt.allowed, res.FetchActionSetForId(ctx, tt.id, tt.avail))
		})
	}
}

func TestRecursiveListingDifferentOutputFields(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	conn := tc.DbConn()
	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	org, _ := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))

	password.TestAuthMethod(t, conn, scope.Global.String(), password.WithName("globalam1"), password.WithDescription("globalam1"))
	password.TestAuthMethod(t, conn, scope.Global.String(), password.WithName("globalam2"), password.WithDescription("globalam2"))
	globalRole := iam.TestRole(t, conn, scope.Global.String())
	iam.TestUserRole(t, conn, globalRole.PublicId, token.UserId)
	iam.TestRoleGrant(t, conn, globalRole.PublicId, "id=*;type=auth-method;output_fields=version,description")
	iam.TestRoleGrant(t, conn, globalRole.PublicId, "id=*;type=auth-method;actions=list;output_fields=name")

	orgAm1 := password.TestAuthMethod(t, conn, org.GetPublicId(), password.WithName("orgam1"), password.WithDescription("orgam1"))
	orgAm2 := password.TestAuthMethod(t, conn, org.GetPublicId(), password.WithName("orgam2"), password.WithDescription("orgam2"))
	orgRole := iam.TestRole(t, conn, org.GetPublicId())
	iam.TestUserRole(t, conn, orgRole.PublicId, token.UserId)
	// The first and second will actually not take effect because it's a list
	// and output fields are scoped by action. So we expect only name and scope_id for the
	// auth methods in the scope, using two patterns below.
	iam.TestRoleGrant(t, conn, orgRole.PublicId, fmt.Sprintf("id=%s;actions=read;output_fields=id,version", orgAm1.GetPublicId()))
	iam.TestRoleGrant(t, conn, orgRole.PublicId, fmt.Sprintf("id=%s;actions=read;output_fields=description", orgAm2.GetPublicId()))
	iam.TestRoleGrant(t, conn, orgRole.PublicId, "id=*;type=auth-method;output_fields=name")
	iam.TestRoleGrant(t, conn, orgRole.PublicId, "id=*;type=auth-method;actions=list;output_fields=scope_id")

	amClient := authmethods.NewClient(tc.Client())
	resp, err := amClient.List(tc.Context(), scope.Global.String(), authmethods.WithRecursive(true))
	require.NoError(err)
	require.NotNil(resp)
	require.NotNil(resp.GetItems())
	assert.Len(resp.GetItems().([]*authmethods.AuthMethod), 5)
	items := resp.GetResponse().Map["items"].([]interface{})
	require.NotNil(items)
	for _, item := range items {
		m := item.(map[string]interface{})
		require.NotNil(m)
		switch {
		case m["scope"] != nil:
			continue
		case m["version"] != nil:
			assert.Len(m, 3)
			assert.Contains(m, "name")
			assert.Contains(m, "description")
		default:
			assert.Len(m, 2)
			assert.Contains(m, "name")
			assert.Contains(m, "scope_id")
		}
	}
}
