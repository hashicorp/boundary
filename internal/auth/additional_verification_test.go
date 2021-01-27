package auth_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
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
	iam.TestRoleGrant(t, conn, orgRole.PublicId, "id=bar;actions=read,update,delete,list,authorize-session")
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
