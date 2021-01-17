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

func TestAdditionalVerification(t *testing.T) {
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	conn := tc.DbConn()
	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	org, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))

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
	iam.TestRoleGrant(t, conn, orgRole.PublicId, "id=ampw_1234567890;actions=read,list")

	orgRoleInProj := iam.TestRole(t, conn, org.GetPublicId(), iam.WithGrantScopeId(proj.GetPublicId()))
	iam.TestUserRole(t, conn, orgRoleInProj.PublicId, token.UserId)
	iam.TestRoleGrant(t, conn, orgRoleInProj.PublicId, "id=hcst_1234567890;type=host-set;actions=create,update")

	projRole := iam.TestRole(t, conn, proj.GetPublicId())
	iam.TestUserRole(t, conn, projRole.PublicId, token.UserId)
	iam.TestRoleGrant(t, conn, projRole.PublicId, "id=ttcp_1234567890;actions=authorize-session")

	type additionalCase struct {
		name    string
		opts    []auth.Option
		allowed bool
	}
	cases := []struct {
		name            string
		initialOpts     []auth.Option
		additionalCases []additionalCase
	}{
		{
			name: "base",
			initialOpts: []auth.Option{
				auth.WithId("hsst_1234567890"),
				auth.WithAction(action.Create),
				auth.WithScopeId(proj.PublicId),
				auth.WithType(resource.HostSet),
				auth.WithPin("hcst_1234567890"),
			},
			additionalCases: []additionalCase{
				{
					name: "same as base",
					opts: []auth.Option{
						auth.WithId("hsst_1234567890"),
						auth.WithAction(action.Create),
						auth.WithScopeId(proj.PublicId),
						auth.WithType(resource.HostSet),
						auth.WithPin("hcst_1234567890"),
					},
					allowed: true,
				},
				{
					name: "no pin off from base",
					opts: []auth.Option{
						auth.WithId("hsst_1234567890"),
						auth.WithAction(action.Create),
						auth.WithScopeId(proj.PublicId),
						auth.WithType(resource.HostSet),
					},
				},
				{
					name: "good target",
					opts: []auth.Option{
						auth.WithId("ttcp_1234567890"),
						auth.WithAction(action.AuthorizeSession),
						auth.WithScopeId(proj.PublicId),
						auth.WithType(resource.Target),
					},
					allowed: true,
				},
				{
					name: "cross scope",
					opts: []auth.Option{
						auth.WithId("ampw_1234567890"),
						auth.WithAction(action.List),
						auth.WithScopeId(org.PublicId),
						auth.WithType(resource.AuthMethod),
					},
					allowed: true,
				},
				{
					name: "cross scope, bad action",
					opts: []auth.Option{
						auth.WithId("ampw_1234567890"),
						auth.WithAction(action.Update),
						auth.WithScopeId(org.PublicId),
						auth.WithType(resource.AuthMethod),
					},
				},
			},
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
			res := auth.Verify(ctx, tt.initialOpts...)
			req.NoError(res.Error)

			for _, c := range tt.additionalCases {
				t.Run(c.name, func(t *testing.T) {
					req = require.New(t)
					res = res.AdditionalVerification(ctx, c.opts...)
					if c.allowed {
						req.NoError(res.Error)
					} else {
						req.Error(res.Error)
					}
				})
			}
		})
	}
}

func TestFetchActionsForId(t *testing.T) {
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
			assert.Equal(t, tt.allowed, res.FetchActionsForId(ctx, tt.id, tt.avail))
		})
	}
}
