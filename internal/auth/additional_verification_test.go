package auth_test

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	authmethodsservice "github.com/hashicorp/boundary/internal/daemon/controller/handlers/authmethods"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/server"
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
	serversRepoFn := func() (*server.Repository, error) {
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
				iamRepoFn,
				authTokenRepoFn,
				serversRepoFn,
				tc.Kms(),
				&authpb.RequestInfo{
					PublicId:       token.Id,
					EncryptedToken: strings.Split(token.Token, "_")[2],
					TokenFormat:    uint32(auth.AuthTokenTypeBearer),
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
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		// Disable this to avoid having to deal with sorting them in the test
		DisableOidcAuthMethodCreation: true,
	})
	defer tc.Shutdown()

	conn := tc.DbConn()
	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)

	// Set some global permissions so we can read the auth method there. Here we
	// will expect the defaults.
	globalRole := iam.TestRole(t, conn, scope.Global.String())
	iam.TestUserRole(t, conn, globalRole.PublicId, token.UserId)
	iam.TestUserRole(t, conn, globalRole.PublicId, auth.AnonymousUserId)
	iam.TestRoleGrant(t, conn, globalRole.PublicId, "id=*;type=auth-method;actions=list,no-op")

	// Create some users at the org level, and some role grants for them
	org, _ := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	orgAm1 := password.TestAuthMethod(t, conn, org.GetPublicId(), password.WithName("orgam1"), password.WithDescription("orgam1"))
	orgAm2 := password.TestAuthMethod(t, conn, org.GetPublicId(), password.WithName("orgam2"), password.WithDescription("orgam2"))
	orgRole := iam.TestRole(t, conn, org.GetPublicId())
	iam.TestUserRole(t, conn, orgRole.PublicId, token.UserId)
	// The first and second will actually not take effect for output
	// grantsbecause it's a list and output fields are scoped by action. So we
	// expect only name and scope_id for the auth methods in the scope, using
	// two patterns below. However, since you need an action on the resource for
	// list to return anything, those grants allow us to list the items, while
	// also verifying that those output fields don't take effect for the wrong
	// action.
	iam.TestRoleGrant(t, conn, orgRole.PublicId, fmt.Sprintf("id=%s;actions=read;output_fields=id,version", orgAm1.GetPublicId()))
	iam.TestRoleGrant(t, conn, orgRole.PublicId, fmt.Sprintf("id=%s;actions=read;output_fields=description", orgAm2.GetPublicId()))
	iam.TestRoleGrant(t, conn, orgRole.PublicId, "id=*;type=auth-method;output_fields=name")
	iam.TestRoleGrant(t, conn, orgRole.PublicId, "id=*;type=auth-method;actions=list;output_fields=scope_id")

	amClient := authmethods.NewClient(tc.Client())
	resp, err := amClient.List(tc.Context(), scope.Global.String(), authmethods.WithRecursive(true))
	// Basic sanity checks
	require.NoError(err)
	require.NotNil(resp)
	require.NotNil(resp.GetItems())
	assert.Len(resp.GetItems().([]*authmethods.AuthMethod), 3)
	items := resp.GetResponse().Map["items"].([]interface{})
	require.NotNil(items)

	// The default generated roles don't have output field definitions for them,
	// so we look for "scope" and if it's there we skip. Otherwise, we look for
	// "version" and if found expect that we will see a global auth method also
	// containing name and description. Otherwise it's an org role and we expect
	// to see name and scope_id. At the end we verify we've seen the exact
	// numbers of each we expect. Note that we expect 3 at global because of the
	// auto generated one.
	var globalAms, orgAms int
	for _, item := range items {
		m := item.(map[string]interface{})
		require.NotNil(m)
		switch m["scope_id"].(string) {
		case scope.Global.String():
			// Validate that it contains fields anon shouldn't; we'll check anon
			// later
			assert.Contains(m, "created_time")
			assert.Contains(m, "attributes")
			globalAms++

		default:
			assert.Len(m, 2)
			assert.Contains(m, "name")
			assert.Contains(m, "scope_id")
			orgAms++
		}
	}
	assert.Equal(1, globalAms)
	assert.Equal(2, orgAms)

	// Now act as the anonymous user and ensure that the fields we checked for
	// before are not available
	tc.Client().SetToken("")
	amClient = authmethods.NewClient(tc.Client())
	resp, err = amClient.List(tc.Context(), scope.Global.String(), authmethods.WithRecursive(true))
	require.NoError(err)
	require.NotNil(resp)
	require.NotNil(resp.GetItems())
	assert.Len(resp.GetItems().([]*authmethods.AuthMethod), 1)
	item := resp.GetResponse().Map["items"].([]interface{})[0].(map[string]interface{})
	assert.NotContains(item, "created_time")
	assert.NotContains(item, "attributes")
}

func TestSelfReadingDifferentOutputFields(t *testing.T) {
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	conn := tc.DbConn()

	s, err := authmethodsservice.NewService(tc.Kms(),
		tc.Controller().PasswordAuthRepoFn,
		tc.Controller().OidcRepoFn,
		tc.Controller().IamRepoFn,
		tc.Controller().AuthTokenRepoFn)
	require.NoError(t, err)

	// Create two auth tokens belonging to different users in the org. Each will
	// have grants below and should be able to read the other token but see more
	// fields for its own.
	org, _ := iam.TestScopes(t, tc.IamRepo(), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	am := password.TestAuthMethod(t, conn, org.GetPublicId())
	acct1 := password.TestAccount(t, conn, am.GetPublicId(), "acct1")
	acct2 := password.TestAccount(t, conn, am.GetPublicId(), "acct2")
	user1 := iam.TestUser(t, tc.IamRepo(), org.GetPublicId(), iam.WithAccountIds(acct1.GetPublicId()))
	user2 := iam.TestUser(t, tc.IamRepo(), org.GetPublicId(), iam.WithAccountIds(acct2.GetPublicId()))
	at1, err := tc.AuthTokenRepo().CreateAuthToken(tc.Context(), user1, acct1.GetPublicId())
	require.NoError(t, err)
	token1, err := s.ConvertInternalAuthTokenToApiAuthToken(tc.Context(), at1)
	require.NoError(t, err)
	at2, err := tc.AuthTokenRepo().CreateAuthToken(tc.Context(), user2, acct2.GetPublicId())
	require.NoError(t, err)
	token2, err := s.ConvertInternalAuthTokenToApiAuthToken(tc.Context(), at2)
	require.NoError(t, err)

	orgRole := iam.TestRole(t, conn, org.GetPublicId())
	iam.TestUserRole(t, conn, orgRole.PublicId, user1.GetPublicId())
	iam.TestUserRole(t, conn, orgRole.PublicId, user2.GetPublicId())
	iam.TestRoleGrant(t, conn, orgRole.PublicId, "id=*;type=auth-token;actions=read:self;output_fields=account_id")
	iam.TestRoleGrant(t, conn, orgRole.PublicId, "id=*;type=auth-token;actions=read;output_fields=id,scope_id")

	cases := []struct {
		name     string
		token    string
		lookupId string
		keys     []string
	}{
		{
			name:     "at1 self",
			token:    token1.GetToken(),
			lookupId: token1.GetId(),
			keys:     []string{"id", "scope_id", "account_id"},
		},
		{
			name:     "at2 self",
			token:    token2.GetToken(),
			lookupId: token2.GetId(),
			keys:     []string{"id", "scope_id", "account_id"},
		},
		{
			name:     "at1 other",
			token:    token1.GetToken(),
			lookupId: token2.GetId(),
			keys:     []string{"id", "scope_id"},
		},
		{
			name:     "at2 other",
			token:    token2.GetToken(),
			lookupId: token1.GetId(),
			keys:     []string{"id", "scope_id"},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			client := tc.Client().Clone()
			client.SetToken(test.token)
			atClient := authtokens.NewClient(client)
			resp, err := atClient.Read(tc.Context(), test.lookupId)
			require.NoError(err)
			require.NotNil(resp)
			require.NotNil(resp.GetItem())
			item := resp.GetResponse().Map
			require.NotNil(item)
			keys := make([]string, 0, len(item))
			for k := range item {
				keys = append(keys, k)
			}
			sort.Strings(test.keys)
			sort.Strings(keys)
			assert.Equal(test.keys, keys)
		})
	}
}
