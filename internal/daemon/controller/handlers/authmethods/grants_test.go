package authmethods_test

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	controllerauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"

	"testing"

	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/authmethods"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/require"
)

// TestGrants_ReadActions tests read actions to assert that grants are being applied properly
func TestGrants_ReadActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kmsCache)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kmsCache)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kmsCache)
	}
	authMethodRepoFn := func() (*auth.AuthMethodRepository, error) {
		return auth.NewAuthMethodRepository(ctx, rw, rw, kmsCache)
	}

	s, err := authmethods.NewService(ctx,
		kmsCache,
		pwRepoFn,
		oidcRepoFn,
		iamRepoFn,
		atRepoFn,
		ldapRepoFn,
		authMethodRepoFn,
		1000)
	require.NoError(t, err)
	org1, _ := iam.TestScopes(t, iamRepo)
	org2, _ := iam.TestScopes(t, iamRepo)

	pwGlobal := password.TestAuthMethod(t, conn, globals.GlobalPrefix)
	pwOrg1 := password.TestAuthMethod(t, conn, org1.GetPublicId())
	pwOrg2 := password.TestAuthMethod(t, conn, org2.GetPublicId())

	t.Run("Get", func(t *testing.T) {
		testcases := []struct {
			name             string
			input            *pbs.ListAuthMethodsRequest
			amIDExpectErrMap map[string]error
			rolesToCreate    []authtoken.TestRoleGrantsForToken
		}{
			{
				name: "global role grant this and children returns all auth methods",
				amIDExpectErrMap: map[string]error{
					pwGlobal.GetPublicId(): nil,
					pwOrg1.GetPublicId():   nil,
					pwOrg2.GetPublicId():   nil,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeID:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=auth-method;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
			},
			{
				name: "org role grant this and children returns auth methods in org1",
				input: &pbs.ListAuthMethodsRequest{
					ScopeId:   org1.PublicId,
					Recursive: true,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeID:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=auth-method;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeChildren},
					},
				},
				amIDExpectErrMap: map[string]error{
					pwGlobal.GetPublicId(): handlers.ForbiddenError(),
					pwOrg1.GetPublicId():   nil,
					pwOrg2.GetPublicId():   nil,
				},
			},
			{
				name: "no grants return all auth methods",
				input: &pbs.ListAuthMethodsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
					PageSize:  500,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{},
				amIDExpectErrMap: map[string]error{
					pwGlobal.GetPublicId(): handlers.ForbiddenError(),
					pwOrg1.GetPublicId():   handlers.ForbiddenError(),
					pwOrg2.GetPublicId():   handlers.ForbiddenError(),
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				tok := authtoken.TestAuthTokenWithRoles(t, conn, kmsCache, globals.GlobalPrefix, tc.rolesToCreate)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				for amId, wantErr := range tc.amIDExpectErrMap {
					_, err := s.GetAuthMethod(fullGrantAuthCtx, &pbs.GetAuthMethodRequest{
						Id: amId,
					})
					if wantErr != nil {
						require.ErrorIs(t, err, wantErr)
						continue
					}
					require.NoError(t, err)
				}
			})
		}
	})
}
