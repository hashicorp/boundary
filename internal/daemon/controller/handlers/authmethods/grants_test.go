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
	"slices"

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
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), globals.GlobalPrefix, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	oidcGlobal := oidc.TestAuthMethod(t, conn, databaseWrapper, globals.GlobalPrefix, oidc.InactiveState, "client-id", "secret")
	oidcOrg1 := oidc.TestAuthMethod(t, conn, databaseWrapper, org1.GetPublicId(), oidc.InactiveState, "client-id", "secret")
	oidcOrg2 := oidc.TestAuthMethod(t, conn, databaseWrapper, org2.GetPublicId(), oidc.InactiveState, "client-id", "secret")

	ldapGlobal := ldap.TestAuthMethod(t, conn, wrap, globals.GlobalPrefix, []string{"ldaps://alice.com"})
	ldapOrg1 := ldap.TestAuthMethod(t, conn, wrap, org1.GetPublicId(), []string{"ldaps://alice.com"})
	ldapOrg2 := ldap.TestAuthMethod(t, conn, wrap, org2.GetPublicId(), []string{"ldaps://alice.com"})

	pwGlobal := password.TestAuthMethod(t, conn, globals.GlobalPrefix)
	pwOrg1 := password.TestAuthMethod(t, conn, org1.GetPublicId())
	pwOrg2 := password.TestAuthMethod(t, conn, org2.GetPublicId())

	// ignoreList consists of auth method IDs to omit from the result set
	// this is to handle auth methods that are created during the auth token
	// creation
	ignoreList := []string{}

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name                     string
			input                    *pbs.ListAuthMethodsRequest
			includeGlobalAuthMethods bool
			rolesToCreate            []authtoken.TestRoleGrantsForToken
			wantErr                  error
			wantIDs                  []string
		}{
			{
				name: "global role grant this and children returns all auth methods",
				input: &pbs.ListAuthMethodsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeID:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=auth-method;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
				wantErr: nil,
				wantIDs: []string{
					oidcGlobal.PublicId,
					oidcOrg1.PublicId,
					oidcOrg2.PublicId,
					ldapGlobal.PublicId,
					ldapOrg1.PublicId,
					ldapOrg2.PublicId,
					pwGlobal.PublicId,
					pwOrg1.PublicId,
					pwOrg2.PublicId,
				},
			},
			{
				name: "no grants return children org",
				input: &pbs.ListAuthMethodsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{},
				wantErr:       nil,
				// auth methods in `global` are filtered out because the user does not have grants to read
				// them in the global scope. Auth methods in org 1 and org 2 show up - my guess is because
				// the u_anon grants allow auth methods to be read on any org.
				wantIDs: []string{
					//oidcGlobal.PublicId,
					oidcOrg1.PublicId,
					oidcOrg2.PublicId,
					//ldapGlobal.PublicId,
					ldapOrg1.PublicId,
					ldapOrg2.PublicId,
					//pwGlobal.PublicId,
					pwOrg1.PublicId,
					pwOrg2.PublicId,
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
						RoleScopeID:  org1.PublicId,
						GrantStrings: []string{"ids=*;type=auth-method;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
				wantErr: nil,
				wantIDs: []string{oidcOrg1.PublicId, ldapOrg1.PublicId, pwOrg1.PublicId},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				tok := authtoken.TestAuthTokenWithRoles(t, conn, kmsCache, globals.GlobalPrefix, tc.rolesToCreate)
				// auth method created during token generation will not be taken into considerations during this test
				// adding to the ignoreList so it can be ignored later
				ignoreList = append(ignoreList, tok.GetAuthMethodId())
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, finalErr := s.ListAuthMethods(fullGrantAuthCtx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, finalErr, tc.wantErr)
					return
				}
				// authtoken.TestAuthTokenWithRoles creates an auth method at `global` scope so
				// include AuthMethodID of the user used to generate AuthToken in the "wantIDs" set
				// when listing auth methods at global scope
				require.NoError(t, finalErr)
				var gotIDs []string
				for _, g := range got.Items {
					// do not include IDs in the ignore list in the
					// result sets
					if slices.Contains(ignoreList, g.Id) {
						continue
					}
					gotIDs = append(gotIDs, g.GetId())
				}
				require.ElementsMatch(t, tc.wantIDs, gotIDs)
			})
		}
	})

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
