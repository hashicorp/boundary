// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package authmethods_test

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	controllerauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/authmethods"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authmethods"
	"github.com/stretchr/testify/require"
)

// TestGrants_ReadActions tests read actions to assert that grants are being applied properly
func TestGrants_ReadActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

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
		return atRepo, nil
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

	// Need to create a wrapper for each scope (global, org1, org2) to test grants against OIDC/LDAP at that scope
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), globals.GlobalPrefix, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	databaseWrapperOrg1, err := kmsCache.GetWrapper(context.Background(), org1.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)
	databaseWrapperOrg2, err := kmsCache.GetWrapper(context.Background(), org2.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)

	// Create OIDC/LDAP/Password auth methods for each scope
	oidcGlobal := oidc.TestAuthMethod(t, conn, databaseWrapper, globals.GlobalPrefix, oidc.InactiveState, "client-id", "secret")
	oidcOrg1 := oidc.TestAuthMethod(t, conn, databaseWrapperOrg1, org1.GetPublicId(), oidc.InactiveState, "client-id", "secret")
	oidcOrg2 := oidc.TestAuthMethod(t, conn, databaseWrapperOrg2, org2.GetPublicId(), oidc.InactiveState, "client-id", "secret")

	ldapGlobal := ldap.TestAuthMethod(t, conn, databaseWrapper, globals.GlobalPrefix, []string{"ldaps://alice.com"})
	ldapOrg1 := ldap.TestAuthMethod(t, conn, databaseWrapperOrg1, org1.GetPublicId(), []string{"ldaps://alice.com"})
	ldapOrg2 := ldap.TestAuthMethod(t, conn, databaseWrapperOrg2, org2.GetPublicId(), []string{"ldaps://alice.com"})

	pwGlobal := password.TestAuthMethod(t, conn, globals.GlobalPrefix)
	pwOrg1 := password.TestAuthMethod(t, conn, org1.GetPublicId())
	pwOrg2 := password.TestAuthMethod(t, conn, org2.GetPublicId())

	// ignoreList consists of auth method IDs to omit from the result set
	// this is to handle auth methods that are created during the auth token
	// creation
	ignoreList := []string{}

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name     string
			input    *pbs.ListAuthMethodsRequest
			userFunc func() (*iam.User, auth.Account)
			wantErr  error
			wantIDs  []string
		}{
			{
				name:  "global role grant this only returns global auth methods",
				input: &pbs.ListAuthMethodsRequest{ScopeId: globals.GlobalPrefix},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantIDs: []string{
					oidcGlobal.PublicId,
					ldapGlobal.PublicId,
					pwGlobal.PublicId,
				},
			},
			{
				name: "global role grant this recursively returns all auth methods",
				input: &pbs.ListAuthMethodsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-method;actions=list,no-op"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
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
				name: "global role grant this and children returns global auth methods",
				input: &pbs.ListAuthMethodsRequest{
					ScopeId: globals.GlobalPrefix,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-method;actions=list,no-op"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantIDs: []string{
					oidcGlobal.PublicId,
					ldapGlobal.PublicId,
					pwGlobal.PublicId,
				},
			},
			{
				name: "global role grant this and children recursive returns all auth methods",
				input: &pbs.ListAuthMethodsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-method;actions=list,no-op"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
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
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{},
						GrantScopes: []string{},
					},
				}),
				wantErr: nil,
				// auth methods in `global` are filtered out because the user does not have grants to read
				// them in the global scope. Auth methods in org 1 and org 2 show up - my guess is because
				// the u_anon grants allow auth methods to be read on any org.
				wantIDs: []string{
					// oidcGlobal.PublicId,
					oidcOrg1.PublicId,
					oidcOrg2.PublicId,
					// ldapGlobal.PublicId,
					ldapOrg1.PublicId,
					ldapOrg2.PublicId,
					// pwGlobal.PublicId,
					pwOrg1.PublicId,
					pwOrg2.PublicId,
				},
			},
			{
				name: "org role grant this and children returns auth methods in org1",
				input: &pbs.ListAuthMethodsRequest{
					ScopeId: org1.PublicId,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=auth-method;actions=list,no-op"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantIDs: []string{
					oidcOrg1.PublicId,
					ldapOrg1.PublicId,
					pwOrg1.PublicId,
				},
			},
			{
				name: "org role grant this and children recursive returns auth methods in org1",
				input: &pbs.ListAuthMethodsRequest{
					ScopeId:   org1.PublicId,
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=auth-method;actions=list,no-op"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantIDs: []string{
					oidcOrg1.PublicId,
					ldapOrg1.PublicId,
					pwOrg1.PublicId,
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				// Call function to create direct/indirect relationship
				user, account := tc.userFunc()

				// Create auth token for the user
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)

				// Create auth context from the auth token
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

				// auth method created during token generation will not be taken into considerations during this test
				// adding to the ignoreList so it can be ignored later
				ignoreList = append(ignoreList, tok.GetAuthMethodId())

				got, finalErr := s.ListAuthMethods(fullGrantAuthCtx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, finalErr, tc.wantErr)
					return
				}
				require.NoError(t, finalErr)
				var gotIDs []string
				for _, g := range got.Items {
					// do not include IDs in the ignore list in the result sets
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
			name            string
			userFunc        func() (*iam.User, auth.Account)
			inputWantErrMap map[*pbs.GetAuthMethodRequest]error
		}{
			{
				name: "global role grant this returns global auth methods",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputWantErrMap: map[*pbs.GetAuthMethodRequest]error{
					{Id: pwGlobal.PublicId}:   nil,
					{Id: pwOrg1.PublicId}:     handlers.ForbiddenError(),
					{Id: pwOrg2.PublicId}:     handlers.ForbiddenError(),
					{Id: oidcGlobal.PublicId}: nil,
					{Id: oidcOrg1.PublicId}:   handlers.ForbiddenError(),
					{Id: oidcOrg2.PublicId}:   handlers.ForbiddenError(),
					{Id: ldapGlobal.PublicId}: nil,
					{Id: ldapOrg1.PublicId}:   handlers.ForbiddenError(),
					{Id: ldapOrg2.PublicId}:   handlers.ForbiddenError(),
				},
			},
			{
				name: "global role grant children returns org auth methods",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				inputWantErrMap: map[*pbs.GetAuthMethodRequest]error{
					{Id: pwGlobal.PublicId}:   handlers.ForbiddenError(),
					{Id: pwOrg1.PublicId}:     nil,
					{Id: pwOrg2.PublicId}:     nil,
					{Id: oidcGlobal.PublicId}: handlers.ForbiddenError(),
					{Id: oidcOrg1.PublicId}:   nil,
					{Id: oidcOrg2.PublicId}:   nil,
					{Id: ldapGlobal.PublicId}: handlers.ForbiddenError(),
					{Id: ldapOrg1.PublicId}:   nil,
					{Id: ldapOrg2.PublicId}:   nil,
				},
			},
			{
				name: "global role grant this and children with all permissions returns all auth methods",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				inputWantErrMap: map[*pbs.GetAuthMethodRequest]error{
					{Id: pwGlobal.PublicId}:   nil,
					{Id: pwOrg1.PublicId}:     nil,
					{Id: pwOrg2.PublicId}:     nil,
					{Id: oidcGlobal.PublicId}: nil,
					{Id: oidcOrg1.PublicId}:   nil,
					{Id: oidcOrg2.PublicId}:   nil,
					{Id: ldapGlobal.PublicId}: nil,
					{Id: ldapOrg1.PublicId}:   nil,
					{Id: ldapOrg2.PublicId}:   nil,
				},
			},
			{
				name: "org1 role grant this scope with all permissions",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.GetPublicId(),
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputWantErrMap: map[*pbs.GetAuthMethodRequest]error{
					{Id: pwGlobal.PublicId}:   handlers.ForbiddenError(),
					{Id: pwOrg1.PublicId}:     nil,
					{Id: pwOrg2.PublicId}:     handlers.ForbiddenError(),
					{Id: oidcGlobal.PublicId}: handlers.ForbiddenError(),
					{Id: oidcOrg1.PublicId}:   nil,
					{Id: oidcOrg2.PublicId}:   handlers.ForbiddenError(),
					{Id: ldapGlobal.PublicId}: handlers.ForbiddenError(),
					{Id: ldapOrg1.PublicId}:   nil,
					{Id: ldapOrg2.PublicId}:   handlers.ForbiddenError(),
				},
			},
			{
				name:     "no grants return all auth methods",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, nil),
				inputWantErrMap: map[*pbs.GetAuthMethodRequest]error{
					{Id: pwGlobal.PublicId}:   handlers.ForbiddenError(),
					{Id: pwOrg1.PublicId}:     handlers.ForbiddenError(),
					{Id: pwOrg2.PublicId}:     handlers.ForbiddenError(),
					{Id: oidcGlobal.PublicId}: handlers.ForbiddenError(),
					{Id: oidcOrg1.PublicId}:   handlers.ForbiddenError(),
					{Id: oidcOrg2.PublicId}:   handlers.ForbiddenError(),
					{Id: ldapGlobal.PublicId}: handlers.ForbiddenError(),
					{Id: ldapOrg1.PublicId}:   handlers.ForbiddenError(),
					{Id: ldapOrg2.PublicId}:   handlers.ForbiddenError(),
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				for input, wantErr := range tc.inputWantErrMap {
					_, err := s.GetAuthMethod(fullGrantAuthCtx, input)
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

// TestGrants_WriteActions tests write actions to assert that grants are being applied properly
func TestGrants_WriteActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

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
		return atRepo, nil
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

	t.Run("Create", func(t *testing.T) {
		testcases := []struct {
			name              string
			userFunc          func() (*iam.User, auth.Account)
			canCreateInScopes map[string]error
		}{
			{
				name: "direct grant all can create all",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				canCreateInScopes: map[string]error{
					globals.GlobalPrefix: nil,
					org1.PublicId:        nil,
					org2.PublicId:        nil,
				},
			},
			{
				name: "global role grant children can only create org auth methods",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-method;actions=create"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				canCreateInScopes: map[string]error{
					globals.GlobalPrefix: handlers.ForbiddenError(),
					org1.PublicId:        nil,
					org2.PublicId:        nil,
				},
			},
			{
				name: "org role can't create global auth methods nor auth methods in other orgs",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org2.PublicId,
						Grants:      []string{"ids=*;type=auth-method;actions=create"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canCreateInScopes: map[string]error{
					globals.GlobalPrefix: handlers.ForbiddenError(),
					org1.PublicId:        handlers.ForbiddenError(),
					org2.PublicId:        nil,
				},
			},
			{
				name: "incorrect grants returns 403 error",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-method;actions=list,read,update"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=auth-method;actions=list,read,update"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canCreateInScopes: map[string]error{
					globals.GlobalPrefix: handlers.ForbiddenError(),
					org1.PublicId:        handlers.ForbiddenError(),
					org2.PublicId:        handlers.ForbiddenError(),
				},
			},
			{
				name:     "no grants returns 403 error",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, nil),
				canCreateInScopes: map[string]error{
					globals.GlobalPrefix: handlers.ForbiddenError(),
					org1.PublicId:        handlers.ForbiddenError(),
					org2.PublicId:        handlers.ForbiddenError(),
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

				for scopeId, wantErr := range tc.canCreateInScopes {
					// Build a distinct name for each Auth Method
					name := fmt.Sprintf("[%s] ", tc.name)
					switch scopeId {
					case globals.GlobalPrefix:
						name += "global"
					case org1.PublicId:
						name += "org 1"
					case org2.PublicId:
						name += "org 2"
					default:
						t.Fatalf("Unexpected scope ID: %s", scopeId)
					}

					_, err := s.CreateAuthMethod(fullGrantAuthCtx, &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
						Name:        wrapperspb.String(name),
						Description: wrapperspb.String("test description"),
						ScopeId:     scopeId,
						Type:        "password",
					}})
					if wantErr != nil {
						require.ErrorIs(t, err, wantErr)
						continue
					}
					require.NoError(t, err)
				}
			})
		}
	})

	t.Run("Update", func(t *testing.T) {
		// Create global & org auth methods to test updates
		globalAmId := password.TestAuthMethod(t, conn, globals.GlobalPrefix).PublicId
		globalAm := &pb.AuthMethod{
			Name:        &wrapperspb.StringValue{Value: "new name"},
			Description: &wrapperspb.StringValue{Value: "new desc"},
			Version:     1,
		}

		org1AmId := password.TestAuthMethod(t, conn, org1.PublicId).PublicId
		org1Am := &pb.AuthMethod{
			Name:        &wrapperspb.StringValue{Value: "new name"},
			Description: &wrapperspb.StringValue{Value: "new desc"},
			Version:     1,
		}

		testcases := []struct {
			name          string
			input         *pbs.UpdateAuthMethodRequest
			rolesToCreate []authtoken.TestRoleGrantsForToken
			wantErr       error
		}{
			{
				name: "global role grant this and children can update global auth method",
				input: &pbs.UpdateAuthMethodRequest{
					Id: globalAmId,
					UpdateMask: &field_mask.FieldMask{
						Paths: []string{"name", "description"},
					},
					Item: globalAm,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=auth-method;actions=update"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
			},
			{
				name: "global role grant this and children & org role grant this can update org auth method",
				input: &pbs.UpdateAuthMethodRequest{
					Id: org1AmId,
					UpdateMask: &field_mask.FieldMask{
						Paths: []string{"name", "description"},
					},
					Item: org1Am,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=auth-method;actions=update"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
					{
						RoleScopeId:  org1.PublicId,
						GrantStrings: []string{"ids=*;type=auth-method;actions=update"},
						GrantScopes:  []string{globals.GrantScopeThis},
					},
				},
			},
			{
				name: "org role can't update global auth methods",
				input: &pbs.UpdateAuthMethodRequest{
					Id: globalAmId,
					UpdateMask: &field_mask.FieldMask{
						Paths: []string{"name", "description"},
					},
					Item: globalAm,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{{
					RoleScopeId:  org1.PublicId,
					GrantStrings: []string{"ids=*;type=auth-method;actions=update"},
					GrantScopes:  []string{globals.GrantScopeThis},
				}},
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "incorrect grants returns 403 error",
				input: &pbs.UpdateAuthMethodRequest{
					Id: org1AmId,
					UpdateMask: &field_mask.FieldMask{
						Paths: []string{"name", "description"},
					},
					Item: org1Am,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=auth-method;actions=list,read,create"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
					{
						RoleScopeId:  org1.PublicId,
						GrantStrings: []string{"ids=*;type=auth-method;actions=list,read,create"},
						GrantScopes:  []string{globals.GrantScopeThis},
					},
				},
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "no grants returns 403 error",
				input: &pbs.UpdateAuthMethodRequest{
					Id: globalAmId,
					UpdateMask: &field_mask.FieldMask{
						Paths: []string{"name", "description"},
					},
					Item: globalAm,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{},
				wantErr:       handlers.ForbiddenError(),
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				tok := authtoken.TestAuthTokenWithRoles(t, conn, kmsCache, globals.GlobalPrefix, tc.rolesToCreate)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				_, finalErr := s.UpdateAuthMethod(fullGrantAuthCtx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, finalErr, tc.wantErr)
					return
				}
				require.NoError(t, finalErr)
			})
		}
	})

	t.Run("Delete", func(t *testing.T) {
		allScopeIDs := []string{globals.GlobalPrefix, org1.PublicId, org2.PublicId}
		testcases := []struct {
			name                    string
			am                      *password.AuthMethod
			userFunc                func() (*iam.User, auth.Account)
			deleteAllowedAtScopeIDs []string
		}{
			{
				name: "grant all can delete all",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				deleteAllowedAtScopeIDs: allScopeIDs,
			},
			{
				name: "grant children can only delete in orgs",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				deleteAllowedAtScopeIDs: []string{org1.PublicId, org2.PublicId},
			},
			{
				name: "org role can't delete global auth methods",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=auth-method;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				deleteAllowedAtScopeIDs: []string{org1.PublicId},
			},
			{
				name: "incorrect grants returns 403 error",
				am:   password.TestAuthMethod(t, conn, org1.PublicId),
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-method;actions=list,read,create,update"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
			},
			{
				name:     "no grants returns 403 error",
				am:       password.TestAuthMethod(t, conn, globals.GlobalPrefix),
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, nil),
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				// setup a map to track which scope correlates to an auth method
				scopeIdAuthMethodMap := map[string]*password.AuthMethod{}
				for _, scopeId := range allScopeIDs {
					am := password.TestAuthMethod(t, conn, scopeId)
					scopeIdAuthMethodMap[scopeId] = am
				}
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				for scope, am := range scopeIdAuthMethodMap {
					_, err = s.DeleteAuthMethod(fullGrantAuthCtx, &pbs.DeleteAuthMethodRequest{Id: am.PublicId})
					if !slices.Contains(tc.deleteAllowedAtScopeIDs, scope) {
						require.ErrorIs(t, err, handlers.ForbiddenError())
						continue
					}
					require.NoErrorf(t, err, "failed to delete auth method in scope %s", scope)
				}
			})
		}
	})

	t.Run("Authenticate", func(t *testing.T) {
		pwRepo, err := pwRepoFn()
		require.NoError(t, err)

		// We need a sys eventer in order to authenticate
		eventConfig := event.TestEventerConfig(t, "TestGrants_WriteActions", event.TestWithObservationSink(t))
		testLock := &sync.Mutex{}
		testLogger := hclog.New(&hclog.LoggerOptions{
			Mutex: testLock,
			Name:  "test",
		})

		require.NoError(t, event.InitSysEventer(testLogger, testLock, "TestGrants_WriteActions", event.WithEventerConfig(&eventConfig.EventerConfig)))
		sinkFileName := eventConfig.ObservationEvents.Name()
		t.Cleanup(func() {
			require.NoError(t, os.Remove(sinkFileName))
			event.TestResetSystEventer(t)
		})

		testcases := []struct {
			name          string
			scopeId       string
			input         *pbs.AuthenticateRequest
			rolesToCreate []authtoken.TestRoleGrantsForToken
			wantErr       error
		}{
			{
				name:    "global role grant this and children can authenticate against a global auth method",
				scopeId: globals.GlobalPrefix,
				input: &pbs.AuthenticateRequest{
					TokenType: "token",
					Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
						PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
							LoginName: testLoginName,
							Password:  testPassword,
						},
					},
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=auth-method;actions=authenticate"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
			},
			{
				name:    "org role can't authenticate against a global auth method",
				scopeId: globals.GlobalPrefix,
				input: &pbs.AuthenticateRequest{
					TokenType: "token",
					Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
						PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
							LoginName: testLoginName,
							Password:  testPassword,
						},
					},
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{{
					RoleScopeId:  org1.PublicId,
					GrantStrings: []string{"ids=*;type=auth-method;actions=authenticate"},
					GrantScopes:  []string{globals.GrantScopeThis},
				}},
				wantErr: handlers.ForbiddenError(),
			},
			{
				name:    "no grants returns 403 error for a global auth method",
				scopeId: globals.GlobalPrefix,
				input: &pbs.AuthenticateRequest{
					TokenType: "token",
					Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
						PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
							LoginName: testLoginName,
							Password:  testPassword,
						},
					},
				},
				wantErr: handlers.ForbiddenError(),
			},
			{
				name:    "org scopes grant anyone permission to authenticate (and list) auth methods by default",
				scopeId: org1.PublicId,
				input: &pbs.AuthenticateRequest{
					TokenType: "token",
					Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
						PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
							LoginName: testLoginName,
							Password:  testPassword,
						},
					},
				},
			},
			{
				name:    "granting authenticate again at the org scope allows authentication",
				scopeId: org1.PublicId,
				input: &pbs.AuthenticateRequest{
					TokenType: "token",
					Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
						PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
							LoginName: testLoginName,
							Password:  testPassword,
						},
					},
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{{
					RoleScopeId:  org1.PublicId,
					GrantStrings: []string{"ids=*;type=auth-method;actions=authenticate"},
					GrantScopes:  []string{globals.GrantScopeThis},
				}},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				// Create auth method
				if tc.scopeId == globals.GlobalPrefix {
					tc.input.AuthMethodId = password.TestAuthMethod(t, conn, globals.GlobalPrefix).PublicId
				} else {
					tc.input.AuthMethodId = password.TestAuthMethod(t, conn, org1.PublicId).PublicId
				}

				// Create account for the auth method
				account, err := password.NewAccount(ctx, tc.input.AuthMethodId, password.WithLoginName(testLoginName))
				require.NoError(t, err)
				account, err = pwRepo.CreateAccount(context.Background(), tc.scopeId, account, password.WithPassword(testPassword))
				require.NoError(t, err)
				require.NotNil(t, account)

				// Create user linked to the account
				user := iam.TestUser(t, iamRepo, tc.scopeId, iam.WithAccountIds(account.PublicId))

				// Create the desired role/grants for the user
				for _, roleToCreate := range tc.rolesToCreate {
					role := iam.TestRoleWithGrants(t, conn, roleToCreate.RoleScopeId, roleToCreate.GrantScopes, roleToCreate.GrantStrings)
					iam.TestUserRole(t, conn, role.PublicId, user.PublicId)
				}

				// Create auth token for the user
				tok, err := atRepo.CreateAuthToken(ctx, user, account.PublicId)
				require.NoError(t, err)
				ctx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

				_, err = s.Authenticate(ctx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, err, tc.wantErr)
					return
				}
				require.NoError(t, err)
			})
		}
	})
}
