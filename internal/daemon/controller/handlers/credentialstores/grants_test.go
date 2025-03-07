// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credentialstores_test

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/hashicorp/boundary/globals"
	authdomain "github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/credentialstores"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/stretchr/testify/require"
)

// TestGrants_ListCredentialStores tests read actions to assert that grants are being applied properly
// non-recursive list is not allowed at global/org so those will not be tested
func TestGrants_ListCredentialStores(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	vaultRepoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(ctx, rw, rw, kmsCache, scheduler.TestScheduler(t, conn, wrap))
	}
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kmsCache)
	}
	credStoreRepoFn := func() (*credential.StoreRepository, error) {
		return credential.NewStoreRepository(context.Background(), rw, rw)
	}
	s, err := credentialstores.NewService(ctx, iamRepoFn, vaultRepoFn, staticRepoFn, credStoreRepoFn, 1000)
	require.NoError(t, err)

	org1, proj1 := iam.TestScopes(t, iamRepo)
	org2, proj2 := iam.TestScopes(t, iamRepo)
	proj3 := iam.TestProject(t, iamRepo, org2.GetPublicId())

	var proj1Stores []string
	for _, s := range vault.TestCredentialStores(t, conn, wrap, proj1.GetPublicId(), 1) {
		proj1Stores = append(proj1Stores, s.GetPublicId())
	}
	for _, s := range static.TestCredentialStores(t, conn, wrap, proj1.GetPublicId(), 1) {
		proj1Stores = append(proj1Stores, s.GetPublicId())
	}

	var proj2Stores []string
	for _, s := range vault.TestCredentialStores(t, conn, wrap, proj2.GetPublicId(), 2) {
		proj2Stores = append(proj2Stores, s.GetPublicId())
	}
	for _, s := range static.TestCredentialStores(t, conn, wrap, proj2.GetPublicId(), 2) {
		proj2Stores = append(proj2Stores, s.GetPublicId())
	}

	var proj3Stores []string
	for _, s := range vault.TestCredentialStores(t, conn, wrap, proj3.GetPublicId(), 2) {
		proj3Stores = append(proj3Stores, s.GetPublicId())
	}
	for _, s := range static.TestCredentialStores(t, conn, wrap, proj3.GetPublicId(), 2) {
		proj3Stores = append(proj3Stores, s.GetPublicId())
	}

	testcases := []struct {
		name     string
		input    *pbs.ListCredentialStoresRequest
		userFunc func() (*iam.User, authdomain.Account)
		wantErr  error
		wantIDs  []string
	}{
		{
			name: "global role grant this returns all created credential stores",
			input: &pbs.ListCredentialStoresRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=credential-store;actions=list,read"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
			}),
			wantErr: nil,
			wantIDs: slices.Concat(proj1Stores, proj2Stores, proj3Stores),
		},
		{
			name: "global role grant recursive list without access returns empty list",
			input: &pbs.ListCredentialStoresRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=credential-store;actions=list,read"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: nil,
			wantIDs: []string{},
		},
		{
			name: "org role grant this and children recursive-list returns all created credential stores",
			input: &pbs.ListCredentialStoresRequest{
				ScopeId:   org1.GetPublicId(),
				Recursive: true,
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org1.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=list,read"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			wantErr: nil,
			wantIDs: proj1Stores,
		},
		{
			name: "org role children grants list org return all credential stores in child projects",
			input: &pbs.ListCredentialStoresRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org2.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=list,read"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			wantErr: nil,
			wantIDs: slices.Concat(proj2Stores, proj3Stores),
		},
		{
			name: "org role grant this list a different org returns error",
			input: &pbs.ListCredentialStoresRequest{
				ScopeId:   org1.GetPublicId(),
				Recursive: true,
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org2.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=list,read"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			wantErr: handlers.ForbiddenError(),
			wantIDs: nil,
		},
		{
			name: "project role grant this returns all created credential stores",
			input: &pbs.ListCredentialStoresRequest{
				ScopeId: proj1.GetPublicId(),
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj1.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=list,read"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: nil,
			wantIDs: proj1Stores,
		},
		{
			name: "project role grant this without list actions return error",
			input: &pbs.ListCredentialStoresRequest{
				ScopeId: proj1.GetPublicId(),
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj1.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=read"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: handlers.ForbiddenError(),
			wantIDs: proj1Stores,
		},
		{
			name: "project role grant this without list actions return error",
			input: &pbs.ListCredentialStoresRequest{
				ScopeId: proj1.GetPublicId(),
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj1.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=read"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: handlers.ForbiddenError(),
			wantIDs: proj1Stores,
		},
		{
			name: "grants specific project ID recursive list from global returns only granted project",
			input: &pbs.ListCredentialStoresRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj1.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=list,no-op"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: nil,
			wantIDs: proj1Stores,
		},
		{
			name: "multiple grants specific project ID recursive list from global returns only granted project",
			input: &pbs.ListCredentialStoresRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=credential-store;actions=list"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: proj1.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=list,no-op"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: proj2.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=list,no-op"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: nil,
			wantIDs: slices.Concat(proj1Stores, proj2Stores),
		},
		{
			name: "multiple grants specific credentials-library no-op returns only granted credentials-library",
			input: &pbs.ListCredentialStoresRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=credential-store;actions=list"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
				},
				{
					RoleScopeId: proj1.PublicId,
					Grants: []string{
						fmt.Sprintf("ids=%s;type=credential-store;actions=no-op", proj1Stores[0]),
					},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: org2.PublicId,
					Grants: []string{
						fmt.Sprintf("ids=%s;type=credential-store;actions=no-op", proj2Stores[0]),
						fmt.Sprintf("ids=%s;type=credential-store;actions=no-op", proj3Stores[0]),
					},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			wantErr: nil,
			wantIDs: []string{proj1Stores[0], proj2Stores[0], proj3Stores[0]},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			got, err := s.ListCredentialStores(fullGrantAuthCtx, tc.input)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			var gotIDs []string
			for _, g := range got.Items {
				gotIDs = append(gotIDs, g.GetId())
			}
			require.ElementsMatch(t, tc.wantIDs, gotIDs)
		})
	}

}
