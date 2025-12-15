// Copyright IBM Corp. 2020, 2025
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
	"github.com/hashicorp/boundary/internal/types/resource"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentialstores"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// TestGrants_ListCredentialStores tests read actions to assert that grants are being applied properly
// non-recursive list is not allowed at global/org so non-recursive lists at global/org will not be covered
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
		name                                 string
		input                                *pbs.ListCredentialStoresRequest
		userFunc                             func() (*iam.User, authdomain.Account)
		wantErr                              error
		wantIDs                              []string
		wantIdAuthorizedActionsMap           map[string][]string
		wantIdAuthorizedCollectionActionsMap map[string][]string
	}{
		{
			name: "global role grant this returns all created credential stores",
			input: &pbs.ListCredentialStoresRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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

	t.Run("authorized actions", func(t *testing.T) {
		user, account := iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
			{
				RoleScopeId: globals.GlobalPrefix,
				Grants:      []string{"ids=*;type=*;actions=*"},
				GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
			},
		})()
		tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
		require.NoError(t, err)
		fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
		got, err := s.ListCredentialStores(fullGrantAuthCtx, &pbs.ListCredentialStoresRequest{
			ScopeId:   globals.GlobalPrefix,
			Recursive: true,
		})
		require.NoError(t, err)
		require.Len(t, got.Items, len(slices.Concat(proj1Stores, proj2Stores, proj3Stores)))
		for _, item := range got.Items {
			switch item.Type {
			case "vault":
				require.ElementsMatch(t, item.AuthorizedActions, []string{"no-op", "read", "update", "delete"})
				require.Len(t, item.AuthorizedCollectionActions, 1)
				require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.CredentialLibrary.PluralString()].AsSlice(), []string{"list", "create"})
			case "static":
				require.ElementsMatch(t, item.AuthorizedActions, []string{"no-op", "read", "update", "delete"})
				require.Len(t, item.AuthorizedCollectionActions, 1)
				require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Credential.PluralString()].AsSlice(), []string{"list", "create"})
			default:
				t.Fatalf("unknown item type: %s", item.Type)
			}
		}
	})
}

func TestGrants_GetCredentialStores(t *testing.T) {
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

	_, proj1 := iam.TestScopes(t, iamRepo)
	org2, proj2 := iam.TestScopes(t, iamRepo)
	proj3 := iam.TestProject(t, iamRepo, org2.GetPublicId())

	proj1VaultStore := vault.TestCredentialStores(t, conn, wrap, proj1.GetPublicId(), 1)[0]
	proj2StaticStore := static.TestCredentialStores(t, conn, wrap, proj2.GetPublicId(), 1)[0]
	proj3VaultStore := vault.TestCredentialStores(t, conn, wrap, proj3.GetPublicId(), 1)[0]

	testcases := []struct {
		name          string
		userFunc      func() (*iam.User, authdomain.Account)
		inputErrorMap map[*pbs.GetCredentialStoreRequest]error
	}{
		{
			name: "global role grant descendant can read all created credential stores",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=credential-store;actions=read"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
			}),
			inputErrorMap: map[*pbs.GetCredentialStoreRequest]error{
				{Id: proj1VaultStore.GetPublicId()}:  nil,
				{Id: proj2StaticStore.GetPublicId()}: nil,
				{Id: proj3VaultStore.GetPublicId()}:  nil,
			},
		},
		{
			name: "global role grant this and children cannot get any credential stores",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=credential-store;actions=read"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			inputErrorMap: map[*pbs.GetCredentialStoreRequest]error{
				{Id: proj1VaultStore.GetPublicId()}:  handlers.ForbiddenError(),
				{Id: proj2StaticStore.GetPublicId()}: handlers.ForbiddenError(),
				{Id: proj3VaultStore.GetPublicId()}:  handlers.ForbiddenError(),
			},
		},
		{
			name: "org role grant children can read all credential stores under granted org",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org2.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=read"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			inputErrorMap: map[*pbs.GetCredentialStoreRequest]error{
				{Id: proj1VaultStore.GetPublicId()}:  handlers.ForbiddenError(),
				{Id: proj2StaticStore.GetPublicId()}: nil,
				{Id: proj3VaultStore.GetPublicId()}:  nil,
			},
		},
		{
			name: "project role can only read credential stores in this project",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj1.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=read"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputErrorMap: map[*pbs.GetCredentialStoreRequest]error{
				{Id: proj1VaultStore.GetPublicId()}:  nil,
				{Id: proj2StaticStore.GetPublicId()}: handlers.ForbiddenError(),
				{Id: proj3VaultStore.GetPublicId()}:  handlers.ForbiddenError(),
			},
		},
		{
			name: "composite grants individually grant each project roles can read all credential stores",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj1.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=read"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: proj2.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=read"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: proj3.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=read"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputErrorMap: map[*pbs.GetCredentialStoreRequest]error{
				{Id: proj1VaultStore.GetPublicId()}:  nil,
				{Id: proj2StaticStore.GetPublicId()}: nil,
				{Id: proj3VaultStore.GetPublicId()}:  nil,
			},
		},
		{
			name: "global grants individual resources can only read resources that are granted access",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{fmt.Sprintf("ids=%s,%s;type=credential-store;actions=read", proj1VaultStore.GetPublicId(), proj3VaultStore.GetPublicId())},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
			}),
			inputErrorMap: map[*pbs.GetCredentialStoreRequest]error{
				{Id: proj1VaultStore.GetPublicId()}:  nil,
				{Id: proj2StaticStore.GetPublicId()}: handlers.ForbiddenError(),
				{Id: proj3VaultStore.GetPublicId()}:  nil,
			},
		},
		{
			name: "global grants not granting read permission cannot read credentials store",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=credential-store;actions=list,create,delete"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
				{
					RoleScopeId: proj2.GetPublicId(),
					Grants:      []string{"ids=*;type=credential-store;actions=read"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputErrorMap: map[*pbs.GetCredentialStoreRequest]error{
				{Id: proj1VaultStore.GetPublicId()}:  handlers.ForbiddenError(),
				{Id: proj2StaticStore.GetPublicId()}: nil,
				{Id: proj3VaultStore.GetPublicId()}:  handlers.ForbiddenError(),
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			for input, wantErr := range tc.inputErrorMap {
				_, err = s.GetCredentialStore(fullGrantAuthCtx, input)
				if wantErr != nil {
					require.ErrorIs(t, err, wantErr)
					continue
				}
				require.NoError(t, err)
			}
		})
	}
}

func TestGrants_CreateCredentialStores(t *testing.T) {
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

	_, proj1 := iam.TestScopes(t, iamRepo)
	org2, proj2 := iam.TestScopes(t, iamRepo)
	proj3 := iam.TestProject(t, iamRepo, org2.GetPublicId())
	v := vault.NewTestVaultServer(t, vault.WithTestVaultTLS(vault.TestClientTLS))

	staticCredStoreInput := func(scopeID string) *pbs.CreateCredentialStoreRequest {
		return &pbs.CreateCredentialStoreRequest{
			Item: &pb.CredentialStore{
				ScopeId: scopeID,
				Type:    static.Subtype.String(),
			},
		}
	}
	vaultCredStoreInput := func(scopeID string) *pbs.CreateCredentialStoreRequest {
		_, token := v.CreateToken(t)
		return &pbs.CreateCredentialStoreRequest{
			Item: &pb.CredentialStore{
				ScopeId: scopeID,
				Type:    vault.Subtype.String(),
				Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
					VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
						Address:           wrapperspb.String(v.Addr),
						Token:             wrapperspb.String(token),
						CaCert:            wrapperspb.String(string(v.CaCert)),
						ClientCertificate: wrapperspb.String(string(v.ClientCert) + string(v.ClientKey)),
					},
				},
			},
		}
	}

	testcases := []struct {
		name          string
		userFunc      func() (*iam.User, authdomain.Account)
		inputErrorMap map[*pbs.CreateCredentialStoreRequest]error
	}{
		{
			name: "global role grant descendant can list all created credential stores",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=credential-store;actions=create"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
			}),
			inputErrorMap: map[*pbs.CreateCredentialStoreRequest]error{
				staticCredStoreInput(proj1.PublicId): nil,
				staticCredStoreInput(proj2.PublicId): nil,
				staticCredStoreInput(proj3.PublicId): nil,
			},
		},
		{
			name: "global role grant this and children cannot create credential store in any project",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=credential-store;actions=create"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			inputErrorMap: map[*pbs.CreateCredentialStoreRequest]error{
				staticCredStoreInput(proj1.PublicId): handlers.ForbiddenError(),
				staticCredStoreInput(proj2.PublicId): handlers.ForbiddenError(),
				staticCredStoreInput(proj3.PublicId): handlers.ForbiddenError(),
			},
		},
		{
			name: "org role grant children can create credential stores under granted org",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org2.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=create"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			inputErrorMap: map[*pbs.CreateCredentialStoreRequest]error{
				vaultCredStoreInput(proj1.PublicId): handlers.ForbiddenError(),
				vaultCredStoreInput(proj2.PublicId): nil,
				vaultCredStoreInput(proj3.PublicId): nil,
			},
		},
		{
			name: "project role can only read credential stores in this project",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj1.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=create"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputErrorMap: map[*pbs.CreateCredentialStoreRequest]error{
				vaultCredStoreInput(proj1.PublicId): nil,
				vaultCredStoreInput(proj2.PublicId): handlers.ForbiddenError(),
				vaultCredStoreInput(proj3.PublicId): handlers.ForbiddenError(),
			},
		},
		{
			name: "composite grants individually grant each project roles can create in granted project",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj1.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=create"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: proj2.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=create"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: proj3.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=create"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputErrorMap: map[*pbs.CreateCredentialStoreRequest]error{
				vaultCredStoreInput(proj1.PublicId): nil,
				vaultCredStoreInput(proj2.PublicId): nil,
				vaultCredStoreInput(proj3.PublicId): nil,
			},
		},
		{
			name: "global grants not granting create permission cannot create credentials store",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=credential-store;actions=delete"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
				{
					RoleScopeId: proj2.GetPublicId(),
					Grants:      []string{"ids=*;type=credential-store;actions=create"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputErrorMap: map[*pbs.CreateCredentialStoreRequest]error{
				vaultCredStoreInput(proj1.PublicId): handlers.ForbiddenError(),
				vaultCredStoreInput(proj2.PublicId): nil,
				vaultCredStoreInput(proj3.PublicId): handlers.ForbiddenError(),
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			for input, wantErr := range tc.inputErrorMap {
				_, err = s.CreateCredentialStore(fullGrantAuthCtx, input)
				if wantErr != nil {
					require.ErrorIs(t, err, wantErr)
					continue
				}
				require.NoError(t, err)
			}
		})
	}
}

func TestGrants_DeleteCredentialStores(t *testing.T) {
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

	_, proj1 := iam.TestScopes(t, iamRepo)
	org2, proj2 := iam.TestScopes(t, iamRepo)
	proj3 := iam.TestProject(t, iamRepo, org2.GetPublicId())

	staticCredStoreInput := func(scopeID string) *pbs.DeleteCredentialStoreRequest {
		store := static.TestCredentialStores(t, conn, wrap, scopeID, 1)[0]
		return &pbs.DeleteCredentialStoreRequest{
			Id: store.PublicId,
		}
	}
	vaultCredStoreInput := func(scopeID string) *pbs.DeleteCredentialStoreRequest {
		id, _ := uuid.GenerateUUID()
		store := vault.TestCredentialStore(t, conn, wrap, scopeID, fmt.Sprintf("http://vault%s", id), id, fmt.Sprintf("accessor-%s", id))
		return &pbs.DeleteCredentialStoreRequest{
			Id: store.PublicId,
		}
	}

	testcases := []struct {
		name          string
		userFunc      func() (*iam.User, authdomain.Account)
		inputErrorMap map[*pbs.DeleteCredentialStoreRequest]error
	}{
		{
			name: "global role grant descendant can delete credential stores everywhere",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=credential-store;actions=delete"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
			}),
			inputErrorMap: map[*pbs.DeleteCredentialStoreRequest]error{
				staticCredStoreInput(proj1.PublicId): nil,
				staticCredStoreInput(proj2.PublicId): nil,
				staticCredStoreInput(proj3.PublicId): nil,
			},
		},
		{
			name: "global role grant this and children cannot delete credential store in any project",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=credential-store;actions=delete"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			inputErrorMap: map[*pbs.DeleteCredentialStoreRequest]error{
				staticCredStoreInput(proj1.PublicId): handlers.ForbiddenError(),
				staticCredStoreInput(proj2.PublicId): handlers.ForbiddenError(),
				staticCredStoreInput(proj3.PublicId): handlers.ForbiddenError(),
			},
		},
		{
			name: "org role grant children can delete credential stores under granted org",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org2.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=delete"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			inputErrorMap: map[*pbs.DeleteCredentialStoreRequest]error{
				vaultCredStoreInput(proj1.PublicId): handlers.ForbiddenError(),
				vaultCredStoreInput(proj2.PublicId): nil,
				vaultCredStoreInput(proj3.PublicId): nil,
			},
		},
		{
			name: "project role can only delete credential stores in this project",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj1.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=delete"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputErrorMap: map[*pbs.DeleteCredentialStoreRequest]error{
				vaultCredStoreInput(proj1.PublicId): nil,
				vaultCredStoreInput(proj2.PublicId): handlers.ForbiddenError(),
				vaultCredStoreInput(proj3.PublicId): handlers.ForbiddenError(),
			},
		},
		{
			name: "composite grants individually grant each project roles can delete in granted project",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj1.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=delete"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: proj2.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=delete"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: proj3.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=delete"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputErrorMap: map[*pbs.DeleteCredentialStoreRequest]error{
				vaultCredStoreInput(proj1.PublicId): nil,
				vaultCredStoreInput(proj2.PublicId): nil,
				vaultCredStoreInput(proj3.PublicId): nil,
			},
		},
		{
			name: "global grants not granting create permission cannot delete credentials store",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=credential-store;actions=list"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
				{
					RoleScopeId: proj2.GetPublicId(),
					Grants:      []string{"ids=*;type=credential-store;actions=delete"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputErrorMap: map[*pbs.DeleteCredentialStoreRequest]error{
				vaultCredStoreInput(proj1.PublicId): handlers.ForbiddenError(),
				vaultCredStoreInput(proj2.PublicId): nil,
				vaultCredStoreInput(proj3.PublicId): handlers.ForbiddenError(),
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			for input, wantErr := range tc.inputErrorMap {
				_, err = s.DeleteCredentialStore(fullGrantAuthCtx, input)
				if wantErr != nil {
					require.ErrorIs(t, err, wantErr)
					continue
				}
				require.NoError(t, err)
			}
		})
	}
}

func TestGrants_UpdateCredentialStores(t *testing.T) {
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

	_, proj1 := iam.TestScopes(t, iamRepo)
	org2, proj2 := iam.TestScopes(t, iamRepo)
	proj3 := iam.TestProject(t, iamRepo, org2.GetPublicId())

	staticCredStoreInput := func(scopeID string) *pbs.UpdateCredentialStoreRequest {
		old, _ := uuid.GenerateUUID()
		newId, _ := uuid.GenerateUUID()
		store := static.TestCredentialStore(t, conn, wrap, scopeID, static.WithName(old), static.WithDescription(old))
		return &pbs.UpdateCredentialStoreRequest{
			Id: store.PublicId,
			Item: &pb.CredentialStore{
				Name:        &wrapperspb.StringValue{Value: newId},
				Description: &wrapperspb.StringValue{Value: newId},
				Version:     store.Version,
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"name", "description"},
			},
		}
	}
	vaultCredStoreInput := func(scopeID string) *pbs.UpdateCredentialStoreRequest {
		id, _ := uuid.GenerateUUID()
		newId, _ := uuid.GenerateUUID()
		store := vault.TestCredentialStore(t, conn, wrap, scopeID, fmt.Sprintf("http://vault%s", id), id, fmt.Sprintf("accessor-%s", id))
		return &pbs.UpdateCredentialStoreRequest{
			Id: store.PublicId,
			Item: &pb.CredentialStore{
				Name:        &wrapperspb.StringValue{Value: newId},
				Description: &wrapperspb.StringValue{Value: newId},
				Version:     store.Version,
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"name", "description"},
			},
		}
	}

	testcases := []struct {
		name          string
		userFunc      func() (*iam.User, authdomain.Account)
		inputErrorMap map[*pbs.UpdateCredentialStoreRequest]error
	}{
		{
			name: "global role grant descendant can update credential stores everywhere",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=credential-store;actions=update"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
			}),
			inputErrorMap: map[*pbs.UpdateCredentialStoreRequest]error{
				staticCredStoreInput(proj1.PublicId): nil,
				staticCredStoreInput(proj2.PublicId): nil,
				staticCredStoreInput(proj3.PublicId): nil,
			},
		},
		{
			name: "global role grant this and children cannot update credential store in any project",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=credential-store;actions=update"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			inputErrorMap: map[*pbs.UpdateCredentialStoreRequest]error{
				staticCredStoreInput(proj1.PublicId): handlers.ForbiddenError(),
				staticCredStoreInput(proj2.PublicId): handlers.ForbiddenError(),
				staticCredStoreInput(proj3.PublicId): handlers.ForbiddenError(),
			},
		},
		{
			name: "org role grant children can update credential stores under granted org",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org2.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=update"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			inputErrorMap: map[*pbs.UpdateCredentialStoreRequest]error{
				vaultCredStoreInput(proj1.PublicId): handlers.ForbiddenError(),
				vaultCredStoreInput(proj2.PublicId): nil,
				vaultCredStoreInput(proj3.PublicId): nil,
			},
		},
		{
			name: "project role can only update credential stores in this project",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj1.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=update"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputErrorMap: map[*pbs.UpdateCredentialStoreRequest]error{
				vaultCredStoreInput(proj1.PublicId): nil,
				vaultCredStoreInput(proj2.PublicId): handlers.ForbiddenError(),
				vaultCredStoreInput(proj3.PublicId): handlers.ForbiddenError(),
			},
		},
		{
			name: "composite grants individually grant each project roles can update in granted project",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj1.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=update"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: proj2.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=update"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: proj3.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=update"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputErrorMap: map[*pbs.UpdateCredentialStoreRequest]error{
				vaultCredStoreInput(proj1.PublicId): nil,
				vaultCredStoreInput(proj2.PublicId): nil,
				vaultCredStoreInput(proj3.PublicId): nil,
			},
		},
		{
			name: "global grants not granting create permission cannot update credentials store",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=credential-store;actions=create"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
				{
					RoleScopeId: proj2.GetPublicId(),
					Grants:      []string{"ids=*;type=credential-store;actions=update"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputErrorMap: map[*pbs.UpdateCredentialStoreRequest]error{
				vaultCredStoreInput(proj1.PublicId): handlers.ForbiddenError(),
				vaultCredStoreInput(proj2.PublicId): nil,
				vaultCredStoreInput(proj3.PublicId): handlers.ForbiddenError(),
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			for input, wantErr := range tc.inputErrorMap {
				_, err = s.UpdateCredentialStore(fullGrantAuthCtx, input)
				if wantErr != nil {
					require.ErrorIs(t, err, wantErr)
					continue
				}
				require.NoError(t, err)
			}
		})
	}
}

func TestOutputFields_ListCredentialStores(t *testing.T) {
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

	org, staticProj := iam.TestScopes(t, iamRepo)
	staticCredStore := static.TestCredentialStore(t, conn, wrap, staticProj.GetPublicId(), static.WithName("static"), static.WithDescription("static"))
	vaultProj := iam.TestProject(t, iamRepo, org.GetPublicId())
	randomId, _ := uuid.GenerateUUID()
	vaultCredStore := vault.TestCredentialStore(t,
		conn,
		wrap,
		vaultProj.PublicId,
		fmt.Sprintf("http://vault%s", randomId),
		randomId,
		fmt.Sprintf("accessor-%s", randomId),
		vault.WithName("vault"), vault.WithDescription("desc"), vault.WithCACert([]byte{1, 2, 3}), vault.WithWorkerFilter(`"worker" in "/tags/name`))

	testcases := []struct {
		name                string
		userFunc            func() (*iam.User, authdomain.Account)
		input               *pbs.ListCredentialStoresRequest
		idToOutputFieldsMap map[string][]string // ID is always required in the output_fields
	}{
		{
			name: "global role grants descendant applies output_fields correctly when recursively listing credential stores",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,scope_id,name,description,authorized_actions,authorized_collection_actions"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
			}),
			input: &pbs.ListCredentialStoresRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			idToOutputFieldsMap: map[string][]string{
				staticCredStore.PublicId: {
					globals.IdField,
					globals.ScopeField,
					globals.ScopeIdField,
					globals.NameField,
					globals.DescriptionField,
					globals.AuthorizedActionsField,
					globals.AuthorizedCollectionActionsField,
				},
				vaultCredStore.PublicId: {
					globals.IdField,
					globals.ScopeField,
					globals.ScopeIdField,
					globals.NameField,
					globals.DescriptionField,
					globals.AuthorizedActionsField,
					globals.AuthorizedCollectionActionsField,
				},
			},
		},
		{
			name: "org role grants children applies output_fields correctly when recursively listing credential stores",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org.GetPublicId(),
					Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,created_time,updated_time,version,authorized_actions,authorized_collection_actions"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			input: &pbs.ListCredentialStoresRequest{
				ScopeId:   org.GetPublicId(),
				Recursive: true,
			},
			idToOutputFieldsMap: map[string][]string{
				staticCredStore.PublicId: {
					globals.IdField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.AuthorizedActionsField,
					globals.AuthorizedCollectionActionsField,
				},
				vaultCredStore.PublicId: {
					globals.IdField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.AuthorizedActionsField,
					globals.AuthorizedCollectionActionsField,
				},
			},
		},
		{
			name: "project role grants this applies output_fields correctly when listing credential stores",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: staticProj.GetPublicId(),
					Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,created_time,updated_time,version,authorized_actions,authorized_collection_actions"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			input: &pbs.ListCredentialStoresRequest{
				ScopeId: staticProj.GetPublicId(),
			},
			idToOutputFieldsMap: map[string][]string{
				staticCredStore.PublicId: {
					globals.IdField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.AuthorizedActionsField,
					globals.AuthorizedCollectionActionsField,
				},
			},
		},
		{
			name: "multiple role grants this applies output_fields correctly when listing credential stores across multiple scopes",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=credential-store;actions=list"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: staticProj.GetPublicId(),
					Grants: []string{
						"ids=*;type=*;actions=*;output_fields=id,created_time,updated_time,version,authorized_actions,authorized_collection_actions",
					},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: vaultProj.GetPublicId(),
					Grants: []string{
						"ids=*;type=*;actions=*;output_fields=id,name,description,scope,scope_id,authorized_actions,authorized_collection_actions",
					},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			input: &pbs.ListCredentialStoresRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			idToOutputFieldsMap: map[string][]string{
				staticCredStore.PublicId: {
					globals.IdField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.AuthorizedActionsField,
					globals.AuthorizedCollectionActionsField,
				},
				vaultCredStore.PublicId: {
					globals.IdField,
					globals.NameField,
					globals.DescriptionField,
					globals.ScopeField,
					globals.ScopeIdField,
					globals.AuthorizedActionsField,
					globals.AuthorizedCollectionActionsField,
				},
			},
		},
		{
			name: "global role grants descendant applies attributes output_fields correctly for each given type",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants: []string{
						"ids=*;type=*;actions=*;output_fields=id,type,attributes,authorized_actions,authorized_collection_actions",
					},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
			}),
			input: &pbs.ListCredentialStoresRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			idToOutputFieldsMap: map[string][]string{
				staticCredStore.PublicId: {
					globals.IdField,
					globals.TypeField,
					globals.AuthorizedActionsField,
					globals.AuthorizedCollectionActionsField,
				},
				vaultCredStore.PublicId: {
					globals.IdField,
					globals.TypeField,
					"vault_credential_store_attributes",
					globals.AuthorizedActionsField,
					globals.AuthorizedCollectionActionsField,
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			got, err := s.ListCredentialStores(fullGrantAuthCtx, tc.input)
			require.NoError(t, err)
			require.Equalf(t, len(got.Items), len(tc.idToOutputFieldsMap), "returned items do not match the number of expected items")
			for _, item := range got.Items {
				fmt.Println(item.String())
				wantFields, ok := tc.idToOutputFieldsMap[item.Id]
				require.Truef(t, ok, "returned item %s does not exist in expect map", item.GetId())
				handlers.TestAssertOutputFields(t, item, wantFields)
			}
		})
	}
}

func TestOutputFields_GetCredentialStore(t *testing.T) {
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

	org, proj := iam.TestScopes(t, iamRepo)
	staticCredStore := static.TestCredentialStore(t, conn, wrap, proj.GetPublicId(), static.WithName("static"), static.WithDescription("static"))
	vaultProj := iam.TestProject(t, iamRepo, org.GetPublicId())
	randomId, _ := uuid.GenerateUUID()
	vaultCredStore := vault.TestCredentialStore(t,
		conn,
		wrap,
		vaultProj.PublicId,
		fmt.Sprintf("http://vault%s", randomId),
		randomId,
		fmt.Sprintf("accessor-%s", randomId),
		vault.WithName("vault"), vault.WithDescription("desc"))

	testcases := []struct {
		name           string
		userFunc       func() (*iam.User, authdomain.Account)
		input          *pbs.GetCredentialStoreRequest
		expectedFields []string
	}{
		{
			name: "global role grants descendant applies output_fields correctly when reading credential stores",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,scope_id,name,description,authorized_actions,authorized_collection_actions"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
			}),
			input: &pbs.GetCredentialStoreRequest{
				Id: staticCredStore.PublicId,
			},
			expectedFields: []string{
				globals.IdField,
				globals.ScopeField,
				globals.ScopeIdField,
				globals.NameField,
				globals.DescriptionField,
				globals.AuthorizedActionsField,
				globals.AuthorizedCollectionActionsField,
			},
		},
		{
			name: "org role grants descendant applies output_fields correctly when reading credential stores",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org.PublicId,
					Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,version,attributes,authorized_actions,authorized_collection_actions"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			input: &pbs.GetCredentialStoreRequest{
				Id: vaultCredStore.PublicId,
			},
			expectedFields: []string{
				globals.IdField,
				globals.VersionField,
				"vault_credential_store_attributes",
				globals.AuthorizedActionsField,
				globals.AuthorizedCollectionActionsField,
			},
		},
		{
			name: "id specific grants descendant applies output_fields correctly",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants: []string{
						fmt.Sprintf("id=%s;type=credential-store;actions=*;output_fields=id,created_time,updated_time,authorized_actions", vaultCredStore.PublicId),
					},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
				},
			}),
			input: &pbs.GetCredentialStoreRequest{
				Id: vaultCredStore.PublicId,
			},
			expectedFields: []string{
				globals.IdField,
				globals.CreatedTimeField,
				globals.UpdatedTimeField,
				globals.AuthorizedActionsField,
			},
		},
		{
			name: "id specific with composite grants pinned that allows collection actions applies output_fields correctly for credential library child resource",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants: []string{
						fmt.Sprintf("id=%s;type=credential-store;actions=read;output_fields=id,authorized_actions,authorized_collection_actions", vaultCredStore.PublicId),
						fmt.Sprintf("id=%s;type=credential-library;actions=create,list", vaultCredStore.PublicId), // without this grants, authorized_collection_actions won't be filled
					},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
			}),
			input: &pbs.GetCredentialStoreRequest{
				Id: vaultCredStore.PublicId,
			},
			expectedFields: []string{
				globals.IdField,
				globals.AuthorizedActionsField,
				globals.AuthorizedCollectionActionsField,
			},
		},
		{
			name: "id specific grants descendant applies output_fields correctly",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: vaultProj.PublicId,
					Grants:      []string{"ids=*;type=*;actions=*;output_fields=*"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			input: &pbs.GetCredentialStoreRequest{
				Id: vaultCredStore.PublicId,
			},
			expectedFields: []string{
				globals.IdField,
				globals.ScopeIdField,
				globals.ScopeField,
				globals.VersionField,
				globals.CreatedTimeField,
				globals.UpdatedTimeField,
				globals.TypeField,
				globals.NameField,
				globals.DescriptionField,
				"vault_credential_store_attributes",
				globals.AuthorizedActionsField,
				globals.AuthorizedCollectionActionsField,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			got, err := s.GetCredentialStore(fullGrantAuthCtx, tc.input)
			require.NoError(t, err)
			handlers.TestAssertOutputFields(t, got.Item, tc.expectedFields)
		})
	}
}

// TestOutputFields_CreateCredentialStore only covers type=vault credentials store
// since the output_fields for Vault credential store is a superset of
// the static credential store
func TestOutputFields_CreateCredentialStore(t *testing.T) {
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
	v := vault.NewTestVaultServer(t, vault.WithTestVaultTLS(vault.TestClientTLS))

	org, proj := iam.TestScopes(t, iamRepo)

	vaultCredStoreInput := func() *pbs.CreateCredentialStoreRequest {
		_, token := v.CreateToken(t)
		id, _ := uuid.GenerateUUID()
		return &pbs.CreateCredentialStoreRequest{
			Item: &pb.CredentialStore{
				ScopeId:     proj.PublicId,
				Type:        vault.Subtype.String(),
				Name:        wrapperspb.String(id),
				Description: wrapperspb.String(id),
				Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
					VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
						Address:           wrapperspb.String(v.Addr),
						Token:             wrapperspb.String(token),
						CaCert:            wrapperspb.String(string(v.CaCert)),
						ClientCertificate: wrapperspb.String(string(v.ClientCert) + string(v.ClientKey)),
					},
				},
			},
		}
	}

	testcases := []struct {
		name           string
		userFunc       func() (*iam.User, authdomain.Account)
		expectedFields []string
	}{
		{
			name: "global role grants descendant applies output_fields correctly when reading credential stores",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,scope_id,name,description,authorized_actions,authorized_collection_actions"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
			}),
			expectedFields: []string{
				globals.IdField,
				globals.ScopeField,
				globals.ScopeIdField,
				globals.NameField,
				globals.DescriptionField,
				globals.AuthorizedActionsField,
				globals.AuthorizedCollectionActionsField,
			},
		},
		{
			name: "org role grants descendant applies output_fields correctly when reading credential stores",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org.PublicId,
					Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,version,attributes,authorized_actions,authorized_collection_actions"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			expectedFields: []string{
				globals.IdField,
				globals.VersionField,
				"vault_credential_store_attributes",
				globals.AuthorizedActionsField,
				globals.AuthorizedCollectionActionsField,
			},
		},
		{
			name: "org role grants descendant applies output_fields correctly when reading credential stores",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org.PublicId,
					Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,version,attributes,authorized_actions,authorized_collection_actions"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			expectedFields: []string{
				globals.IdField,
				globals.VersionField,
				"vault_credential_store_attributes",
				globals.AuthorizedActionsField,
				globals.AuthorizedCollectionActionsField,
			},
		},
		{
			name: "not granting credential-library access does not return authorized_collection_actions",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=*;output_fields=id,version,attributes,authorized_actions,authorized_collection_actions"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			expectedFields: []string{
				globals.IdField,
				globals.VersionField,
				"vault_credential_store_attributes",
				globals.AuthorizedActionsField,
			},
		},
		{
			name: "composite specific grants with credential-library access return authorized_collection_actions",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org.PublicId,
					Grants: []string{
						"ids=*;type=credential-store;actions=create,read;output_fields=id,version,attributes,authorized_actions,authorized_collection_actions",
						"ids=*;type=credential-library;actions=create,list",
					},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			expectedFields: []string{
				globals.IdField,
				globals.VersionField,
				"vault_credential_store_attributes",
				globals.AuthorizedActionsField,
				globals.AuthorizedCollectionActionsField,
			},
		},
		{
			name: "id specific grants descendant applies output_fields correctly",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj.PublicId,
					Grants:      []string{"ids=*;type=*;actions=*;output_fields=*"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectedFields: []string{
				globals.IdField,
				globals.ScopeIdField,
				globals.ScopeField,
				globals.VersionField,
				globals.CreatedTimeField,
				globals.UpdatedTimeField,
				globals.TypeField,
				globals.NameField,
				globals.DescriptionField,
				"vault_credential_store_attributes",
				globals.AuthorizedActionsField,
				globals.AuthorizedCollectionActionsField,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			got, err := s.CreateCredentialStore(fullGrantAuthCtx, vaultCredStoreInput())
			require.NoError(t, err)
			handlers.TestAssertOutputFields(t, got.Item, tc.expectedFields)
		})
	}
}

func TestOutputFields_UpdateCredentialStore(t *testing.T) {
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

	org, proj := iam.TestScopes(t, iamRepo)
	vaultCredStoreInput := func() *pbs.UpdateCredentialStoreRequest {
		id, _ := uuid.GenerateUUID()
		newId, _ := uuid.GenerateUUID()
		store := vault.TestCredentialStore(t, conn, wrap, proj.PublicId, fmt.Sprintf("http://vault%s", id), id, fmt.Sprintf("accessor-%s", id))
		return &pbs.UpdateCredentialStoreRequest{
			Id: store.PublicId,
			Item: &pb.CredentialStore{
				Name:        &wrapperspb.StringValue{Value: newId},
				Description: &wrapperspb.StringValue{Value: newId},
				Version:     store.Version,
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"name", "description"},
			},
		}
	}

	testcases := []struct {
		name           string
		userFunc       func() (*iam.User, authdomain.Account)
		expectedFields []string
	}{
		{
			name: "global role grants descendant applies output_fields correctly when reading credential stores",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,scope_id,name,description,attributes"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
			}),
			expectedFields: []string{
				globals.IdField,
				globals.ScopeField,
				globals.ScopeIdField,
				globals.NameField,
				"vault_credential_store_attributes",
				globals.DescriptionField,
			},
		},
		{
			name: "org role grants descendant applies output_fields correctly when reading credential stores",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org.PublicId,
					Grants:      []string{"ids=*;type=*;actions=*;output_fields=version,type,created_time,updated_time,authorized_actions,authorized_collection_actions"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			expectedFields: []string{
				globals.VersionField,
				globals.CreatedTimeField,
				globals.UpdatedTimeField,
				globals.TypeField,
				globals.AuthorizedActionsField,
				globals.AuthorizedCollectionActionsField,
			},
		},
		{
			name: "org role grants descendant applies output_fields correctly when reading credential stores",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org.PublicId,
					Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,version,attributes,authorized_actions,authorized_collection_actions"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			expectedFields: []string{
				globals.IdField,
				globals.VersionField,
				"vault_credential_store_attributes",
				globals.AuthorizedActionsField,
				globals.AuthorizedCollectionActionsField,
			},
		},
		{
			name: "id specific grants descendant applies output_fields correctly",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj.PublicId,
					Grants:      []string{"ids=*;type=*;actions=*;output_fields=*"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectedFields: []string{
				globals.IdField,
				globals.ScopeIdField,
				globals.ScopeField,
				globals.VersionField,
				globals.CreatedTimeField,
				globals.UpdatedTimeField,
				globals.TypeField,
				globals.NameField,
				globals.DescriptionField,
				"vault_credential_store_attributes",
				globals.AuthorizedActionsField,
				globals.AuthorizedCollectionActionsField,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			got, err := s.UpdateCredentialStore(fullGrantAuthCtx, vaultCredStoreInput())
			require.NoError(t, err)
			handlers.TestAssertOutputFields(t, got.Item, tc.expectedFields)
		})
	}
}
