// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credentialstores_test

import (
	"context"
	"fmt"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentialstores"
	"github.com/hashicorp/go-uuid"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=credential-store;actions=create"},
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org2.PublicId,
					Grants:      []string{"ids=*;type=credential-store;actions=read"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			inputErrorMap: map[*pbs.GetCredentialStoreRequest]error{
				{Id: proj1VaultStore.GetPublicId()}:  nil,
				{Id: proj2StaticStore.GetPublicId()}: nil,
				{Id: proj3VaultStore.GetPublicId()}:  nil,
			},
		},
		{
			name: "project role can only read credential stores in this project",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			name: "composite grants individually grant each project roles can create credential stores where granted",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			name: "composite grants individually grant each project roles can delete credential stores where granted",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			name: "composite grants individually grant each project roles can update credential stores where granted",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
