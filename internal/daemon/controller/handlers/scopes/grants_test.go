// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package scopes_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	controllerauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/scopes"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/require"
)

// TestGrants_ReadActions tests read actions to assert that grants are being applied properly
//
//	 Role - which scope the role is created in
//			- global level
//			- org level
//		Grant - what IAM grant scope is set for the permission
//			- global: descendant
//			- org: children
//		Scopes [resource]:
//			- global [globalScope]
//				- org1
//					- proj1
func TestGrants_ReadActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := scopes.NewServiceFn(ctx, repoFn, kmsCache, 1000)
	require.NoError(t, err)
	rw := db.New(conn)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	org1, proj1 := iam.TestScopes(t, iamRepo)
	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name     string
			input    *pbs.ListScopesRequest
			userFunc func() (*iam.User, auth.Account)
			wantErr  error
			wantIDs  []string
		}{
			{
				name: "global role grant this returns all created scopes",
				input: &pbs.ListScopesRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=scope;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				wantIDs: []string{
					org1.PublicId,
					proj1.PublicId,
				},
			},
			{
				name: "org role grant this returns all created scopes",
				input: &pbs.ListScopesRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=scope;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				wantIDs: []string{
					proj1.PublicId,
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, finalErr := s.ListScopes(fullGrantAuthCtx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, finalErr, tc.wantErr)
					return
				}
				require.NoError(t, finalErr)
				var gotIDs []string
				for _, g := range got.Items {
					gotIDs = append(gotIDs, g.GetId())
				}
				require.ElementsMatch(t, tc.wantIDs, gotIDs)
			})
		}
	})
}

func TestGrants_List_AuthorizedAction(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	_, _ = iam.TestScopes(t, iamRepo)
	_, _ = iam.TestScopes(t, iamRepo)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := scopes.NewServiceFn(ctx, repoFn, kmsCache, 1000)
	require.NoError(t, err)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	user, account := iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
		{
			RoleScopeId: globals.GlobalPrefix,
			Grants:      []string{"ids=*;type=*;actions=*"},
			GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
		},
	})()
	tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
	require.NoError(t, err)
	fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
	got, err := s.ListScopes(fullGrantAuthCtx, &pbs.ListScopesRequest{ScopeId: globals.GlobalPrefix, Recursive: true})
	require.NoError(t, err)
	for _, item := range got.Items {
		switch item.GetType() {
		case "global":
			require.ElementsMatch(t, item.AuthorizedActions, []string{"no-op", "read", "update", "delete", "attach-storage-policy", "detach-storage-policy"})
			require.Len(t, item.AuthorizedCollectionActions, 11)
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Alias.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.AuthMethod.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.StorageBucket.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.AuthToken.PluralString()].AsSlice(), []string{"list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Group.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Role.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Scope.PluralString()].AsSlice(), []string{"create", "list", "list-keys", "rotate-keys", "list-key-version-destruction-jobs", "destroy-key-version"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.User.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Worker.PluralString()].AsSlice(), []string{"read-certificate-authority", "create-controller-led", "create-worker-led", "reinitialize-certificate-authority", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.SessionRecording.PluralString()].AsSlice(), []string{"list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Policy.PluralString()].AsSlice(), []string{"create", "list"})
		case "org":
			require.ElementsMatch(t, item.AuthorizedActions, []string{"no-op", "read", "update", "delete", "attach-storage-policy", "detach-storage-policy"})
			require.Len(t, item.AuthorizedCollectionActions, 9)
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.AuthMethod.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.StorageBucket.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.AuthToken.PluralString()].AsSlice(), []string{"list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Group.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Role.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Scope.PluralString()].AsSlice(), []string{"create", "list", "list-keys", "rotate-keys", "list-key-version-destruction-jobs", "destroy-key-version"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.User.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.SessionRecording.PluralString()].AsSlice(), []string{"list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Policy.PluralString()].AsSlice(), []string{"create", "list"})
		case "project":
			require.ElementsMatch(t, item.AuthorizedActions, []string{"no-op", "read", "update", "delete"})
			require.Len(t, item.AuthorizedCollectionActions, 7)
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.CredentialStore.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Group.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.HostCatalog.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Role.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Scope.PluralString()].AsSlice(), []string{"list-keys", "rotate-keys", "list-key-version-destruction-jobs", "destroy-key-version"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Session.PluralString()].AsSlice(), []string{"list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Target.PluralString()].AsSlice(), []string{"create", "list"})
		default:
			t.Fatalf("unknown item type: %s", item.GetType())
		}
	}
}
