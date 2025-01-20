// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package users_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/globals"
	talias "github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/users"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
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
//			- global [globalUser]
//				- org1 [org1User]
//					- org1User1
//				- org2 [org2User]
//					- org2User1
//					- org2User2
func TestGrants_ReadActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	aliasRepoFn := func() (*talias.Repository, error) {
		return talias.NewRepository(context.Background(), rw, rw, kmsCache)
	}
	s, err := users.NewService(ctx, repoFn, aliasRepoFn, 1000)
	require.NoError(t, err)
	org1, _ := iam.TestScopes(t, iamRepo)
	org2, _ := iam.TestScopes(t, iamRepo)

	globalUser := iam.TestUser(t, iamRepo, globals.GlobalPrefix, iam.WithDescription("global"), iam.WithName("global"))
	org1User1 := iam.TestUser(t, iamRepo, org1.GetPublicId(), iam.WithDescription("org1"), iam.WithName("org1"))
	org2User1 := iam.TestUser(t, iamRepo, org2.GetPublicId(), iam.WithDescription("org2-1"), iam.WithName("org2-1"))
	org2User2 := iam.TestUser(t, iamRepo, org2.GetPublicId(), iam.WithDescription("org2-2"), iam.WithName("org2-2"))

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name          string
			input         *pbs.ListUsersRequest
			rolesToCreate []authtoken.TestRoleGrantsForToken
			wantErr       error
			wantIDs       []string
		}{
			{
				name: "global role grant this and children returns global and org users",
				input: &pbs.ListUsersRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeID:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=user;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
				wantErr: nil,
				wantIDs: []string{
					globals.AnyAuthenticatedUserId,
					globals.AnonymousUserId,
					globals.RecoveryUserId,
					globalUser.PublicId,
					org1User1.PublicId,
					org2User1.PublicId,
					org2User2.PublicId,
				},
			},
			{
				name: "org role grant this and children returns org user",
				input: &pbs.ListUsersRequest{
					ScopeId:   org2.PublicId,
					Recursive: true,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeID:  org2.PublicId,
						GrantStrings: []string{"ids=*;type=user;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
				wantErr: nil,
				wantIDs: []string{
					org2User1.PublicId,
					org2User2.PublicId,
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				tok := authtoken.TestAuthTokenWithRoles(t, conn, kmsCache, globals.GlobalPrefix, tc.rolesToCreate)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, finalErr := s.ListUsers(fullGrantAuthCtx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, finalErr, tc.wantErr)
					return
				}
				require.NoError(t, finalErr)
				var gotIDs []string
				fmt.Println("tok.IamUserId", tok.IamUserId)
				if tc.input.ScopeId == globals.GlobalPrefix {
					tc.wantIDs = append(tc.wantIDs, tok.IamUserId)
				}
				for _, g := range got.Items {
					gotIDs = append(gotIDs, g.GetId())
				}
				require.ElementsMatch(t, tc.wantIDs, gotIDs)
			})
		}
	})
}
