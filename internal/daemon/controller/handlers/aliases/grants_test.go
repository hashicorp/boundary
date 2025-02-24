// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package aliases_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/aliases"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// TestGrants_ReadActions tests read actions to assert that grants are being applied properly
//
//	 Role - which scope the role is created in
//			- global level
//		Scopes [resource]:
//			- globalAlias1 [globalAlias]
//			- globalAlias2 [globalAlias]
func TestGrants_ReadActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(ctx, rw, rw, kmsCache)
	}
	s, err := aliases.NewService(ctx, repoFn, iamRepoFn, 1000)
	require.NoError(t, err)
	globalAlias1 := target.TestAlias(t, rw, "test.alias.one", target.WithDescription("alias_1"), target.WithName("alias_one"))
	globalAlias2 := target.TestAlias(t, rw, "test.alias.two", target.WithDescription("alias_2"), target.WithName("alias_two"))
	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name          string
			input         *pbs.ListAliasesRequest
			rolesToCreate []authtoken.TestRoleGrantsForToken
			wantErr       error
			wantIDs       []string
		}{
			{
				name: "global role grant this returns all created aliases",
				input: &pbs.ListAliasesRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=alias;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis},
					},
				},
				wantErr: nil,
				wantIDs: []string{globalAlias1.PublicId, globalAlias2.PublicId},
			},
			{
				name: "global role grant this with a non-applicable type throws an a permission error",
				input: &pbs.ListAliasesRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=group;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis},
					},
				},
				wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				tok := authtoken.TestAuthTokenWithRoles(t, conn, kmsCache, globals.GlobalPrefix, tc.rolesToCreate)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, finalErr := s.ListAliases(fullGrantAuthCtx, tc.input)
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
