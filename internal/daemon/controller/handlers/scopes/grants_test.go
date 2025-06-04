// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package scopes_test

import (
	"context"
	"maps"
	"slices"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	controllerauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/scopes"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/require"
)

func TestGrants_ListScopes(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := scopes.NewServiceFn(ctx, repoFn, kmsCache, 1000)
	require.NoError(t, err)

	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	org1 := iam.TestOrg(t, iamRepo, iam.WithName("org1"), iam.WithDescription("test org 1"), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	org2 := iam.TestOrg(t, iamRepo, iam.WithName("org2"), iam.WithDescription("test org 2"), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	proj1 := iam.TestProject(t, iamRepo, org1.GetPublicId(), iam.WithName("proj1"), iam.WithDescription("test project 1"), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	proj2a := iam.TestProject(t, iamRepo, org2.GetPublicId(), iam.WithName("proj2a"), iam.WithDescription("test project 2a"), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	proj2b := iam.TestProject(t, iamRepo, org2.GetPublicId(), iam.WithName("proj2b"), iam.WithDescription("test project 2b"), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))

	testcases := []struct {
		name          string
		input         *pbs.ListScopesRequest
		userFunc      func() (*iam.User, auth.Account)
		rolesToCreate []authtoken.TestRoleGrantsForToken
		wantOutfields map[string][]string
		wantErr       error
	}{
		{
			name:  "global role grant this returns all org scopes",
			input: &pbs.ListScopesRequest{ScopeId: globals.GlobalPrefix},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=scope;actions=list,no-op;output_fields=id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantOutfields: map[string][]string{
				org1.PublicId: {globals.IdField},
				org2.PublicId: {globals.IdField},
			},
		},
		{
			name: "global role grant this & children returns org scopes",
			input: &pbs.ListScopesRequest{
				ScopeId: globals.GlobalPrefix,
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=scope;actions=list,read;output_fields=id"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			wantOutfields: map[string][]string{
				org1.PublicId: {globals.IdField},
				org2.PublicId: {globals.IdField},
			},
		},
		{
			name: "global role grant this & children recursive returns org and project scopes",
			input: &pbs.ListScopesRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=scope;actions=list,read;output_fields=id"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			wantOutfields: map[string][]string{
				org1.PublicId:   {globals.IdField},
				org2.PublicId:   {globals.IdField},
				proj1.PublicId:  {globals.IdField},
				proj2a.PublicId: {globals.IdField},
				proj2b.PublicId: {globals.IdField},
			},
		},
		{
			name: "global role grant this & descendants recursive returns org and project scopes",
			input: &pbs.ListScopesRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=scope;actions=list,read;output_fields=id"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
				},
			}),
			wantOutfields: map[string][]string{
				org1.PublicId:   {globals.IdField},
				org2.PublicId:   {globals.IdField},
				proj1.PublicId:  {globals.IdField},
				proj2a.PublicId: {globals.IdField},
				proj2b.PublicId: {globals.IdField},
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

			got, finalErr := s.ListScopes(fullGrantAuthCtx, tc.input)
			if tc.wantErr != nil {
				require.ErrorIs(t, finalErr, tc.wantErr)
				return
			}
			require.NoError(t, finalErr)
			var gotIds []string
			for _, g := range got.Items {
				gotIds = append(gotIds, g.GetId())

				// check if the output fields are as expected
				if tc.wantOutfields[g.Id] != nil {
					handlers.TestAssertOutputFields(t, g, tc.wantOutfields[g.Id])
				}
			}
			wantIds := slices.Collect(maps.Keys(tc.wantOutfields))
			require.ElementsMatch(t, wantIds, gotIds)
		})
	}
}
