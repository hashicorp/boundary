// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credentials_test

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/credential/static"
	controllerauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/credentials"
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
//			- proj level
//		Grant - what IAM grant scope is set for the permission
//			- global: descendant
//			- org: children
//			- project: this
//		Scopes [resource]:
//			- global
//				- org1
//					- proj1
func TestGrants_ReadActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kmsCache)
	}
	s, err := credentials.NewService(ctx, iamRepoFn, staticRepoFn, 1000)
	require.NoError(t, err)

	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	org, proj := iam.TestScopes(t, iamRepo)

	credStore := static.TestCredentialStore(t, conn, wrap, proj.GetPublicId())
	var credIds []string
	for i := range 5 {
		user := fmt.Sprintf("user-%d", i)
		pass := fmt.Sprintf("pass-%d", i)
		c := static.TestUsernamePasswordCredential(t, conn, wrap, user, pass, credStore.GetPublicId(), proj.GetPublicId(), static.WithName(fmt.Sprintf("cred-%d", i)), static.WithDescription(fmt.Sprintf("desc-%d", i)))
		credIds = append(credIds, c.GetPublicId())
	}

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name          string
			userFunc      func() (*iam.User, auth.Account)
			wantErr       error
			wantOutfields map[string][]string
		}{
			{
				name: "global role grant this returns 403 because credentials live on projects",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "org role grant this returns 403 because credentials live on projects",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.GetPublicId(),
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "project role grant this returns all credentials on the project",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantOutfields: map[string][]string{
					credIds[0]: {globals.IdField},
					credIds[1]: {globals.IdField},
					credIds[2]: {globals.IdField},
					credIds[3]: {globals.IdField},
					credIds[4]: {globals.IdField},
				},
			},
			{
				name: "global role grant this & children returns 403 because credentials live on projects",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "org role grant children returns all credentials on child projects",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,credential_store_id,scope,name,description,created_time,updated_time,version,type"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				wantOutfields: map[string][]string{
					credIds[0]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField},
					credIds[1]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField},
					credIds[2]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField},
					credIds[3]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField},
					credIds[4]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField},
				},
			},
			{
				name: "global role grant this & descendants returns all credentials on descendant projects",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantOutfields: map[string][]string{
					credIds[0]: {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					credIds[1]: {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					credIds[2]: {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					credIds[3]: {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					credIds[4]: {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
				},
			},
			{
				name: "project role grant this returns all credentials on the project",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,credential_store_id,scope,name,description,created_time,updated_time,version,type"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantOutfields: map[string][]string{
					credIds[0]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField},
					credIds[1]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField},
					credIds[2]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField},
					credIds[3]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField},
					credIds[4]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField},
				},
			},
			{
				name: "global role grant with credential-store id, list action, credential type, and descendant scope returns all credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=" + credStore.PublicId + ";type=credential;actions=list,no-op;output_fields=id,name,description,credential_store_id"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				wantOutfields: map[string][]string{
					credIds[0]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.CredentialStoreIdField},
					credIds[1]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.CredentialStoreIdField},
					credIds[2]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.CredentialStoreIdField},
					credIds[3]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.CredentialStoreIdField},
					credIds[4]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.CredentialStoreIdField},
				},
			},
			{
				name: "org role grant with credential-store id, list action, credential type, and children scope returns all credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=" + credStore.PublicId + ";type=credential;actions=list,no-op;output_fields=id,name,description,version,credential_store_id"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				wantOutfields: map[string][]string{
					credIds[0]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
					credIds[1]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
					credIds[2]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
					credIds[3]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
					credIds[4]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
				},
			},
			{
				name: "project role grant with credential-store id, list action, credential type, and this scope returns all credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + credStore.PublicId + ";type=credential;actions=list,no-op;output_fields=id,name,description,version,credential_store_id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantOutfields: map[string][]string{
					credIds[0]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
					credIds[1]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
					credIds[2]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
					credIds[3]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
					credIds[4]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
				},
			},
			{
				name: "incorrect grants can't list credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=credential;actions=read,create,update,delete"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name:     "no grants returns 403",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, nil),
				wantErr:  handlers.ForbiddenError(),
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

				got, finalErr := s.ListCredentials(fullGrantAuthCtx, &pbs.ListCredentialsRequest{CredentialStoreId: credStore.GetPublicId()})
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
	})
}
