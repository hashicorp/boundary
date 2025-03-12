// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package host_sets_test

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/authtoken"
	controllerauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/host_sets"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	hostplugin "github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/require"
)

// expectedOutput consolidates common output fields for the test cases
type expectedOutput struct {
	err          error
	outputFields []string
}

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

	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	scheduler := scheduler.TestScheduler(t, conn, wrap)
	pluginRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kmsCache, scheduler, map[string]plgpb.HostPluginServiceClient{})
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kmsCache)
	}
	s, err := host_sets.NewService(ctx, repoFn, pluginRepoFn, 1000)
	require.NoError(t, err)

	org, proj := iam.TestScopes(t, iamRepo) // TODO: Add a second org/proj scopes? To enforce independent behavior (e.g. grants in org1/proj1 shouldn't be returned when querying org2/proj2)

	// Create five test Host Sets under a test Host Catalog
	hcs := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)
	hc := hcs[0]
	hsets := make([]*static.HostSet, 5)
	for i := range cap(hsets) {
		hsets[i] = static.TestSet(t, conn, hc.PublicId,
			static.WithName(fmt.Sprintf("test name %d", i)),
			static.WithDescription(fmt.Sprintf("test description %d", i)),
		)
	}

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name          string
			input         *pbs.ListHostSetsRequest
			userFunc      func() (*iam.User, auth.Account)
			wantErr       error
			wantOutfields map[string][]string
		}{
			{
				name: "global role grant this returns 403 because host-sets live on projects",
				input: &pbs.ListHostSetsRequest{
					HostCatalogId: hc.GetPublicId(),
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "org role grant this returns 403 because host-sets live on projects",
				input: &pbs.ListHostSetsRequest{
					HostCatalogId: hc.GetPublicId(),
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.GetPublicId(),
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "project role grant this returns all host-sets on the project",
				input: &pbs.ListHostSetsRequest{
					HostCatalogId: hc.GetPublicId(),
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantOutfields: map[string][]string{
					hsets[0].GetPublicId(): {globals.IdField},
					hsets[1].GetPublicId(): {globals.IdField},
					hsets[2].GetPublicId(): {globals.IdField},
					hsets[3].GetPublicId(): {globals.IdField},
					hsets[4].GetPublicId(): {globals.IdField},
				},
			},
			{
				name: "global role grant this & children returns 403 because host-sets live on projects",
				input: &pbs.ListHostSetsRequest{
					HostCatalogId: hc.GetPublicId(),
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "org role grant children returns all host-sets on child projects",
				input: &pbs.ListHostSetsRequest{
					HostCatalogId: hc.GetPublicId(),
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				wantOutfields: map[string][]string{
					hsets[0].GetPublicId(): {globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField},
					hsets[1].GetPublicId(): {globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField},
					hsets[2].GetPublicId(): {globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField},
					hsets[3].GetPublicId(): {globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField},
					hsets[4].GetPublicId(): {globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField},
				},
			},
			{
				name: "global role grant this & descendants returns all host-sets on descendant projects",
				input: &pbs.ListHostSetsRequest{
					HostCatalogId: hc.GetPublicId(),
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantOutfields: map[string][]string{
					hsets[0].GetPublicId(): {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					hsets[1].GetPublicId(): {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					hsets[2].GetPublicId(): {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					hsets[3].GetPublicId(): {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					hsets[4].GetPublicId(): {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
				},
			},
			{
				name: "project role grant this returns all host-sets on the project",
				input: &pbs.ListHostSetsRequest{
					HostCatalogId: hc.GetPublicId(),
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,host_catalog_id,scope_id,name,description,created_time,updated_time,version,type,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantOutfields: map[string][]string{
					hsets[0].GetPublicId(): {globals.IdField, globals.HostCatalogIdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField},
					hsets[1].GetPublicId(): {globals.IdField, globals.HostCatalogIdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField},
					hsets[2].GetPublicId(): {globals.IdField, globals.HostCatalogIdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField},
					hsets[3].GetPublicId(): {globals.IdField, globals.HostCatalogIdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField},
					hsets[4].GetPublicId(): {globals.IdField, globals.HostCatalogIdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField},
				},
			},
			{
				name: "org role grant with host-catalog id, list action, host-set type, and children scope returns all host sets",
				input: &pbs.ListHostSetsRequest{
					HostCatalogId: hc.GetPublicId(),
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=" + hc.PublicId + ";type=host-set;actions=list,no-op;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				wantOutfields: map[string][]string{
					hsets[0].GetPublicId(): {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					hsets[1].GetPublicId(): {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					hsets[2].GetPublicId(): {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					hsets[3].GetPublicId(): {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					hsets[4].GetPublicId(): {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
				},
			},
			{
				name: "project role grant with host-catalog id, list action, host-set type, and this scope returns all host sets",
				input: &pbs.ListHostSetsRequest{
					HostCatalogId: hc.GetPublicId(),
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + hc.PublicId + ";type=host-set;actions=list,no-op;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantOutfields: map[string][]string{
					hsets[0].GetPublicId(): {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					hsets[1].GetPublicId(): {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					hsets[2].GetPublicId(): {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					hsets[3].GetPublicId(): {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					hsets[4].GetPublicId(): {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
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

				got, finalErr := s.ListHostSets(fullGrantAuthCtx, tc.input)
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

	t.Run("Get", func(t *testing.T) {
		// TODO: Implement
	})
}

func TestGrants_WriteActions(t *testing.T) {
	// ctx, conn, wrap, rw, kmsCache := helper.TestDbCore(t)
	// iamRepo := iam.TestRepo(t, conn, wrap)

	//TODO: Implement
}
