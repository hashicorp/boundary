// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package host_sets_test

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/golang/protobuf/ptypes/wrappers"
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
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
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

	org, proj := iam.TestScopes(t, iamRepo)
	proj2 := iam.TestProject(t, iamRepo, org.GetPublicId(), iam.WithName("project #2"))

	// Create five test Host Sets under a test Host Catalog
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hsets := make([]*static.HostSet, 5)
	for i := range cap(hsets) {
		hsets[i] = static.TestSet(t, conn, hc.PublicId,
			static.WithName(fmt.Sprintf("test name %d", i)),
			static.WithDescription(fmt.Sprintf("test description %d", i)),
		)
	}

	// do it again for the second project
	hc2 := static.TestCatalogs(t, conn, proj2.GetPublicId(), 1)[0]
	hsets2 := make([]*static.HostSet, 3)
	for i := range cap(hsets2) {
		hsets2[i] = static.TestSet(t, conn, hc2.PublicId,
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
			// The next two cases share identical setup, but test ListHostSets in different projects/host-catalogs:
			{
				name: "org role grant with pinned host-catalog id, list action, host-set type, and children scope can list all host sets in the pinned host-catalog",
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
				name: "org role grant with pinned host-catalog id, list action, host-set type, and children scope can not list host sets in a different host-catalog",
				input: &pbs.ListHostSetsRequest{
					HostCatalogId: hc2.GetPublicId(),
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=" + hc.PublicId + ";type=host-set;actions=list,no-op;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				wantErr: handlers.ForbiddenError(),
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
		testcases := []struct {
			name          string
			userFunc      func() (*iam.User, auth.Account)
			canGetHostSet map[string]expectedOutput
		}{
			{
				name: "global role grant this returns 403",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canGetHostSet: map[string]expectedOutput{
					hsets[0].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[1].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[2].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[3].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[4].GetPublicId(): {err: handlers.ForbiddenError()},
				},
			},
			{
				name: "org role grant this returns 403",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canGetHostSet: map[string]expectedOutput{
					hsets[0].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[1].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[2].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[3].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[4].GetPublicId(): {err: handlers.ForbiddenError()},
				},
			},
			{
				name: "project role grant this returns all host-sets on the project",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canGetHostSet: map[string]expectedOutput{
					hsets[0].GetPublicId(): {outputFields: []string{globals.IdField}},
					hsets[1].GetPublicId(): {outputFields: []string{globals.IdField}},
					hsets[2].GetPublicId(): {outputFields: []string{globals.IdField}},
					hsets[3].GetPublicId(): {outputFields: []string{globals.IdField}},
					hsets[4].GetPublicId(): {outputFields: []string{globals.IdField}},
				},
			},
			{
				name: "global role grant this & children returns 403 because host-sets live on projects",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				canGetHostSet: map[string]expectedOutput{
					hsets[0].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[1].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[2].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[3].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[4].GetPublicId(): {err: handlers.ForbiddenError()},
				},
			},
			{
				name: "org role grant children returns all host-sets on child projects",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				canGetHostSet: map[string]expectedOutput{
					hsets[0].GetPublicId(): {outputFields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField}},
					hsets[1].GetPublicId(): {outputFields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField}},
					hsets[2].GetPublicId(): {outputFields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField}},
					hsets[3].GetPublicId(): {outputFields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField}},
					hsets[4].GetPublicId(): {outputFields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField}},
				},
			},
			{
				name: "global role grant this & descendants returns all host-sets on descendant projects",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				canGetHostSet: map[string]expectedOutput{
					hsets[0].GetPublicId(): {outputFields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
					hsets[1].GetPublicId(): {outputFields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
					hsets[2].GetPublicId(): {outputFields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
					hsets[3].GetPublicId(): {outputFields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
					hsets[4].GetPublicId(): {outputFields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
				},
			},
			{
				name: "project role grant this returns all host-sets on the project",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,host_catalog_id,scope_id,name,description,created_time,updated_time,version,type,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canGetHostSet: map[string]expectedOutput{
					hsets[0].GetPublicId(): {outputFields: []string{globals.IdField, globals.HostCatalogIdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField}},
					hsets[1].GetPublicId(): {outputFields: []string{globals.IdField, globals.HostCatalogIdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField}},
					hsets[2].GetPublicId(): {outputFields: []string{globals.IdField, globals.HostCatalogIdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField}},
					hsets[3].GetPublicId(): {outputFields: []string{globals.IdField, globals.HostCatalogIdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField}},
					hsets[4].GetPublicId(): {outputFields: []string{globals.IdField, globals.HostCatalogIdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField}},
				},
			},
			{
				name: "incorrect grants returns no host set",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=host-set;actions=list,create,update,delete;output_fields=id,name,description,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canGetHostSet: map[string]expectedOutput{
					hsets[0].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[1].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[2].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[3].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[4].GetPublicId(): {err: handlers.ForbiddenError()},
				},
			},
			{
				name:     "no grants returns no host sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, nil),
				canGetHostSet: map[string]expectedOutput{
					hsets[0].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[1].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[2].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[3].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[4].GetPublicId(): {err: handlers.ForbiddenError()},
				},
			},
			{
				name: "project role grant with host-set id, get action, host-set type, and this scope returns the id'd host set",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + hsets[0].PublicId + ";actions=read;output_fields=id,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canGetHostSet: map[string]expectedOutput{
					hsets[0].GetPublicId(): {outputFields: []string{globals.IdField, globals.AuthorizedActionsField}},
					hsets[1].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[2].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[3].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[4].GetPublicId(): {err: handlers.ForbiddenError()},
				},
			},
			{
				name: "org role grant with host-set id, get action, host-set type, and this & children scope returns the id'd host set",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=" + hsets[4].PublicId + ";actions=read;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				canGetHostSet: map[string]expectedOutput{
					hsets[0].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[1].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[2].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[3].GetPublicId(): {err: handlers.ForbiddenError()},
					hsets[4].GetPublicId(): {outputFields: []string{globals.IdField}},
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)

				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				for id, expected := range tc.canGetHostSet {
					input := &pbs.GetHostSetRequest{Id: id}
					_, err := s.GetHostSet(fullGrantAuthCtx, input)
					if expected.err != nil {
						require.ErrorIs(t, err, expected.err)
						continue
					}
					// check if the output fields are as expected
					if tc.canGetHostSet[id].outputFields != nil {
						handlers.TestAssertOutputFields(t, input, tc.canGetHostSet[id].outputFields)
					}
					require.NoError(t, err)
				}
			})
		}
	})
}

func TestGrants_WriteActions(t *testing.T) {
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

	org, proj := iam.TestScopes(t, iamRepo)

	hcs := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)
	hc := hcs[0]

	t.Run("Create", func(t *testing.T) {
		testcases := []struct {
			name     string
			userFunc func() (*iam.User, auth.Account)
			expected expectedOutput
		}{
			{
				name: "global role grant this can't create host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "org role grant this can't create host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "project role grant this can create host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField}},
			},
			{
				name: "global role grant this & descendants can create host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host-set;actions=create,read,update;output_fields=id,host_catalog_id,scope_id,name,description,created_time,updated_time,version,type,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.HostCatalogIdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField}},
			},
			{
				name: "org role grant this & children can create host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=host-set;actions=create;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

				got, err := s.CreateHostSet(fullGrantAuthCtx, &pbs.CreateHostSetRequest{Item: &pb.HostSet{
					HostCatalogId: hc.GetPublicId(),
					Name:          &wrappers.StringValue{Value: "test host set - " + tc.name},
					Description:   &wrappers.StringValue{Value: "test desc"},
				}})
				if tc.expected.err != nil {
					require.ErrorIs(t, err, tc.expected.err)
					return
				}
				// check if the output fields are as expected
				require.NoError(t, err)
				handlers.TestAssertOutputFields(t, got.Item, tc.expected.outputFields)
			})
		}
	})

	t.Run("Update", func(t *testing.T) {
		testcases := []struct {
			name     string
			userFunc func() (*iam.User, auth.Account)
			expected expectedOutput
		}{
			{
				name: "global role grant this can't update host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "org role grant this can't update host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "project role grant this can update host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField}},
			},
			{
				name: "global role grant this & descendants can update host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host-set;actions=update;output_fields=id,host_catalog_id,scope_id,name,description,created_time,updated_time,version,type,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.HostCatalogIdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField}},
			},
			{
				name: "org role grant this & children can update host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=host-set;actions=update;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
			},
			{
				name: "incorrect grants can't update host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=host-set;actions=list,create,delete;output_fields=id,name,description,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name:     "no grants can't update host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, nil),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				hc := static.TestCatalogs(t, conn, proj.PublicId, 1)[0]
				hset := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

				got, err := s.UpdateHostSet(fullGrantAuthCtx, &pbs.UpdateHostSetRequest{
					Id: hset.PublicId,
					Item: &pb.HostSet{
						Name:        &wrappers.StringValue{Value: "updated host set name (" + tc.name + ")"},
						Description: &wrappers.StringValue{Value: "test desc"},
						Version:     1,
					},
					UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"name", "description"}},
				})
				if tc.expected.err != nil {
					require.ErrorIs(t, err, tc.expected.err)
					return
				}
				// check if the output fields are as expected
				require.NoError(t, err)
				handlers.TestAssertOutputFields(t, got.Item, tc.expected.outputFields)
			})
		}
	})

	t.Run("Delete", func(t *testing.T) {
		testcases := []struct {
			name     string
			userFunc func() (*iam.User, auth.Account)
			wantErr  error
		}{
			{
				name: "global role grant this can't delete host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "org role grant this can't delete host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "project role grant this can delete host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
			},
			{
				name: "global role grant this & descendants can delete host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host-set;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
			},
			{
				name: "org role grant this & children can delete host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=host-set;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
			},
			{
				name: "incorrect grants can't delete host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=host-set;actions=list,create,update"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name:     "no grants can't delete host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, nil),
				wantErr:  handlers.ForbiddenError(),
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				hc := static.TestCatalogs(t, conn, proj.PublicId, 1)[0]
				hset := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

				_, err = s.DeleteHostSet(fullGrantAuthCtx, &pbs.DeleteHostSetRequest{Id: hset.PublicId})
				if tc.wantErr != nil {
					require.ErrorIs(t, err, tc.wantErr)
					return
				}
				require.NoError(t, err)
			})
		}
	})

	t.Run("Add Host Set Hosts", func(t *testing.T) {
		hc := static.TestCatalog(t, conn, proj.PublicId, static.WithName("test add host set hosts catalog"), static.WithDescription("test desc"))
		hcClone := static.TestCatalog(t, conn, proj.PublicId, static.WithName("clone add host set hosts catalog"), static.WithDescription("clone desc"))

		testcases := []struct {
			name     string
			userFunc func() (*iam.User, auth.Account)
			expected expectedOutput
		}{
			{
				name: "global role grant this can't add hosts to host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "org role grant this can't add hosts to host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "project role grant this can add hosts to host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=host-set;actions=add-hosts;output_fields=id,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField}},
			},
			{
				name: "global role grant this & descendants can add hosts to host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host-set;actions=add-hosts;output_fields=id,host_catalog_id,scope_id,name,description,created_time,updated_time,version,type,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.HostCatalogIdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField}},
			},
			{
				name: "org role grant this & children can add hosts to host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=host-set;actions=add-hosts;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
			},
			{
				name: "incorrect grants can't add hosts to host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=host-set;actions=list,create,update,delete;output_fields=id,name,description,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name:     "no grants can't add hosts to host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, nil),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "global role grant with host-catalog id, add-hosts action, host-set type, and this/children scope allows adding hosts to host-sets under the specified host-catalog",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=" + hc.PublicId + ";type=host-set;actions=add-hosts;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
			},
			{
				name: "org role grant with host-catalog id, add-hosts action, host-set type, and this/children scope allows adding hosts to host-sets under the specified host-catalog",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=" + hc.PublicId + ";type=host-set;actions=add-hosts;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
			},
			{
				name: "project role grant with host-catalog id, add-hosts action, host-set type, and this/children scope allows adding hosts to host-sets under the specified host-catalog",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + hc.PublicId + ";type=host-set;actions=add-hosts;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
			},
			{
				name: "project role grant with an unassociated host-catalog id and add-hosts action does not allow adding hosts to host-sets under the specified host-catalog",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + hcClone.PublicId + ";type=host-set;actions=add-hosts;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				hset := static.TestSet(t, conn, hc.PublicId,
					static.WithName("test name - "+tc.name),
					static.WithDescription("test description"),
				)
				hosts := static.TestHosts(t, conn, hc.GetPublicId(), 2)

				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

				got, err := s.AddHostSetHosts(fullGrantAuthCtx, &pbs.AddHostSetHostsRequest{
					Id: hset.PublicId,
					HostIds: []string{
						hosts[0].PublicId,
						hosts[1].PublicId,
					},
					Version: 1,
				})
				if tc.expected.err != nil {
					require.ErrorIs(t, err, tc.expected.err)
					return
				}
				// check if the output fields are as expected
				require.NoError(t, err)
				handlers.TestAssertOutputFields(t, got.Item, tc.expected.outputFields)
			})
		}
	})

	t.Run("Remove Host Set Hosts", func(t *testing.T) {
		hc := static.TestCatalog(t, conn, proj.PublicId, static.WithName("test remove host set hosts catalog"), static.WithDescription("test desc"))
		hcClone := static.TestCatalog(t, conn, proj.PublicId, static.WithName("clone remove host set hosts catalog"), static.WithDescription("clone desc"))

		// We need to create a host set with hosts in order to remove hosts.
		// As a result, each testcase is granted the `add-hosts` action for our test host-catalog.
		grantAddHostSetHosts := iam.TestRoleGrantsRequest{
			RoleScopeId: proj.PublicId,
			Grants:      []string{"ids=" + hc.PublicId + ";type=host-set;actions=add-hosts;output_fields=id"},
			GrantScopes: []string{globals.GrantScopeThis},
		}
		testcases := []struct {
			name     string
			userFunc func() (*iam.User, auth.Account)
			expected expectedOutput
		}{
			{
				name: "global role grant this can't remove hosts from host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					grantAddHostSetHosts,
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "org role grant this can't remove hosts from host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					grantAddHostSetHosts,
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "project role grant this can remove hosts from host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					grantAddHostSetHosts,
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=host-set;actions=remove-hosts;output_fields=id,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField}},
			},
			{
				name: "global role grant this & descendants can remove hosts from host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					grantAddHostSetHosts,
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host-set;actions=remove-hosts;output_fields=id,host_catalog_id,scope_id,name,description,created_time,updated_time,version,type,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.HostCatalogIdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField}},
			},
			{
				name: "org role grant this & children can remove hosts from host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					grantAddHostSetHosts,
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=host-set;actions=remove-hosts;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
			},
			{
				name: "incorrect grants can't remove hosts from host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					grantAddHostSetHosts,
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=host-set;actions=list,create,update;output_fields=id,name,description,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name:     "no grants can't remove hosts from host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{grantAddHostSetHosts}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "global role grant with host-catalog id, remove-hosts action, host-set type, and this/children scope allows removing hosts from host-sets under the specified host-catalog",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					grantAddHostSetHosts,
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=" + hc.PublicId + ";type=host-set;actions=remove-hosts;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
			},
			{
				name: "org role grant with host-catalog id, remove-hosts action, host-set type, and this/children scope allows removing hosts from host-sets under the specified host-catalog",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					grantAddHostSetHosts,
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=" + hc.PublicId + ";type=host-set;actions=remove-hosts;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
			},
			{
				name: "project role grant with host-catalog id, remove-hosts action, host-set type, and this/children scope allows removing hosts from host-sets under the specified host-catalog",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					grantAddHostSetHosts,
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + hc.PublicId + ";type=host-set;actions=remove-hosts;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
			},
			{
				name: "project role grant with an unassociated host-catalog id and remove-hosts action does not allow removing hosts from host-sets under the specified host-catalog",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					grantAddHostSetHosts,
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + hcClone.PublicId + ";type=host-set;actions=remove-hosts;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				hset := static.TestSet(t, conn, hc.PublicId,
					static.WithName("test name - "+tc.name),
					static.WithDescription("test description"),
				)
				hosts := static.TestHosts(t, conn, hc.GetPublicId(), 2)

				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

				// add hosts to the host set
				_, err = s.AddHostSetHosts(fullGrantAuthCtx, &pbs.AddHostSetHostsRequest{
					Id: hset.PublicId,
					HostIds: []string{
						hosts[0].PublicId,
						hosts[1].PublicId,
					},
					// Version: version,
					Version: 1,
				})
				require.NoError(t, err)

				// remove hosts from the host set
				got, err := s.RemoveHostSetHosts(fullGrantAuthCtx, &pbs.RemoveHostSetHostsRequest{
					Id: hset.PublicId,
					HostIds: []string{
						hosts[0].PublicId,
						hosts[1].PublicId,
					},
					Version: 2,
				})
				if tc.expected.err != nil {
					require.ErrorIs(t, err, tc.expected.err)
					return
				}
				// check if the output fields are as expected
				require.NoError(t, err)
				handlers.TestAssertOutputFields(t, got.Item, tc.expected.outputFields)
			})
		}
	})

	t.Run("Set Host Set Hosts", func(t *testing.T) {
		hc := static.TestCatalog(t, conn, proj.PublicId, static.WithName("test set host set hosts catalog"), static.WithDescription("test desc"))
		hcClone := static.TestCatalog(t, conn, proj.PublicId, static.WithName("clone set host set hosts catalog"), static.WithDescription("clone desc"))

		testcases := []struct {
			name     string
			userFunc func() (*iam.User, auth.Account)
			expected expectedOutput
		}{
			{
				name: "global role grant this can't set hosts on host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "org role grant this can't set hosts on host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "project role grant this can set hosts on host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=host-set;actions=set-hosts;output_fields=id,host_ids,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.HostIdsField, globals.CreatedTimeField, globals.UpdatedTimeField}},
			},
			{
				name: "global role grant this & descendants can set hosts on host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host-set;actions=set-hosts;output_fields=id,host_ids,host_catalog_id,scope_id,name,description,created_time,updated_time,version,type,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.HostIdsField, globals.HostCatalogIdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField}},
			},
			{
				name: "org role grant this & children can set hosts on host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=host-set;actions=set-hosts;output_fields=id,host_ids,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.HostIdsField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
			},
			{
				name: "incorrect grants can't set hosts on host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=host-set;actions=list,create,update;output_fields=id,name,description,host_ids,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name:     "no grants can't set hosts on host-sets",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, nil),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "global role grant with host-catalog id, set-hosts action, host-set type, and this/children scope allows setting hosts on host-sets under the specified host-catalog",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=" + hc.PublicId + ";type=host-set;actions=set-hosts;output_fields=id,host_ids,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.HostIdsField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
			},
			{
				name: "org role grant with host-catalog id, set-hosts action, host-set type, and this/children scope allows setting hosts on host-sets under the specified host-catalog",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=" + hc.PublicId + ";type=host-set;actions=set-hosts;output_fields=id,host_ids,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.HostIdsField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
			},
			{
				name: "project role grant with host-catalog id, set-hosts action, host-set type, and this/children scope allows setting hosts on host-sets under the specified host-catalog",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + hc.PublicId + ";type=host-set;actions=set-hosts;output_fields=id,host_ids,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.HostIdsField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
			},
			{
				name: "project role grant with an unassociated host-catalog id and set-hosts action does not allow setting hosts on host-sets under the specified host-catalog",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + hcClone.PublicId + ";type=host-set;actions=set-hosts;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				hset := static.TestSet(t, conn, hc.PublicId,
					static.WithName("test name - "+tc.name),
					static.WithDescription("test description"),
				)
				hosts := static.TestHosts(t, conn, hc.GetPublicId(), 3)

				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

				got, err := s.SetHostSetHosts(fullGrantAuthCtx, &pbs.SetHostSetHostsRequest{
					Id: hset.PublicId,
					HostIds: []string{
						hosts[0].PublicId,
						hosts[1].PublicId,
						hosts[2].PublicId,
					},
					Version: 1,
				})
				if tc.expected.err != nil {
					require.ErrorIs(t, err, tc.expected.err)
					return
				}
				require.NoError(t, err)

				wantIds := []string{hosts[0].PublicId, hosts[1].PublicId, hosts[2].PublicId}
				require.ElementsMatch(t, wantIds, got.Item.HostIds)

				// check if the output fields are as expected
				require.NoError(t, err)
				handlers.TestAssertOutputFields(t, got.Item, tc.expected.outputFields)
			})
		}
	})
}
