// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package host_catalogs_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/authtoken"
	cauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/host_catalogs"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host"
	hostplugin "github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/types/resource"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
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
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	sche := scheduler.TestScheduler(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kmsCache)
	}
	pluginHostRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kmsCache, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	pluginRepoFn := func() (*plugin.Repository, error) {
		return plugin.NewRepository(ctx, rw, rw, kmsCache)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrap), nil
	}
	catalogServiceFn := func() (*host.CatalogRepository, error) {
		return host.NewCatalogRepository(ctx, rw, rw)
	}
	s, err := host_catalogs.NewService(ctx, staticRepoFn, pluginHostRepoFn, pluginRepoFn, iamRepoFn, catalogServiceFn, 1000)
	require.NoError(t, err)

	org, proj := iam.TestScopes(t, iamRepo)
	catalogTypeMap := map[string]string{}

	var allHcs []string
	for range 5 {
		hc := static.TestCatalog(t, conn, proj.PublicId)
		catalogTypeMap[hc.PublicId] = "static"
		allHcs = append(allHcs, hc.GetPublicId())
	}

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name                  string
			input                 *pbs.ListHostCatalogsRequest
			userFunc              func() (user *iam.User, account auth.Account)
			wantErr               error
			wantIDs               []string
			expectOutfieldsByType map[string][]string
		}{
			{
				name: "direct association - global role with host-catalog type, list, read actions, grant scope: this and descendants returns all created host catalogs",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host-catalog;actions=list,read;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantErr: nil,
				wantIDs: allHcs,
				expectOutfieldsByType: map[string][]string{
					"static": {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					"plugin": {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
				},
			},
			{
				name: "group association - global role with host-catalog type, list, read actions, grant scope: this and descendants returns all created host catalogs",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host-catalog;actions=list,read;output_fields=id,scope_id,type"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantIDs: allHcs,
				expectOutfieldsByType: map[string][]string{
					"static": {globals.IdField, globals.ScopeIdField, globals.TypeField},
					"plugin": {globals.IdField, globals.ScopeIdField, globals.TypeField},
				},
			},
			{
				name: "managed group association - global role with host-catalog type, list, read actions, grant scope: this and descendants returns all created host catalogs",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host-catalog;actions=list,read;output_fields=id,attributes"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantIDs: allHcs,
				expectOutfieldsByType: map[string][]string{
					"static": {globals.IdField},
					"plugin": {globals.IdField, globals.AttributesField},
				},
			},
			{
				name: "org role with host-catalog type, list, read actions, grant scope: this and children returns all created host catalogs",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   org.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=host-catalog;actions=list,read;output_fields=id,authorized_actions,secrets_hmac,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantIDs: allHcs,
				expectOutfieldsByType: map[string][]string{
					"static": {globals.IdField, globals.AuthorizedActionsField, globals.CreatedTimeField, globals.UpdatedTimeField},
					"plugin": {globals.IdField, globals.AuthorizedActionsField, globals.SecretsHmacField, globals.CreatedTimeField, globals.UpdatedTimeField},
				},
			},
			{
				name: "org role with host-catalog type, list, read actions, grant scope children returns all created host catalogs",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=host-catalog;actions=list,read;output_fields=id,type"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				wantIDs: allHcs,
				expectOutfieldsByType: map[string][]string{
					"static": {globals.IdField, globals.TypeField},
					"plugin": {globals.IdField, globals.TypeField},
				},
			},
			{
				name: "project role with host-catalog type, list, read actions, grant scope: this returns all created host catalogs",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=host-catalog;actions=list,read;output_fields=id,type"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantIDs: allHcs,
				expectOutfieldsByType: map[string][]string{
					"static": {globals.IdField, globals.TypeField},
					"plugin": {globals.IdField, globals.TypeField},
				},
			},
			{
				name: "project role with host-catalog type, list action, grant scope: does not return any host catalogs",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=host-catalog;actions=list"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantIDs: nil,
			},
			{
				name: "project role with host-catalog type, list and no-op actions, grant scope: this returns all created host catalogs",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=host-catalog;actions=no-op,list;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantIDs: allHcs,
				expectOutfieldsByType: map[string][]string{
					"static": {globals.IdField},
					"plugin": {globals.IdField},
				},
			},
			{
				name: "project role with non-applicable type, list and no-op actions, grant scope: this returns forbidden error",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=host;actions=no-op,list"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "global role with host-catalog type, list and no-op actions, grant scope: children returns forbidden error",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host-catalog;actions=no-op,list"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				wantIDs: nil,
			},
			{
				name: "org role with host-catalog type, list and no-op actions, grant scope: this returns forbidden error",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=host-catalog;actions=no-op,list"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantIDs: nil,
			},
			{
				name: "role with no grant",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, nil),
				wantErr:  handlers.ForbiddenError(),
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, finalErr := s.ListHostCatalogs(fullGrantAuthCtx, tc.input)
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
				for _, item := range got.Items {
					catalogType := catalogTypeMap[item.Id]
					handlers.TestAssertOutputFields(t, item, tc.expectOutfieldsByType[catalogType])
				}
			})
		}
	})

	t.Run("Get", func(t *testing.T) {
		testcases := []struct {
			name            string
			userFunc        func() (user *iam.User, account auth.Account)
			inputWantErrMap map[*pbs.GetHostCatalogRequest]error
			wantErr         error
			expectOutfields []string
		}{
			{
				name: "direct association - project role with id, host-catalog type, read action, grant scope: this returns host catalog",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + allHcs[2] + ";type=host-catalog;actions=read;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputWantErrMap: map[*pbs.GetHostCatalogRequest]error{
					{Id: allHcs[0]}: handlers.ForbiddenError(),
					{Id: allHcs[1]}: handlers.ForbiddenError(),
					{Id: allHcs[2]}: nil,
					{Id: allHcs[3]}: handlers.ForbiddenError(),
					{Id: allHcs[4]}: handlers.ForbiddenError(),
				},
				expectOutfields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
			},
			{
				name: "group association - global role with id, host-catalog type, read action, grant scope: this and descendants returns host catalog",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=" + allHcs[0] + ";type=host-catalog;actions=read;output_fields=id,scope_id,type"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				inputWantErrMap: map[*pbs.GetHostCatalogRequest]error{
					{Id: allHcs[0]}: nil,
					{Id: allHcs[1]}: handlers.ForbiddenError(),
					{Id: allHcs[2]}: handlers.ForbiddenError(),
					{Id: allHcs[3]}: handlers.ForbiddenError(),
					{Id: allHcs[4]}: handlers.ForbiddenError(),
				},
				expectOutfields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField},
			},
			{
				name: "direct association - global role with host-catalog type, read action, grant scope: descendants returns host catalog",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host-catalog;actions=read;output_fields=id,type"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				inputWantErrMap: map[*pbs.GetHostCatalogRequest]error{
					{Id: allHcs[0]}: nil,
					{Id: allHcs[1]}: nil,
					{Id: allHcs[2]}: nil,
					{Id: allHcs[3]}: nil,
					{Id: allHcs[4]}: nil,
				},
				expectOutfields: []string{globals.IdField, globals.TypeField},
			},
			{
				name: "org role with host-catalog type, read action, grant scope: children returns host catalog",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=host-catalog;actions=read;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				inputWantErrMap: map[*pbs.GetHostCatalogRequest]error{
					{Id: allHcs[0]}: nil,
					{Id: allHcs[1]}: nil,
					{Id: allHcs[2]}: nil,
					{Id: allHcs[3]}: nil,
					{Id: allHcs[4]}: nil,
				},
				expectOutfields: []string{globals.IdField},
			},
			{
				name: "project role with host-catalog type, read action, grant scope: this returns host catalog",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=host-catalog;actions=read;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputWantErrMap: map[*pbs.GetHostCatalogRequest]error{
					{Id: allHcs[0]}: nil,
					{Id: allHcs[1]}: nil,
					{Id: allHcs[2]}: nil,
					{Id: allHcs[3]}: nil,
					{Id: allHcs[4]}: nil,
				},
				expectOutfields: []string{globals.IdField},
			},
			{
				name: "project role with host-catalog type, update action, grant scope: this returns forbidden error",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=host-catalog;actions=update"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputWantErrMap: map[*pbs.GetHostCatalogRequest]error{
					{Id: allHcs[0]}: handlers.ForbiddenError(),
					{Id: allHcs[1]}: handlers.ForbiddenError(),
					{Id: allHcs[2]}: handlers.ForbiddenError(),
					{Id: allHcs[3]}: handlers.ForbiddenError(),
					{Id: allHcs[4]}: handlers.ForbiddenError(),
				},
			},
			{
				name: "union multiple grants returns a subset of all host catalogs",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + allHcs[0] + ";type=host-catalog;actions=read;output_fields=id,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + allHcs[0] + ";type=host-catalog;actions=read;output_fields=scope_id,type"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=" + allHcs[2] + ";type=host-catalog;actions=read;output_fields=id,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=" + allHcs[2] + ";type=host-catalog;actions=read;output_fields=scope_id,type"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=" + allHcs[3] + ";type=host-catalog;actions=read;output_fields=id,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + allHcs[3] + ";type=host-catalog;actions=read;output_fields=scope_id,type"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputWantErrMap: map[*pbs.GetHostCatalogRequest]error{
					{Id: allHcs[0]}: nil,
					{Id: allHcs[1]}: handlers.ForbiddenError(),
					{Id: allHcs[2]}: nil,
					{Id: allHcs[3]}: nil,
					{Id: allHcs[4]}: handlers.ForbiddenError(),
				},
				expectOutfields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
			},
			{
				name:     "no grants can't read host catalogs",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, nil),
				inputWantErrMap: map[*pbs.GetHostCatalogRequest]error{
					{Id: allHcs[0]}: handlers.ForbiddenError(),
					{Id: allHcs[1]}: handlers.ForbiddenError(),
					{Id: allHcs[2]}: handlers.ForbiddenError(),
					{Id: allHcs[3]}: handlers.ForbiddenError(),
					{Id: allHcs[4]}: handlers.ForbiddenError(),
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				for input, wantErr := range tc.inputWantErrMap {
					got, err := s.GetHostCatalog(fullGrantAuthCtx, input)
					if wantErr != nil {
						require.ErrorIs(t, err, wantErr)
						continue
					}
					require.NoError(t, err)
					handlers.TestAssertOutputFields(t, got.Item, tc.expectOutfields)
				}
			})
		}
	})

	t.Run("authorized action", func(t *testing.T) {
		user, account := iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
			{
				RoleScopeId: globals.GlobalPrefix,
				Grants:      []string{"ids=*;type=host-catalog;actions=*"},
				GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
			},
			{
				RoleScopeId: globals.GlobalPrefix,
				Grants:      []string{"ids=*;type=host;actions=*"},
				GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
			},
			{
				RoleScopeId: globals.GlobalPrefix,
				Grants:      []string{"ids=*;type=host-set;actions=*"},
				GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
			},
		})()
		tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
		require.NoError(t, err)
		fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
		got, err := s.ListHostCatalogs(fullGrantAuthCtx, &pbs.ListHostCatalogsRequest{
			ScopeId:   globals.GlobalPrefix,
			Recursive: true,
		})
		require.NoError(t, err)
		for _, item := range got.Items {
			switch item.GetType() {
			case "static":
				require.ElementsMatch(t, item.AuthorizedActions, []string{"no-op", "read", "update", "delete"})
				require.Len(t, item.AuthorizedCollectionActions, 2)
				require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.HostSet.PluralString()].AsSlice(), []string{"create", "list"})
				require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Host.PluralString()].AsSlice(), []string{"create", "list"})
			case "plugin":
				require.ElementsMatch(t, item.AuthorizedActions, []string{"no-op", "read", "update", "delete"})
				require.Len(t, item.AuthorizedCollectionActions, 2)
				require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.HostSet.PluralString()].AsSlice(), []string{"create", "list"})
				require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Host.PluralString()].AsSlice(), []string{"list"})
			default:
				t.Fatalf("unknown subtype: %s", item.GetType())
			}
		}
	})
}

func TestGrants_WriteActions(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		ctx := context.Background()
		conn, _ := db.TestSetup(t, "postgres")
		wrap := db.TestWrapper(t)
		rw := db.New(conn)
		iamRepo := iam.TestRepo(t, conn, wrap)
		kmsCache := kms.TestKms(t, conn, wrap)
		sche := scheduler.TestScheduler(t, conn, wrap)
		atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		staticRepoFn := func() (*static.Repository, error) {
			return static.NewRepository(ctx, rw, rw, kmsCache)
		}
		pluginHostRepoFn := func() (*hostplugin.Repository, error) {
			return hostplugin.NewRepository(ctx, rw, rw, kmsCache, sche, map[string]plgpb.HostPluginServiceClient{})
		}
		pluginRepoFn := func() (*plugin.Repository, error) {
			return plugin.NewRepository(ctx, rw, rw, kmsCache)
		}
		iamRepoFn := func() (*iam.Repository, error) {
			return iam.TestRepo(t, conn, wrap), nil
		}
		catalogServiceFn := func() (*host.CatalogRepository, error) {
			return host.NewCatalogRepository(ctx, rw, rw)
		}
		s, err := host_catalogs.NewService(ctx, staticRepoFn, pluginHostRepoFn, pluginRepoFn, iamRepoFn, catalogServiceFn, 1000)
		require.NoError(t, err)

		org, proj := iam.TestScopes(t, iamRepo)
		proj2 := iam.TestProject(t, iamRepo, org.GetPublicId())

		testcases := []struct {
			name              string
			userFunc          func() (userId *iam.User, account auth.Account)
			canCreateInScopes map[*pbs.CreateHostCatalogRequest]error
			expectOutfields   []string
		}{
			{
				name: "direct grant with wildcard can create host catalog in project",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"id=*;type=*;actions=*;output_fields=id,name"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canCreateInScopes: map[*pbs.CreateHostCatalogRequest]error{
					{Item: &pb.HostCatalog{ScopeId: proj.PublicId, Type: "static", Name: &wrapperspb.StringValue{Value: "hc-direct-test-1"}}}:  nil,
					{Item: &pb.HostCatalog{ScopeId: proj2.PublicId, Type: "static", Name: &wrapperspb.StringValue{Value: "hc-direct-test-2"}}}: handlers.ForbiddenError(),
				},
				expectOutfields: []string{globals.IdField, globals.NameField},
			},
			{
				name: "groups grant with wildcard can create host catalog in project",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj2.PublicId,
						Grants:      []string{"id=*;type=*;actions=*;output_fields=id,name"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canCreateInScopes: map[*pbs.CreateHostCatalogRequest]error{
					{Item: &pb.HostCatalog{ScopeId: proj.PublicId, Type: "static", Name: &wrapperspb.StringValue{Value: "hc-group-test-1"}}}:  handlers.ForbiddenError(),
					{Item: &pb.HostCatalog{ScopeId: proj2.PublicId, Type: "static", Name: &wrapperspb.StringValue{Value: "hc-group-test-2"}}}: nil,
				},
				expectOutfields: []string{globals.IdField, globals.NameField},
			},
			{
				name: "ldap grant with wildcard can create host catalog in project",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"id=*;type=*;actions=*;output_fields=id,name"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canCreateInScopes: map[*pbs.CreateHostCatalogRequest]error{
					{Item: &pb.HostCatalog{ScopeId: proj.PublicId, Type: "static", Name: &wrapperspb.StringValue{Value: "hc-ldap-test-1"}}}:  nil,
					{Item: &pb.HostCatalog{ScopeId: proj2.PublicId, Type: "static", Name: &wrapperspb.StringValue{Value: "hc-ldap-test-2"}}}: handlers.ForbiddenError(),
				},
				expectOutfields: []string{globals.IdField, globals.NameField},
			},
			{
				name: "global role - descendant grant with host-catalog type can create host catalog in project",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=host-catalog;actions=*;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				canCreateInScopes: map[*pbs.CreateHostCatalogRequest]error{
					{Item: &pb.HostCatalog{ScopeId: proj.PublicId, Type: "static"}}:  nil,
					{Item: &pb.HostCatalog{ScopeId: proj2.PublicId, Type: "static"}}: nil,
				},
				expectOutfields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
			},
			{
				name: "global role - individual project id grant with host-catalog type can create host catalog in the specified project only",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=host-catalog;actions=*;output_fields=id,scope_id,type,created_time,updated_time"},
						GrantScopes: []string{proj2.PublicId},
					},
				}),
				canCreateInScopes: map[*pbs.CreateHostCatalogRequest]error{
					{Item: &pb.HostCatalog{ScopeId: proj.PublicId, Type: "static"}}:  handlers.ForbiddenError(),
					{Item: &pb.HostCatalog{ScopeId: proj2.PublicId, Type: "static"}}: nil,
				},
				expectOutfields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
			},
			{
				name: "org role - children grant with host-catalog type can create host catalog in all its child projects",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"id=*;type=host-catalog;actions=*;output_fields=id,scope_id,type"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				canCreateInScopes: map[*pbs.CreateHostCatalogRequest]error{
					{Item: &pb.HostCatalog{ScopeId: proj.PublicId, Type: "static"}}:  nil,
					{Item: &pb.HostCatalog{ScopeId: proj2.PublicId, Type: "static"}}: nil,
				},
				expectOutfields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField},
			},
			{
				name: "org role - individual project id grant with host-catalog type can create host catalog in the specified project only",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"id=*;type=host-catalog;actions=*;output_fields=id,scope_id,type"},
						GrantScopes: []string{proj2.PublicId},
					},
				}),
				canCreateInScopes: map[*pbs.CreateHostCatalogRequest]error{
					{Item: &pb.HostCatalog{ScopeId: proj.PublicId, Type: "static"}}:  handlers.ForbiddenError(),
					{Item: &pb.HostCatalog{ScopeId: proj2.PublicId, Type: "static"}}: nil,
				},
				expectOutfields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField},
			},
			{
				name: "direct grant with host-catalog type, create action, grant scope: this can create host catalog in project",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"id=*;type=host-catalog;actions=create;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canCreateInScopes: map[*pbs.CreateHostCatalogRequest]error{
					{Item: &pb.HostCatalog{ScopeId: proj.PublicId, Type: "static"}}:  nil,
					{Item: &pb.HostCatalog{ScopeId: proj2.PublicId, Type: "static"}}: handlers.ForbiddenError(),
				},
				expectOutfields: []string{globals.IdField},
			},
			{
				name: "direct grant with host-catalog type, update action, grant scope: this can create host catalog in project",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"id=*;type=host-catalog;actions=update"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canCreateInScopes: map[*pbs.CreateHostCatalogRequest]error{
					{Item: &pb.HostCatalog{ScopeId: proj.PublicId, Type: "static"}}:  handlers.ForbiddenError(),
					{Item: &pb.HostCatalog{ScopeId: proj2.PublicId, Type: "static"}}: handlers.ForbiddenError(),
				},
			},
			{
				name: "grant children can only create in orgs",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=host-catalog;actions=*"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				canCreateInScopes: map[*pbs.CreateHostCatalogRequest]error{
					{Item: &pb.HostCatalog{ScopeId: proj.PublicId, Type: "static"}}:  handlers.ForbiddenError(),
					{Item: &pb.HostCatalog{ScopeId: proj2.PublicId, Type: "static"}}: handlers.ForbiddenError(),
				},
			},
			{
				name:     "no grants can't create in any scope",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, nil),
				canCreateInScopes: map[*pbs.CreateHostCatalogRequest]error{
					{Item: &pb.HostCatalog{ScopeId: proj.PublicId, Type: "static"}}:  handlers.ForbiddenError(),
					{Item: &pb.HostCatalog{ScopeId: proj2.PublicId, Type: "static"}}: handlers.ForbiddenError(),
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				for req, wantErr := range tc.canCreateInScopes {
					got, err := s.CreateHostCatalog(fullGrantAuthCtx, req)
					if wantErr != nil {
						require.ErrorIs(t, err, wantErr)
						continue
					}
					require.NoError(t, err)
					handlers.TestAssertOutputFields(t, got.Item, tc.expectOutfields)
				}
			})
		}
	})

	t.Run("update", func(t *testing.T) {
		ctx := context.Background()
		conn, _ := db.TestSetup(t, "postgres")
		wrap := db.TestWrapper(t)
		rw := db.New(conn)
		iamRepo := iam.TestRepo(t, conn, wrap)
		kmsCache := kms.TestKms(t, conn, wrap)
		sche := scheduler.TestScheduler(t, conn, wrap)
		atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		staticRepoFn := func() (*static.Repository, error) {
			return static.NewRepository(ctx, rw, rw, kmsCache)
		}
		pluginHostRepoFn := func() (*hostplugin.Repository, error) {
			return hostplugin.NewRepository(ctx, rw, rw, kmsCache, sche, map[string]plgpb.HostPluginServiceClient{})
		}
		pluginRepoFn := func() (*plugin.Repository, error) {
			return plugin.NewRepository(ctx, rw, rw, kmsCache)
		}
		iamRepoFn := func() (*iam.Repository, error) {
			return iam.TestRepo(t, conn, wrap), nil
		}
		catalogServiceFn := func() (*host.CatalogRepository, error) {
			return host.NewCatalogRepository(ctx, rw, rw)
		}
		s, err := host_catalogs.NewService(ctx, staticRepoFn, pluginHostRepoFn, pluginRepoFn, iamRepoFn, catalogServiceFn, 1000)
		require.NoError(t, err)

		org, proj := iam.TestScopes(t, iamRepo)

		testcases := []struct {
			name                        string
			setupScopesResourcesAndUser func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*static.HostCatalog, func() (userId *iam.User, account auth.Account))
			wantErr                     error
			expectOutfields             []string
		}{
			{
				name: "direct grant with wildcard can update host catalog in project",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*static.HostCatalog, func() (userId *iam.User, account auth.Account)) {
					hc := static.TestCatalogs(t, conn, proj.PublicId, 1)[0]
					return hc, iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
						{
							RoleScopeId: proj.PublicId,
							Grants:      []string{"id=*;type=*;actions=*;output_fields=id,name,updated_time,version"},
							GrantScopes: []string{globals.GrantScopeThis},
						},
					})
				},
				wantErr:         nil,
				expectOutfields: []string{globals.IdField, globals.NameField, globals.UpdatedTimeField, globals.VersionField},
			},
			{
				name: "global role - direct grant with grant_scope project can update host catalog in project",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*static.HostCatalog, func() (userId *iam.User, account auth.Account)) {
					hc := static.TestCatalogs(t, conn, proj.PublicId, 1)[0]
					return hc, iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
						{
							RoleScopeId: globals.GlobalPrefix,
							Grants:      []string{"ids=*;type=host-catalog;actions=*;output_fields=id,name,description,updated_time,version"},
							GrantScopes: []string{proj.PublicId},
						},
					})
				},
				wantErr:         nil,
				expectOutfields: []string{globals.IdField, globals.NameField, globals.DescriptionField, globals.UpdatedTimeField, globals.VersionField},
			},
			{
				name: "grant with specific resource and scope can update host catalog in project",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*static.HostCatalog, func() (userId *iam.User, account auth.Account)) {
					hc := static.TestCatalogs(t, conn, proj.PublicId, 1)[0]
					return hc, iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
						{
							RoleScopeId: org.PublicId,
							Grants:      []string{fmt.Sprintf("ids=%s;types=host-catalog;actions=*;output_fields=id,scope_id,type,name,description,created_time,updated_time,version", hc.PublicId)},
							GrantScopes: []string{proj.PublicId},
						},
					})
				},
				wantErr: nil,
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeIdField,
					globals.TypeField,
					globals.NameField,
					globals.VersionField,
					globals.DescriptionField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
				},
			},
			{
				name: "non applicable grant returns forbidden error",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*static.HostCatalog, func() (userId *iam.User, account auth.Account)) {
					hc := static.TestCatalogs(t, conn, proj.PublicId, 1)[0]
					return hc, iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
						{
							RoleScopeId: globals.GlobalPrefix,
							Grants:      []string{"id=*;type=*;actions=*"},
							GrantScopes: []string{globals.GrantScopeChildren},
						},
					})
				},
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "no grants returns forbidden error",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*static.HostCatalog, func() (userId *iam.User, account auth.Account)) {
					hc := static.TestCatalogs(t, conn, proj.PublicId, 1)[0]
					return hc, iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, nil)
				},
				wantErr: handlers.ForbiddenError(),
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				original, userFunc := tc.setupScopesResourcesAndUser(t, conn, iamRepo, kmsCache)
				user, account := userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, err := s.UpdateHostCatalog(fullGrantAuthCtx, &pbs.UpdateHostCatalogRequest{
					Id: original.PublicId,
					Item: &pb.HostCatalog{
						Name:        &wrapperspb.StringValue{Value: "new-name-" + original.PublicId},
						Description: &wrapperspb.StringValue{Value: "new-description"},
						Version:     1,
					},
					UpdateMask: &fieldmaskpb.FieldMask{
						Paths: []string{"name", "description"},
					},
				})
				if tc.wantErr != nil {
					require.Error(t, err)
					require.ErrorIs(t, err, tc.wantErr)
					return
				}
				require.NoError(t, err)
				require.Equal(t, uint32(2), got.Item.Version)
				require.True(t, got.Item.UpdatedTime.AsTime().After(original.UpdateTime.AsTime()))
				handlers.TestAssertOutputFields(t, got.Item, tc.expectOutfields)
			})
		}
	})

	t.Run("delete", func(t *testing.T) {
		ctx := context.Background()
		conn, _ := db.TestSetup(t, "postgres")
		wrap := db.TestWrapper(t)
		rw := db.New(conn)
		iamRepo := iam.TestRepo(t, conn, wrap)
		kmsCache := kms.TestKms(t, conn, wrap)
		sche := scheduler.TestScheduler(t, conn, wrap)
		atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		staticRepoFn := func() (*static.Repository, error) {
			return static.NewRepository(ctx, rw, rw, kmsCache)
		}
		pluginHostRepoFn := func() (*hostplugin.Repository, error) {
			return hostplugin.NewRepository(ctx, rw, rw, kmsCache, sche, map[string]plgpb.HostPluginServiceClient{})
		}
		pluginRepoFn := func() (*plugin.Repository, error) {
			return plugin.NewRepository(ctx, rw, rw, kmsCache)
		}
		iamRepoFn := func() (*iam.Repository, error) {
			return iam.TestRepo(t, conn, wrap), nil
		}
		catalogServiceFn := func() (*host.CatalogRepository, error) {
			return host.NewCatalogRepository(ctx, rw, rw)
		}
		s, err := host_catalogs.NewService(ctx, staticRepoFn, pluginHostRepoFn, pluginRepoFn, iamRepoFn, catalogServiceFn, 1000)
		require.NoError(t, err)

		org, proj := iam.TestScopes(t, iamRepo)

		testcases := []struct {
			name                        string
			setupScopesResourcesAndUser func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*static.HostCatalog, func() (user *iam.User, account auth.Account))
			wantErr                     error
		}{
			{
				name: "direct grant with wildcard can delete host catalog in project",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*static.HostCatalog, func() (user *iam.User, account auth.Account)) {
					hc := static.TestCatalogs(t, conn, proj.PublicId, 1)[0]
					return hc, iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
						{
							RoleScopeId: proj.PublicId,
							Grants:      []string{"id=*;type=*;actions=*"},
							GrantScopes: []string{globals.GrantScopeThis},
						},
					})
				},
				wantErr: nil,
			},
			{
				name: "direct grant with type: host-catalog can delete host catalog in project",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*static.HostCatalog, func() (user *iam.User, account auth.Account)) {
					hc := static.TestCatalogs(t, conn, proj.PublicId, 1)[0]
					return hc, iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
						{
							RoleScopeId: proj.PublicId,
							Grants:      []string{"id=*;type=host-catalog;actions=*"},
							GrantScopes: []string{globals.GrantScopeThis},
						},
					})
				},
				wantErr: nil,
			},
			{
				name: "direct grant with type: host-catalog, update action can delete host catalog in project",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*static.HostCatalog, func() (user *iam.User, account auth.Account)) {
					hc := static.TestCatalogs(t, conn, proj.PublicId, 1)[0]
					return hc, iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
						{
							RoleScopeId: proj.PublicId,
							Grants:      []string{"id=*;type=host-catalog;actions=delete"},
							GrantScopes: []string{globals.GrantScopeThis},
						},
					})
				},
				wantErr: nil,
			},
			{
				name: "direct grant with global scope, descendants grants scope, host-catalog type, delete action can delete host catalog in project",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*static.HostCatalog, func() (user *iam.User, account auth.Account)) {
					hc := static.TestCatalogs(t, conn, proj.PublicId, 1)[0]
					return hc, iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
						{
							RoleScopeId: globals.GlobalPrefix,
							Grants:      []string{"id=*;type=host-catalog;actions=delete"},
							GrantScopes: []string{globals.GrantScopeDescendants},
						},
					})
				},
				wantErr: nil,
			},
			{
				name: "direct grant with org scope, children grants scope, host-catalog type, delete action can delete host catalog in project",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*static.HostCatalog, func() (user *iam.User, account auth.Account)) {
					hc := static.TestCatalogs(t, conn, proj.PublicId, 1)[0]
					return hc, iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
						{
							RoleScopeId: org.PublicId,
							Grants:      []string{"id=*;type=host-catalog;actions=delete"},
							GrantScopes: []string{globals.GrantScopeChildren},
						},
					})
				},
				wantErr: nil,
			},
			{
				name: "direct grant with non-applicable grant scope returns forbidden error",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*static.HostCatalog, func() (user *iam.User, account auth.Account)) {
					hc := static.TestCatalogs(t, conn, proj.PublicId, 1)[0]
					return hc, iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
						{
							RoleScopeId: proj.PublicId,
							Grants:      []string{"id=*;type=host-catalog;actions=update"},
							GrantScopes: []string{globals.GrantScopeThis},
						},
					})
				},
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "direct grant with non-applicable type returns forbidden error",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*static.HostCatalog, func() (user *iam.User, account auth.Account)) {
					hc := static.TestCatalogs(t, conn, proj.PublicId, 1)[0]
					return hc, iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
						{
							RoleScopeId: proj.PublicId,
							Grants:      []string{"id=*;type=group;actions=*"},
							GrantScopes: []string{globals.GrantScopeThis},
						},
					})
				},
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "direct grant with global scope and children grant scope returns forbidden error",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*static.HostCatalog, func() (user *iam.User, account auth.Account)) {
					hc := static.TestCatalogs(t, conn, proj.PublicId, 1)[0]
					return hc, iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
						{
							RoleScopeId: globals.GlobalPrefix,
							Grants:      []string{"id=*;type=*;actions=*"},
							GrantScopes: []string{globals.GrantScopeChildren},
						},
					})
				},
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "direct grant with org scope and this grant scope returns forbidden error",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*static.HostCatalog, func() (user *iam.User, account auth.Account)) {
					hc := static.TestCatalogs(t, conn, proj.PublicId, 1)[0]
					return hc, iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
						{
							RoleScopeId: org.PublicId,
							Grants:      []string{"id=*;type=host-catalog;actions=*"},
							GrantScopes: []string{globals.GrantScopeThis},
						},
					})
				},
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "no grants returns forbidden error",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*static.HostCatalog, func() (user *iam.User, account auth.Account)) {
					hc := static.TestCatalogs(t, conn, proj.PublicId, 1)[0]
					return hc, iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, nil)
				},
				wantErr: handlers.ForbiddenError(),
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				original, userFunc := tc.setupScopesResourcesAndUser(t, conn, iamRepo, kmsCache)
				user, account := userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				_, err = s.DeleteHostCatalog(fullGrantAuthCtx, &pbs.DeleteHostCatalogRequest{Id: original.PublicId})
				if tc.wantErr != nil {
					require.Error(t, err)
					require.ErrorIs(t, err, tc.wantErr)
					return
				}
				require.NoError(t, err)
			})
		}
	})
}
