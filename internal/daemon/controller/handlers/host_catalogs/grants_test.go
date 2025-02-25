// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package host_catalogs_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
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
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
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
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	sche := scheduler.TestScheduler(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
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

	hcs := static.TestCatalogs(t, conn, proj.GetPublicId(), 5)
	var wantHcs []string
	for _, h := range hcs {
		wantHcs = append(wantHcs, h.GetPublicId())
	}

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name     string
			input    *pbs.ListHostCatalogsRequest
			userFunc func() (user *iam.User, account auth.Account)
			wantErr  error
			wantIDs  []string
		}{
			{
				name: "direct association - global role with host-catalog type, list, read actions, grant scope: this and descendants returns all created host catalogs",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host-catalog;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantErr: nil,
				wantIDs: wantHcs,
			},
			{
				name: "group association - global role with host-catalog type, list, read actions, grant scope: this and descendants returns all created host catalogs",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=host-catalog;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				wantIDs: wantHcs,
			},
			{
				name: "managed group association - global role with host-catalog type, list, read actions, grant scope: this and descendants returns all created host catalogs",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host-catalog;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantErr: nil,
				wantIDs: wantHcs,
			},
			{
				name: "org role with host-catalog type, list, read actions, grant scope: this and children returns all created host catalogs",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=host-catalog;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				wantIDs: wantHcs,
			},
			{
				name: "org role with host-catalog type, list, read actions, grant scope children returns all created host catalogs",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=host-catalog;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				wantIDs: wantHcs,
			},
			{
				name: "project role with host-catalog type, list, read actions, grant scope: this returns all created host catalogs",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=host-catalog;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: wantHcs,
			},
			{
				name: "project role with host-catalog type, list action, grant scope: this returns all created host catalogs",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=host-catalog;actions=no-op,list"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: wantHcs,
			},
			{
				name: "project role with non-applicable type, list and no-op actions, grant scope: this returns forbidden error",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=host-catalog;actions=no-op,list"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantIDs: nil,
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
			})
		}
	})

	t.Run("Get", func(t *testing.T) {
		testcases := []struct {
			name            string
			userFunc        func() (user *iam.User, account auth.Account)
			inputWantErrMap map[*pbs.GetHostCatalogRequest]error
			wantErr         error
		}{
			{
				name: "direct association - project role with id, host-catalog type, read action, grant scope: this returns host catalog",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + hcs[2].GetPublicId() + ";type=host-catalog;actions=read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputWantErrMap: map[*pbs.GetHostCatalogRequest]error{
					{Id: hcs[0].GetPublicId()}: handlers.ForbiddenError(),
					{Id: hcs[1].GetPublicId()}: handlers.ForbiddenError(),
					{Id: hcs[2].GetPublicId()}: nil,
					{Id: hcs[3].GetPublicId()}: handlers.ForbiddenError(),
					{Id: hcs[4].GetPublicId()}: handlers.ForbiddenError(),
				},
			},
			{
				name: "group association - global role with id, host-catalog type, read action, grant scope: this and descendants returns host catalog",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=" + hcs[0].GetPublicId() + ";type=host-catalog;actions=read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				inputWantErrMap: map[*pbs.GetHostCatalogRequest]error{
					{Id: hcs[0].GetPublicId()}: nil,
					{Id: hcs[1].GetPublicId()}: handlers.ForbiddenError(),
					{Id: hcs[2].GetPublicId()}: handlers.ForbiddenError(),
					{Id: hcs[3].GetPublicId()}: handlers.ForbiddenError(),
					{Id: hcs[4].GetPublicId()}: handlers.ForbiddenError(),
				},
			},
			{
				name: "direct association - global role with host-catalog type, read action, grant scope: descendants returns host catalog",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host-catalog;actions=read"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				inputWantErrMap: map[*pbs.GetHostCatalogRequest]error{
					{Id: hcs[0].GetPublicId()}: nil,
					{Id: hcs[1].GetPublicId()}: nil,
					{Id: hcs[2].GetPublicId()}: nil,
					{Id: hcs[3].GetPublicId()}: nil,
					{Id: hcs[4].GetPublicId()}: nil,
				},
			},
			{
				name: "org role with host-catalog type, read action, grant scope: children returns host catalog",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=host-catalog;actions=read"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				inputWantErrMap: map[*pbs.GetHostCatalogRequest]error{
					{Id: hcs[0].GetPublicId()}: nil,
					{Id: hcs[1].GetPublicId()}: nil,
					{Id: hcs[2].GetPublicId()}: nil,
					{Id: hcs[3].GetPublicId()}: nil,
					{Id: hcs[4].GetPublicId()}: nil,
				},
			},
			{
				name: "project role with host-catalog type, read action, grant scope: this returns host catalog",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=host-catalog;actions=read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputWantErrMap: map[*pbs.GetHostCatalogRequest]error{
					{Id: hcs[0].GetPublicId()}: nil,
					{Id: hcs[1].GetPublicId()}: nil,
					{Id: hcs[2].GetPublicId()}: nil,
					{Id: hcs[3].GetPublicId()}: nil,
					{Id: hcs[4].GetPublicId()}: nil,
				},
			},
			{
				name: "project role with host-catalog type, update action, grant scope: this returns forbidden error",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=host-catalog;actions=update"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputWantErrMap: map[*pbs.GetHostCatalogRequest]error{
					{Id: hcs[0].GetPublicId()}: handlers.ForbiddenError(),
					{Id: hcs[1].GetPublicId()}: handlers.ForbiddenError(),
					{Id: hcs[2].GetPublicId()}: handlers.ForbiddenError(),
					{Id: hcs[3].GetPublicId()}: handlers.ForbiddenError(),
					{Id: hcs[4].GetPublicId()}: handlers.ForbiddenError(),
				},
			},
			{
				name: "union multiple grants returns a subset of all host catalogs",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + hcs[0].GetPublicId() + ";type=host-catalog;actions=read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=" + hcs[2].GetPublicId() + ";type=host-catalog;actions=read"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=" + hcs[3].GetPublicId() + ";type=host-catalog;actions=read"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				inputWantErrMap: map[*pbs.GetHostCatalogRequest]error{
					{Id: hcs[0].GetPublicId()}: nil,
					{Id: hcs[1].GetPublicId()}: handlers.ForbiddenError(),
					{Id: hcs[2].GetPublicId()}: nil,
					{Id: hcs[3].GetPublicId()}: nil,
					{Id: hcs[4].GetPublicId()}: handlers.ForbiddenError(),
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
					_, err := s.GetHostCatalog(fullGrantAuthCtx, input)
					if wantErr != nil {
						require.ErrorIs(t, err, wantErr)
						continue
					}
					require.NoError(t, err)
				}
			})
		}
	})
}
