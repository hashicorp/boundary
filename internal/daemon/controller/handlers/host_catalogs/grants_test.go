// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package host_catalogs_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
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
			name          string
			input         *pbs.ListHostCatalogsRequest
			rolesToCreate []authtoken.TestRoleGrantsForToken
			wantErr       error
			wantIDs       []string
		}{
			{
				name: "global role grant this returns all created host catalogs",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=host-catalog;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				},
				wantErr: nil,
				wantIDs: wantHcs,
			},
			{
				name: "org role grant this returns all created host catalogs",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  org.PublicId,
						GrantStrings: []string{"ids=*;type=host-catalog;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
				wantErr: nil,
				wantIDs: wantHcs,
			},
			{
				name: "project role grant this returns all created host catalogs",
				input: &pbs.ListHostCatalogsRequest{
					ScopeId:   proj.GetPublicId(),
					Recursive: true,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  proj.PublicId,
						GrantStrings: []string{"ids=*;type=host-catalog;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis},
					},
				},
				wantErr: nil,
				wantIDs: wantHcs,
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				tok := authtoken.TestAuthTokenWithRoles(t, conn, kmsCache, globals.GlobalPrefix, tc.rolesToCreate)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
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
}
