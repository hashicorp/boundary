// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package hosts_test

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	controllerauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/hosts"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	hostplugin "github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hosts"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	// StaticHostAttributes is the field name for the StaticHost subtype of the `Hosts.Attrs` attributes field
	//
	// When the "attributes" field is specified as an output_field and can be one of many sub-types, the expected output field must be the corresponding sub-type and not `globals.AttributesField`
	StaticHostAttributes = "static_host_attributes"
)

// expectedOutput consolidates common output fields for the test cases
type expectedOutput struct {
	err          error
	outputFields []string
}

func TestGrants_ReadActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	sche := scheduler.TestScheduler(t, conn, wrap)
	pluginRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kmsCache, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kmsCache)
	}
	s, err := hosts.NewService(ctx, repoFn, pluginRepoFn, 1000)
	require.NoError(t, err)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	org, proj := iam.TestScopes(t, iamRepo)
	org2, proj2 := iam.TestScopes(t, iamRepo)

	hcs := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)
	hc := hcs[0]

	hset := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	var wantHs []string
	testHosts := static.TestHosts(t, conn, hc.GetPublicId(), 5)
	static.TestSetMembers(t, conn, hset.GetPublicId(), testHosts)
	for _, h := range testHosts {
		wantHs = append(wantHs, h.GetPublicId())
	}

	hcs2 := static.TestCatalogs(t, conn, proj2.GetPublicId(), 1)
	hc2 := hcs2[0]

	hset2 := static.TestSets(t, conn, hc2.GetPublicId(), 1)[0]
	testHosts2 := static.TestHosts(t, conn, hc2.GetPublicId(), 5)
	static.TestSetMembers(t, conn, hset2.GetPublicId(), testHosts2)
	for _, h := range testHosts2 {
		wantHs = append(wantHs, h.GetPublicId())
	}

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name          string
			input         *pbs.ListHostsRequest
			userFunc      func() (*iam.User, auth.Account)
			wantErr       error
			wantIDs       []string
			wantOutfields map[string][]string
		}{
			{
				name: "global role grant this + descendants returns all created hosts in catalog 1",
				input: &pbs.ListHostsRequest{
					HostCatalogId: hc.GetPublicId(),
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host;actions=list,read;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantErr: nil,
				wantOutfields: map[string][]string{
					wantHs[0]: {globals.IdField},
					wantHs[1]: {globals.IdField},
					wantHs[2]: {globals.IdField},
					wantHs[3]: {globals.IdField},
					wantHs[4]: {globals.IdField},
				},
			},
			{
				name: "global role grant this returns 403 forbidden error because hosts live on projects",
				input: &pbs.ListHostsRequest{
					HostCatalogId: hc.GetPublicId(),
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host;actions=list,read;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "org role grant this returns 403 forbidden error because hosts live on projects",
				input: &pbs.ListHostsRequest{
					HostCatalogId: hc.GetPublicId(),
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=list,read;output_fields=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "org role grant this + children returns all created hosts in catalog 1",
				input: &pbs.ListHostsRequest{
					HostCatalogId: hc.GetPublicId(),
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=list,read;output_fields=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				wantOutfields: map[string][]string{
					wantHs[0]: {globals.IdField, globals.HostCatalogIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.HostSetIdsField, StaticHostAttributes, globals.AuthorizedActionsField},
					wantHs[1]: {globals.IdField, globals.HostCatalogIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.HostSetIdsField, StaticHostAttributes, globals.AuthorizedActionsField},
					wantHs[2]: {globals.IdField, globals.HostCatalogIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.HostSetIdsField, StaticHostAttributes, globals.AuthorizedActionsField},
					wantHs[3]: {globals.IdField, globals.HostCatalogIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.HostSetIdsField, StaticHostAttributes, globals.AuthorizedActionsField},
					wantHs[4]: {globals.IdField, globals.HostCatalogIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.HostSetIdsField, StaticHostAttributes, globals.AuthorizedActionsField},
				},
			},
			{
				name: "project role grant this returns all created hosts in catalog 1",
				input: &pbs.ListHostsRequest{
					HostCatalogId: hc.GetPublicId(),
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,created_time,updated_time,version,type,authorized_actions,attributes"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantOutfields: map[string][]string{
					wantHs[0]: {globals.IdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, StaticHostAttributes},
					wantHs[1]: {globals.IdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, StaticHostAttributes},
					wantHs[2]: {globals.IdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, StaticHostAttributes},
					wantHs[3]: {globals.IdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, StaticHostAttributes},
					wantHs[4]: {globals.IdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, StaticHostAttributes},
				},
			},
			{
				name: "project role grant this pinned id returns all created hosts in catalog 1",
				input: &pbs.ListHostsRequest{
					HostCatalogId: hc.GetPublicId(),
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + hc.PublicId + ";type=*;actions=list,read;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantOutfields: map[string][]string{
					wantHs[0]: {globals.IdField},
					wantHs[1]: {globals.IdField},
					wantHs[2]: {globals.IdField},
					wantHs[3]: {globals.IdField},
					wantHs[4]: {globals.IdField},
				},
			},
			{
				name: "project role grant this wrong pinned id returns error",
				input: &pbs.ListHostsRequest{
					HostCatalogId: hc.GetPublicId(),
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + hc2.PublicId + ";type=*;actions=list,read;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "org2 role grant this returns all created hosts in catalog 2",
				input: &pbs.ListHostsRequest{
					HostCatalogId: hc2.GetPublicId(),
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org2.PublicId,
						Grants:      []string{"ids=*;type=*;actions=list,read;output_fields=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				wantOutfields: map[string][]string{
					wantHs[5]: {globals.IdField, globals.HostCatalogIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.HostSetIdsField, StaticHostAttributes, globals.AuthorizedActionsField},
					wantHs[6]: {globals.IdField, globals.HostCatalogIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.HostSetIdsField, StaticHostAttributes, globals.AuthorizedActionsField},
					wantHs[7]: {globals.IdField, globals.HostCatalogIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.HostSetIdsField, StaticHostAttributes, globals.AuthorizedActionsField},
					wantHs[8]: {globals.IdField, globals.HostCatalogIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.HostSetIdsField, StaticHostAttributes, globals.AuthorizedActionsField},
					wantHs[9]: {globals.IdField, globals.HostCatalogIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.HostSetIdsField, StaticHostAttributes, globals.AuthorizedActionsField},
				},
			},
			{
				name: "project2 role grant this returns all created hosts in catalog 2",
				input: &pbs.ListHostsRequest{
					HostCatalogId: hc2.GetPublicId(),
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj2.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,created_time,updated_time,version,type,authorized_actions,attributes"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantOutfields: map[string][]string{
					wantHs[5]: {globals.IdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, StaticHostAttributes},
					wantHs[6]: {globals.IdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, StaticHostAttributes},
					wantHs[7]: {globals.IdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, StaticHostAttributes},
					wantHs[8]: {globals.IdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, StaticHostAttributes},
					wantHs[9]: {globals.IdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, StaticHostAttributes},
				},
			},
			{
				name: "org2 role catalog 1 returns 403 error",
				input: &pbs.ListHostsRequest{
					HostCatalogId: hc.GetPublicId(),
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org2.PublicId,
						Grants:      []string{"ids=*;type=*;actions=list,read;output_fields=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "project2 role catalog 1 returns 403 error",
				input: &pbs.ListHostsRequest{
					HostCatalogId: hc.GetPublicId(),
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj2.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,created_time,updated_time,version,type,authorized_actions,attributes"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, finalErr := s.ListHosts(fullGrantAuthCtx, tc.input)
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
			name     string
			userFunc func() (*iam.User, auth.Account)
			canGet   map[string]expectedOutput
		}{
			{
				name: "global role grant this returns 403 forbidden error because hosts live on projects",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host;actions=list,read;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canGet: map[string]expectedOutput{
					wantHs[0]: {err: handlers.ForbiddenError()},
					wantHs[1]: {err: handlers.ForbiddenError()},
					wantHs[2]: {err: handlers.ForbiddenError()},
					wantHs[3]: {err: handlers.ForbiddenError()},
					wantHs[4]: {err: handlers.ForbiddenError()},
				},
			},
			{
				name: "global role grant this + descendants returns expected",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host;actions=list,read;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				canGet: map[string]expectedOutput{
					wantHs[0]: {outputFields: []string{globals.IdField}},
					wantHs[1]: {outputFields: []string{globals.IdField}},
					wantHs[2]: {outputFields: []string{globals.IdField}},
					wantHs[3]: {outputFields: []string{globals.IdField}},
					wantHs[4]: {outputFields: []string{globals.IdField}},
				},
			},
			{
				name: "org role grant this returns 403 forbidden error because hosts live on projects",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=list,read;output_fields=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canGet: map[string]expectedOutput{
					wantHs[0]: {err: handlers.ForbiddenError()},
					wantHs[1]: {err: handlers.ForbiddenError()},
					wantHs[2]: {err: handlers.ForbiddenError()},
					wantHs[3]: {err: handlers.ForbiddenError()},
					wantHs[4]: {err: handlers.ForbiddenError()},
				},
			},
			{
				name: "org role grant this + children returns successfully for self, returns error for other org",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=list,read;output_fields=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				canGet: map[string]expectedOutput{
					wantHs[0]: {outputFields: []string{globals.IdField, globals.HostCatalogIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.HostSetIdsField, StaticHostAttributes, globals.AuthorizedActionsField}},
					wantHs[1]: {outputFields: []string{globals.IdField, globals.HostCatalogIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.HostSetIdsField, StaticHostAttributes, globals.AuthorizedActionsField}},
					wantHs[2]: {outputFields: []string{globals.IdField, globals.HostCatalogIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.HostSetIdsField, StaticHostAttributes, globals.AuthorizedActionsField}},
					wantHs[3]: {outputFields: []string{globals.IdField, globals.HostCatalogIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.HostSetIdsField, StaticHostAttributes, globals.AuthorizedActionsField}},
					wantHs[4]: {outputFields: []string{globals.IdField, globals.HostCatalogIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.HostSetIdsField, StaticHostAttributes, globals.AuthorizedActionsField}},
					wantHs[5]: {err: handlers.ForbiddenError()},
					wantHs[6]: {err: handlers.ForbiddenError()},
					wantHs[7]: {err: handlers.ForbiddenError()},
					wantHs[8]: {err: handlers.ForbiddenError()},
					wantHs[9]: {err: handlers.ForbiddenError()},
				},
			},
			{
				name: "project role grant this returns all created hosts in catalog 1",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,created_time,updated_time,version,type,authorized_actions,attributes"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canGet: map[string]expectedOutput{
					wantHs[0]: {outputFields: []string{globals.IdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, StaticHostAttributes}},
					wantHs[1]: {outputFields: []string{globals.IdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, StaticHostAttributes}},
					wantHs[2]: {outputFields: []string{globals.IdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, StaticHostAttributes}},
					wantHs[3]: {outputFields: []string{globals.IdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, StaticHostAttributes}},
					wantHs[4]: {outputFields: []string{globals.IdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, StaticHostAttributes}},
					wantHs[5]: {err: handlers.ForbiddenError()},
					wantHs[6]: {err: handlers.ForbiddenError()},
					wantHs[7]: {err: handlers.ForbiddenError()},
					wantHs[8]: {err: handlers.ForbiddenError()},
					wantHs[9]: {err: handlers.ForbiddenError()},
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				for id, expected := range tc.canGet {
					input := &pbs.GetHostRequest{
						Id: id,
					}

					got, err := s.GetHost(fullGrantAuthCtx, input)
					if expected.err != nil {
						require.ErrorIs(t, err, expected.err)
						continue
					}
					require.NoError(t, err)
					if tc.canGet[id].outputFields != nil {
						handlers.TestAssertOutputFields(t, got.Item, tc.canGet[id].outputFields)
					}
				}
			})
		}
	})
}

func TestGrants_CreateActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	org1, proj1 := iam.TestScopes(t, iamRepo)
	_, proj2 := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	pluginRepoFn := func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(ctx, rw, rw, kmsCache, sche, map[string]plgpb.HostPluginServiceClient{})
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kmsCache)
	}
	repo, err := repoFn()
	require.NoError(t, err, "Couldn't create new static repo.")

	hc := static.TestCatalogs(t, conn, proj1.GetPublicId(), 1)[0]
	hc2 := static.TestCatalogs(t, conn, proj2.GetPublicId(), 1)[0]

	s := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]

	h, err := static.NewHost(ctx, hc.GetPublicId(), static.WithName("default"), static.WithDescription("default"), static.WithAddress("defaultaddress"))
	require.NoError(t, err)
	h, err = repo.CreateHost(ctx, proj1.GetPublicId(), h)
	require.NoError(t, err)
	static.TestSetMembers(t, conn, s.GetPublicId(), []*static.Host{h})

	tested, err := hosts.NewService(ctx, repoFn, pluginRepoFn, 1000)
	require.NoError(t, err)

	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	var version uint32 = 1

	resetHost := func() {
		version++
		_, _, err = repo.UpdateHost(ctx, proj1.GetPublicId(), h, version, []string{"Name", "Description", "Address"})
		require.NoError(t, err, "Failed to reset host.")
		version++
	}

	t.Run("Create", func(t *testing.T) {
		testcases := []struct {
			name     string
			userFunc func() (*iam.User, auth.Account)
			expected expectedOutput
		}{
			{
				name: "global role grant this can't create hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "global role grant this + children can't create hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "org role grant this can't create hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=host;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "proj role grant this can create hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj1.PublicId,
						Grants:      []string{"ids=*;type=host;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField}},
			},
			{
				name: "proj role grant this pinned to different host catalog can't create hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj1.PublicId,
						Grants:      []string{"ids=" + hc2.PublicId + ";type=host;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "global role grant this + descendants can create hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host;actions=*;output_fields=id,scope,created_time,updated_time,version,type,authorized_actions,attributes"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, StaticHostAttributes}},
			},
			{
				name: "org role grant this + children can create hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=*;actions=create;output_fields=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.NameField, globals.DescriptionField, globals.HostCatalogIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, StaticHostAttributes}},
			},
			{
				name: "org role pinned-id granted children can create hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=" + hc.PublicId + ";type=*;actions=create;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField}},
			},
		}
		for i, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrapper, tok, iamRepo)

				got, err := tested.CreateHost(fullGrantAuthCtx, &pbs.CreateHostRequest{
					Item: &pb.Host{
						HostCatalogId: hc.GetPublicId(),
						Name:          &wrappers.StringValue{Value: fmt.Sprintf("name%d", i)},
						Description:   &wrappers.StringValue{Value: fmt.Sprintf("desc%d", i)},
						Type:          "static",
						Attrs: &pb.Host_StaticHostAttributes{
							StaticHostAttributes: &pb.StaticHostAttributes{
								Address: wrapperspb.String("123.456.789"),
							},
						},
					},
				})
				if tc.expected.err != nil {
					require.ErrorIs(t, err, tc.expected.err)
					return
				}
				require.NoError(t, err)
				handlers.TestAssertOutputFields(t, got.Item, tc.expected.outputFields)
			})
		}
	})

	t.Run("Update", func(t *testing.T) {
		testcases := []struct {
			name     string
			userFunc func() (*iam.User, auth.Account)
			wantErr  bool
			expected expectedOutput
		}{
			{
				name: "global role grant this can't update hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "global role grant this + children can't update hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "global role grant this + descendants can update hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField}},
			},
			{
				name: "org role grant this can't update hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=host;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "org role grant this + children can update hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=*;actions=update;output_fields=id,name,description,type"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.NameField, globals.DescriptionField, globals.TypeField}},
			},
			{
				name: "org role pinned-id granted children can update hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=" + hc.PublicId + ";type=*;actions=update;output_fields=id,name,description,type"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.NameField, globals.DescriptionField, globals.TypeField}},
			},
			{
				name: "proj role grant this can update hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj1.PublicId,
						Grants:      []string{"ids=*;type=host;actions=update"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.NameField, globals.DescriptionField, globals.HostCatalogIdField, globals.ScopeField, globals.HostSetIdsField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, StaticHostAttributes, globals.AuthorizedActionsField}},
			},
			{
				name: "proj role grant this pinned to different host catalog can't update hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj1.PublicId,
						Grants:      []string{"ids=" + hc2.PublicId + ";type=host;actions=update;output_fields=id,name,description,type"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrapper, tok, iamRepo)

				got, err := tested.UpdateHost(fullGrantAuthCtx, &pbs.UpdateHostRequest{
					Id: h.GetPublicId(),
					UpdateMask: &field_mask.FieldMask{
						Paths: []string{"name", "description", "type"},
					},
					Item: &pb.Host{
						Name:        &wrappers.StringValue{Value: "new"},
						Description: &wrappers.StringValue{Value: "desc"},
						Type:        "static",
						Version:     version,
					},
				})
				if tc.expected.err != nil {
					require.ErrorIs(t, err, tc.expected.err)
					return
				}
				defer resetHost()

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
				name: "global role grant this can't delete hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "global role grant this + children can't delete hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=host;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "org role grant this can't delete hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=host;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "org role grant this + children can delete hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=*;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
			},
			{
				name: "org role pinned-id granted children can delete hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=" + hc.PublicId + ";type=*;actions=delete"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
			},
			{
				name: "proj role grant this can delete hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj1.PublicId,
						Grants:      []string{"ids=*;type=host;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
			},
			{
				name: "proj role grant this pinned to different host catalog can't delete hosts",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj1.PublicId,
						Grants:      []string{"ids=" + hc2.PublicId + ";type=host;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrapper, tok, iamRepo)

				_, err = tested.DeleteHost(fullGrantAuthCtx, &pbs.DeleteHostRequest{
					Id: h.GetPublicId(),
				})
				if tc.wantErr != nil {
					require.ErrorIs(t, err, tc.wantErr)
					return
				}
				require.NoError(t, err)

				h, err = static.NewHost(ctx, hc.GetPublicId(), static.WithName("default"), static.WithDescription("default"), static.WithAddress("defaultaddress"))
				require.NoError(t, err)
				h, err = repo.CreateHost(ctx, proj1.GetPublicId(), h)
				require.NoError(t, err)
			})
		}
	})
}
