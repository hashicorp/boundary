// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package tcp_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	credstatic "github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
	controllerauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestGrants_ReadActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	s, err := testService(t, ctx, conn, kmsCache, wrapper)
	require.NoError(t, err)
	rw := db.New(conn)

	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	org1, proj1 := iam.TestScopes(t, iamRepo, iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	_, proj2 := iam.TestScopes(t, iamRepo, iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	noTargetOrg := iam.TestOrg(t, iamRepo, iam.WithSkipDefaultRoleCreation(true), iam.WithSkipAdminRoleCreation(true))
	target1 := tcp.TestTarget(ctx, t, conn, proj1.GetPublicId(), "test address-1", target.WithAddress("8.8.8.8"))
	target2 := tcp.TestTarget(ctx, t, conn, proj1.GetPublicId(), "test address-2", target.WithAddress("8.8.8.8"))
	target3 := tcp.TestTarget(ctx, t, conn, proj2.GetPublicId(), "test address-2", target.WithAddress("8.8.8.8"))

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name               string
			input              *pbs.ListTargetsRequest
			userFunc           func() (*iam.User, auth.Account)
			wantErr            error
			wantIdOutputFields map[string][]string
		}{
			{
				name: "global role grant descendants returns all created targets",
				input: &pbs.ListTargetsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=target;actions=list,read;output_fields=id,authorized_actions,scope_id,address"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				wantErr: nil,
				wantIdOutputFields: map[string][]string{
					target1.GetPublicId(): {globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField},
					target2.GetPublicId(): {globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField},
					target3.GetPublicId(): {globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField},
				},
			},
			{
				name: "global role grant descendants list at org return all org targets",
				input: &pbs.ListTargetsRequest{
					ScopeId:   org1.PublicId,
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=target;actions=list,read;output_fields=id,authorized_actions,scope_id,address"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				wantErr: nil,
				wantIdOutputFields: map[string][]string{
					target1.GetPublicId(): {globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField},
					target2.GetPublicId(): {globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField},
				},
			},
			{
				name: "org role grant this returns all created targets",
				input: &pbs.ListTargetsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.GetPublicId(),
						Grants:      []string{"ids=*;type=target;actions=list,read;output_fields=id,authorized_actions,scope_id,address"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				wantIdOutputFields: map[string][]string{
					target1.GetPublicId(): {globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField},
					target2.GetPublicId(): {globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField},
				},
			},
			{
				name: "project role grant this returns all created targets",
				input: &pbs.ListTargetsRequest{
					ScopeId: proj2.GetPublicId(),
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj2.GetPublicId(),
						Grants:      []string{"ids=*;type=target;actions=list,read;output_fields=id,name,created_time,updated_time,version"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIdOutputFields: map[string][]string{
					target3.GetPublicId(): {globals.IdField, globals.NameField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField},
				},
			},
			{
				name: "recursive list return no result but no error",
				input: &pbs.ListTargetsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: noTargetOrg.PublicId,
						GrantScopes: []string{globals.GrantScopeThis},
						Grants:      []string{"ids=*;type=target;actions=list"},
					},
				}),
				wantErr:            nil,
				wantIdOutputFields: map[string][]string{},
			},
			{
				name: "no grant recursive list return error",
				input: &pbs.ListTargetsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{}),
				wantErr:  handlers.ForbiddenError(),
			},
			{
				name: "no grant non-recursive list return error",
				input: &pbs.ListTargetsRequest{
					ScopeId: proj2.GetPublicId(),
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{}),
				wantErr:  handlers.ForbiddenError(),
			},
			{
				name: "iss 5003 less permissive grants should not override more permissive grants with specific type",
				input: &pbs.ListTargetsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;actions=authorize-session;output_fields=id,authorized_actions,scope_id,address", target1.GetPublicId())},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=target;actions=read,list;output_fields=id,authorized_actions,scope_id,address"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				wantErr: nil,
				wantIdOutputFields: map[string][]string{
					target1.GetPublicId(): {globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField},
					target2.GetPublicId(): {globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField},
					target3.GetPublicId(): {globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField},
				},
			},
			{
				name: "iss 5003 less permissive grants should not override more permissive grants",
				input: &pbs.ListTargetsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,authorized_actions,scope_id,address"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;actions=authorize-session;output_fields=id,authorized_actions,scope_id,address", target1.GetPublicId())},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				wantErr: nil,
				wantIdOutputFields: map[string][]string{
					target1.GetPublicId(): {globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField},
					target2.GetPublicId(): {globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField},
					target3.GetPublicId(): {globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField},
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrapper, tok, iamRepo)
				got, finalErr := s.ListTargets(fullGrantAuthCtx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, finalErr, tc.wantErr)
					return
				}
				require.NoError(t, finalErr)
				require.Len(t, got.Items, len(tc.wantIdOutputFields))

				for _, item := range got.Items {
					wantOutputFields, ok := tc.wantIdOutputFields[item.Id]
					require.True(t, ok)
					handlers.TestAssertOutputFields(t, item, wantOutputFields)
				}
			})
		}
	})
	type readTestResult struct {
		wantErr          error
		wantOutputFields []string
	}
	t.Run("Read", func(t *testing.T) {
		testcases := []struct {
			name               string
			userFunc           func() (*iam.User, auth.Account)
			wantIdOutputFields map[string]readTestResult
		}{
			{
				name: "global role grant descendants returns all created targets",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=target;actions=list,read;output_fields=id,authorized_actions,scope_id,address"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				wantIdOutputFields: map[string]readTestResult{
					target1.GetPublicId(): {wantOutputFields: []string{globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField}},
					target2.GetPublicId(): {wantOutputFields: []string{globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField}},
					target3.GetPublicId(): {wantOutputFields: []string{globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField}},
				},
			},
			{
				name: "org role grant children returns all its created targets",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.GetPublicId(),
						Grants:      []string{"ids=*;type=target;actions=list,read;output_fields=id,authorized_actions,scope_id,address"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				wantIdOutputFields: map[string]readTestResult{
					target1.GetPublicId(): {wantOutputFields: []string{globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField}},
					target2.GetPublicId(): {wantOutputFields: []string{globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField}},
					target3.GetPublicId(): {wantErr: handlers.ForbiddenError()},
				},
			},
			{
				name: "project role grant this returns all created targets",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj2.GetPublicId(),
						Grants:      []string{"ids=*;type=target;actions=list,read;output_fields=id,name,created_time,updated_time,version"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantIdOutputFields: map[string]readTestResult{
					target1.GetPublicId(): {wantErr: handlers.ForbiddenError()},
					target2.GetPublicId(): {wantErr: handlers.ForbiddenError()},
					target3.GetPublicId(): {wantOutputFields: []string{globals.IdField, globals.NameField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
				},
			},
			{
				name: "global role with individual project grant returns all created targets on the project",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=target;actions=list,read;output_fields=id,name,created_time,updated_time,version"},
						GrantScopes: []string{proj2.PublicId},
					},
				}),
				wantIdOutputFields: map[string]readTestResult{
					target1.GetPublicId(): {wantErr: handlers.ForbiddenError()},
					target2.GetPublicId(): {wantErr: handlers.ForbiddenError()},
					target3.GetPublicId(): {wantOutputFields: []string{globals.IdField, globals.NameField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrapper, tok, iamRepo)

				for targetId, expect := range tc.wantIdOutputFields {
					got, finalErr := s.GetTarget(fullGrantAuthCtx, &pbs.GetTargetRequest{
						Id: targetId,
					})
					if expect.wantErr != nil {
						require.ErrorIs(t, finalErr, expect.wantErr)
						continue
					}
					require.NoError(t, err)
					handlers.TestAssertOutputFields(t, got.Item, expect.wantOutputFields)
				}
			})
		}
	})
}

func TestGrants_Create(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	s, err := testService(t, ctx, conn, kmsCache, wrapper)
	require.NoError(t, err)
	rw := db.New(conn)

	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	org1, proj1 := iam.TestScopes(t, iamRepo, iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	_, proj2 := iam.TestScopes(t, iamRepo, iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))

	type expectResult struct {
		wantErr          error
		wantOutputFields []string
	}

	testcases := []struct {
		name           string
		input          *pbs.CreateTargetRequest
		userFunc       func() (*iam.User, auth.Account)
		scopeResultMap map[string]expectResult
	}{
		{
			name: "global role descendants grants can create anywhere",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=target;actions=*;output_fields=id,authorized_actions,scope_id,address"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
			}),
			scopeResultMap: map[string]expectResult{
				proj1.PublicId: {wantOutputFields: []string{globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField}},
				proj2.PublicId: {wantOutputFields: []string{globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField}},
			},
		},
		{
			name: "org role children grants can create in children scopes",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org1.GetPublicId(),
					Grants:      []string{"ids=*;type=target;actions=create;output_fields=id,name,created_time,updated_time,version"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			scopeResultMap: map[string]expectResult{
				proj1.PublicId: {wantOutputFields: []string{globals.IdField, globals.NameField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
				proj2.PublicId: {wantErr: handlers.ForbiddenError()},
			},
		},
		{
			name: "proj role this grants can create this scopes",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj1.GetPublicId(),
					Grants:      []string{"ids=*;type=target;actions=create;output_fields=id,name,created_time,updated_time,version"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			scopeResultMap: map[string]expectResult{
				proj1.PublicId: {wantOutputFields: []string{globals.IdField, globals.NameField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
				proj2.PublicId: {wantErr: handlers.ForbiddenError()},
			},
		},
		{
			name: "global role specific project grants can create in project scopes",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=target;actions=create;output_fields=id,name,created_time,updated_time,version"},
					GrantScopes: []string{proj2.PublicId},
				},
			}),
			scopeResultMap: map[string]expectResult{
				proj1.PublicId: {wantErr: handlers.ForbiddenError()},
				proj2.PublicId: {wantOutputFields: []string{globals.IdField, globals.NameField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
			},
		},
		{
			name: "org role specific project grants can create in project scopes",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org1.GetPublicId(),
					Grants:      []string{"ids=*;type=target;actions=create;output_fields=id,name,created_time,updated_time,version"},
					GrantScopes: []string{proj1.PublicId},
				},
			}),
			scopeResultMap: map[string]expectResult{
				proj1.PublicId: {wantOutputFields: []string{globals.IdField, globals.NameField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
				proj2.PublicId: {wantErr: handlers.ForbiddenError()},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrapper, tok, iamRepo)
			for scope, expect := range tc.scopeResultMap {
				tgt := validTcpTarget(t, scope)
				got, finalErr := s.CreateTarget(fullGrantAuthCtx, &pbs.CreateTargetRequest{
					Item: tgt,
				})
				if expect.wantErr != nil {
					require.ErrorIs(t, finalErr, expect.wantErr)
					continue
				}
				require.NoError(t, finalErr)
				handlers.TestAssertOutputFields(t, got.Item, expect.wantOutputFields)
			}
		})
	}
}

type userFn func() (*iam.User, auth.Account)

func TestGrants_SetTargetCredentialSources(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	s, err := testService(t, ctx, conn, kmsCache, wrapper)
	require.NoError(t, err)
	rw := db.New(conn)

	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	org1, proj1 := iam.TestScopes(t, iamRepo, iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	_, proj2 := iam.TestScopes(t, iamRepo, iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))

	proj1Vault := vault.TestCredentialStores(t, conn, wrapper, proj1.GetPublicId(), 1)[0]
	proj1Cls := vault.TestCredentialLibraries(t, conn, wrapper, proj1Vault.GetPublicId(), globals.UsernamePasswordCredentialType, 2)

	proj2StoreStatic := credstatic.TestCredentialStore(t, conn, wrapper, proj2.GetPublicId())
	proj2Creds := credstatic.TestUsernamePasswordCredentials(t, conn, wrapper, "user", "pass", proj2StoreStatic.GetPublicId(), proj2.GetPublicId(), 2)

	testcases := []struct {
		name             string
		input            *pbs.ListTargetsRequest
		setup            func(t *testing.T) (*pbs.SetTargetCredentialSourcesRequest, userFn)
		wantErr          error
		wantOutputFields []string
	}{
		{
			name: "global role grant descendants returns succeed",
			setup: func(t *testing.T) (*pbs.SetTargetCredentialSourcesRequest, userFn) {
				setupUser := iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						GrantScopes: []string{globals.GrantScopeDescendants},
						Grants:      []string{"ids=*;type=target;actions=*;output_fields=id,authorized_actions,scope_id,address"},
					},
				})
				randId, err := uuid.GenerateUUID()
				require.NoError(t, err)
				tgt := tcp.TestTarget(ctx, t, conn, proj1.GetPublicId(), randId, target.WithAddress("8.8.8.8"))
				return &pbs.SetTargetCredentialSourcesRequest{
					Id:                          tgt.GetPublicId(),
					Version:                     tgt.GetVersion(),
					BrokeredCredentialSourceIds: []string{proj1Cls[0].GetPublicId()},
				}, setupUser
			},
			wantOutputFields: []string{globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField},
		},
		{
			name: "global role grant specific project and pinned id returns succeed",
			setup: func(t *testing.T) (*pbs.SetTargetCredentialSourcesRequest, userFn) {
				randId, err := uuid.GenerateUUID()
				require.NoError(t, err)
				tgt := tcp.TestTarget(ctx, t, conn, proj1.GetPublicId(), randId, target.WithAddress("8.8.8.8"))
				setupUser := iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						GrantScopes: []string{proj1.PublicId},
						Grants:      []string{fmt.Sprintf("ids=%s;actions=set-credential-sources;output_fields=id,authorized_actions,scope_id,address", tgt.GetPublicId())},
					},
				})
				return &pbs.SetTargetCredentialSourcesRequest{
					Id:                          tgt.GetPublicId(),
					Version:                     tgt.GetVersion(),
					BrokeredCredentialSourceIds: []string{proj1Cls[0].GetPublicId()},
				}, setupUser
			},
			wantOutputFields: []string{globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField},
		},
		{
			name: "global role grant specific project and pinned id wrong action error",
			setup: func(t *testing.T) (*pbs.SetTargetCredentialSourcesRequest, userFn) {
				randId, err := uuid.GenerateUUID()
				require.NoError(t, err)
				tgt := tcp.TestTarget(ctx, t, conn, proj1.GetPublicId(), randId, target.WithAddress("8.8.8.8"))
				setupUser := iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						GrantScopes: []string{proj1.PublicId},
						Grants:      []string{fmt.Sprintf("ids=%s;actions=remove-credential-sources;output_fields=id,authorized_actions,scope_id,address", tgt.GetPublicId())},
					},
				})
				return &pbs.SetTargetCredentialSourcesRequest{
					Id:                          tgt.GetPublicId(),
					Version:                     tgt.GetVersion(),
					BrokeredCredentialSourceIds: []string{proj1Cls[0].GetPublicId()},
				}, setupUser
			},
			wantErr: handlers.ForbiddenError(),
		},
		{
			name: "org role grant children returns all succeed",
			setup: func(t *testing.T) (*pbs.SetTargetCredentialSourcesRequest, userFn) {
				setupUser := iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.GetPublicId(),
						GrantScopes: []string{globals.GrantScopeChildren},
						Grants:      []string{"ids=*;type=target;actions=*;output_fields=id,authorized_actions,scope_id,address"},
					},
				})
				randId, err := uuid.GenerateUUID()
				require.NoError(t, err)
				tgt := tcp.TestTarget(ctx, t, conn, proj1.GetPublicId(), randId, target.WithAddress("8.8.8.8"))
				return &pbs.SetTargetCredentialSourcesRequest{
					Id:                          tgt.GetPublicId(),
					Version:                     tgt.GetVersion(),
					BrokeredCredentialSourceIds: []string{proj1Cls[0].GetPublicId()},
				}, setupUser
			},
			wantOutputFields: []string{globals.IdField, globals.AuthorizedActionsField, globals.ScopeIdField, globals.AddressField},
		},
		{
			name: "org role grant this returns error",
			setup: func(t *testing.T) (*pbs.SetTargetCredentialSourcesRequest, userFn) {
				setupUser := iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.GetPublicId(),
						GrantScopes: []string{globals.GrantScopeThis},
						Grants:      []string{"ids=*;type=target;actions=*;output_fields=id,authorized_actions,scope_id,address"},
					},
				})
				randId, err := uuid.GenerateUUID()
				require.NoError(t, err)
				tgt := tcp.TestTarget(ctx, t, conn, proj1.GetPublicId(), randId, target.WithAddress("8.8.8.8"))
				return &pbs.SetTargetCredentialSourcesRequest{
					Id:                          tgt.GetPublicId(),
					Version:                     tgt.GetVersion(),
					BrokeredCredentialSourceIds: []string{proj1Cls[0].GetPublicId()},
				}, setupUser
			},
			wantErr: handlers.ForbiddenError(),
		},
		{
			name: "project role grant this succeed",
			setup: func(t *testing.T) (*pbs.SetTargetCredentialSourcesRequest, userFn) {
				setupUser := iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj2.GetPublicId(),
						GrantScopes: []string{globals.GrantScopeThis},
						Grants:      []string{"ids=*;type=target;actions=*;output_fields=id,name,created_time,updated_time,version"},
					},
				})
				randId, err := uuid.GenerateUUID()
				require.NoError(t, err)
				tgt := tcp.TestTarget(ctx, t, conn, proj2.GetPublicId(), randId, target.WithAddress("8.8.8.8"))
				return &pbs.SetTargetCredentialSourcesRequest{
					Id:                          tgt.GetPublicId(),
					Version:                     tgt.GetVersion(),
					BrokeredCredentialSourceIds: []string{proj2Creds[0].GetPublicId()},
				}, setupUser
			},
			wantOutputFields: []string{globals.IdField, globals.NameField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			input, userFunc := tc.setup(t)
			user, account := userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrapper, tok, iamRepo)
			got, err := s.SetTargetCredentialSources(fullGrantAuthCtx, input)
			if tc.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			handlers.TestAssertOutputFields(t, got.Item, tc.wantOutputFields)
		})
	}
}

func validTcpTarget(t *testing.T, scopeId string) *pb.Target {
	randString, err := uuid.GenerateUUID()
	require.NoError(t, err)
	return &pb.Target{
		ScopeId:     scopeId,
		Name:        wrapperspb.String(randString),
		Description: wrapperspb.String(randString),
		Type:        "tcp",
		Attrs: &pb.Target_TcpTargetAttributes{
			TcpTargetAttributes: &pb.TcpTargetAttributes{
				DefaultPort:       wrapperspb.UInt32(2),
				DefaultClientPort: wrapperspb.UInt32(3),
			},
		},
	}
}
