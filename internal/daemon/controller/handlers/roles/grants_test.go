// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package roles_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/authtoken"
	controllerauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/roles"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/roles"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type expect struct {
	wantErr    error
	wantFields []string
}

func TestGrants_ReadActions(t *testing.T) {
	const (
		// Set role description to this value for every role that should be included in the result set.
		// This is used to work around a non-deterministic behavior from roles being created as a part of
		// the test setup.
		// This also means that `description` must also be included in the output_fields
		roleDescription = "test role"
	)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	kmsCache := kms.TestKms(t, conn, wrap)
	s, err := roles.NewService(ctx, repoFn, 1000)
	require.NoError(t, err)
	rw := db.New(conn)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	org1, noRoleProj := iam.TestScopes(t, iamRepo, iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	org2, proj2 := iam.TestScopes(t, iamRepo, iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	proj3 := iam.TestProject(t, iamRepo, org2.PublicId, iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))

	globalRole := iam.TestRole(t, conn, globals.GlobalPrefix, iam.WithDescription(roleDescription), iam.WithName("glob"))
	iam.TestRoleGrant(t, conn, globalRole.PublicId, "ids=*;type=*;actions=*")
	org1Role := iam.TestRole(t, conn, org1.GetPublicId(), iam.WithDescription(roleDescription), iam.WithName("org1"))
	iam.TestRoleGrant(t, conn, org1Role.PublicId, "ids=*;type=*;actions=*")
	org2Role := iam.TestRole(t, conn, org2.GetPublicId(), iam.WithDescription(roleDescription), iam.WithName("org2"))
	iam.TestRoleGrant(t, conn, org2Role.PublicId, "ids=*;type=*;actions=*")
	proj2Role := iam.TestRole(t, conn, proj2.GetPublicId(), iam.WithDescription(roleDescription), iam.WithName("proj2"))
	iam.TestRoleGrant(t, conn, proj2Role.PublicId, "ids=*;type=*;actions=*")
	proj3Role := iam.TestRole(t, conn, proj3.GetPublicId(), iam.WithDescription(roleDescription), iam.WithName("proj3"))
	iam.TestRoleGrant(t, conn, proj3Role.PublicId, "ids=*;type=*;actions=*")

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name              string
			input             *pbs.ListRolesRequest
			userFunc          func() (*iam.User, auth.Account)
			wantErr           error
			idOutputFieldsMap map[string][]string
		}{
			{
				name: "global role grant this and descendants returns global org and project roles",
				input: &pbs.ListRolesRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=role;actions=list,read;output_fields=id,name,description,scope_id,authorized_actions,principal_ids"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantErr: nil,
				idOutputFieldsMap: map[string][]string{
					globalRole.PublicId: {globals.IdField, globals.NameField, globals.DescriptionField, globals.ScopeIdField, globals.AuthorizedActionsField},
					org1Role.PublicId:   {globals.IdField, globals.NameField, globals.DescriptionField, globals.ScopeIdField, globals.AuthorizedActionsField},
					org2Role.PublicId:   {globals.IdField, globals.NameField, globals.DescriptionField, globals.ScopeIdField, globals.AuthorizedActionsField},
					proj2Role.PublicId:  {globals.IdField, globals.NameField, globals.DescriptionField, globals.ScopeIdField, globals.AuthorizedActionsField},
					proj3Role.PublicId:  {globals.IdField, globals.NameField, globals.DescriptionField, globals.ScopeIdField, globals.AuthorizedActionsField},
				},
			},
			{
				name: "project grant scope list recursive returns no result and no error",
				input: &pbs.ListRolesRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: noRoleProj.PublicId,
						Grants:      []string{"ids=*;type=role;actions=list,read;output_fields=id,name,description,scope_id,authorized_actions,principal_ids"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr:           nil,
				idOutputFieldsMap: map[string][]string{},
			},
			{
				name: "project grant scope list non-recursive returns error",
				input: &pbs.ListRolesRequest{
					ScopeId: globals.GlobalPrefix,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: noRoleProj.PublicId,
						Grants:      []string{"ids=*;type=role;actions=list,read;output_fields=id,name,description,scope_id,authorized_actions,principal_ids"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr:           handlers.ForbiddenError(),
				idOutputFieldsMap: map[string][]string{},
			},
			{
				name: "global role grant this and children returns global and org roles",
				input: &pbs.ListRolesRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=role;actions=list,read;output_fields=id,name,description,scope_id,authorized_actions,principal_ids"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				idOutputFieldsMap: map[string][]string{
					globalRole.PublicId: {globals.IdField, globals.NameField, globals.DescriptionField, globals.ScopeIdField, globals.AuthorizedActionsField},
					org1Role.PublicId:   {globals.IdField, globals.NameField, globals.DescriptionField, globals.ScopeIdField, globals.AuthorizedActionsField},
					org2Role.PublicId:   {globals.IdField, globals.NameField, globals.DescriptionField, globals.ScopeIdField, globals.AuthorizedActionsField},
				},
			},
			{
				name: "no role recursive list returns error",
				input: &pbs.ListRolesRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{}),
				wantErr:  handlers.ForbiddenError(),
			},
			{
				name: "org role grant this and children returns org and project roles",
				input: &pbs.ListRolesRequest{
					ScopeId:   org2.PublicId,
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org2.PublicId,
						Grants:      []string{"ids=*;type=role;actions=list,read;output_fields=id,description,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				idOutputFieldsMap: map[string][]string{
					org2Role.PublicId:  {globals.IdField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField},
					proj2Role.PublicId: {globals.IdField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField},
					proj3Role.PublicId: {globals.IdField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField},
				},
			},
			{
				name: "org role grant this and individual project returns org and granted project roles",
				input: &pbs.ListRolesRequest{
					ScopeId:   org2.PublicId,
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org2.PublicId,
						Grants:      []string{"ids=*;type=role;actions=list,read;output_fields=id,description,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: org2.PublicId,
						Grants:      []string{"ids=*;type=role;actions=list,read;output_fields=id,description,created_time"},
						GrantScopes: []string{proj3.PublicId},
					},
				}),
				wantErr: nil,
				idOutputFieldsMap: map[string][]string{
					org2Role.PublicId:  {globals.IdField, globals.DescriptionField, globals.UpdatedTimeField},
					proj3Role.PublicId: {globals.IdField, globals.DescriptionField, globals.CreatedTimeField},
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, finalErr := s.ListRoles(fullGrantAuthCtx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, finalErr, tc.wantErr)
					return
				}
				require.NoError(t, finalErr)
				var filteredRoles []*pb.Role
				for _, r := range got.Items {
					// only include roles with description that indicates that the roles are created as a part of
					// the test setup
					if r.GetDescription().GetValue() != roleDescription {
						continue
					}
					filteredRoles = append(filteredRoles, r)
				}
				require.Len(t, filteredRoles, len(tc.idOutputFieldsMap))
				for _, item := range filteredRoles {
					wantFields, ok := tc.idOutputFieldsMap[item.GetId()]
					require.True(t, ok)
					handlers.TestAssertOutputFields(t, item, wantFields)
				}
			})
		}
	})

	t.Run("Read", func(t *testing.T) {
		testcases := []struct {
			name           string
			userFunc       func() (*iam.User, auth.Account)
			inputExpectMap map[*pbs.GetRoleRequest]expect
		}{
			{
				name: "global role grant this and descendants can read all roles",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=role;actions=read;output_fields=id,name,created_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				inputExpectMap: map[*pbs.GetRoleRequest]expect{
					{Id: globalRole.PublicId}: {wantFields: []string{globals.IdField, globals.NameField, globals.CreatedTimeField}},
					{Id: org1Role.PublicId}:   {wantFields: []string{globals.IdField, globals.NameField, globals.CreatedTimeField}},
					{Id: org2Role.PublicId}:   {wantFields: []string{globals.IdField, globals.NameField, globals.CreatedTimeField}},
					{Id: proj2Role.PublicId}:  {wantFields: []string{globals.IdField, globals.NameField, globals.CreatedTimeField}},
					{Id: proj3Role.PublicId}:  {wantFields: []string{globals.IdField, globals.NameField, globals.CreatedTimeField}},
				},
			},
			{
				name: "global role grant this and children can read global and org roles",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=role;actions=*;output_fields=id,updated_time,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				inputExpectMap: map[*pbs.GetRoleRequest]expect{
					{Id: globalRole.PublicId}: {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.AuthorizedActionsField}},
					{Id: org1Role.PublicId}:   {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.AuthorizedActionsField}},
					{Id: org2Role.PublicId}:   {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.AuthorizedActionsField}},
					{Id: proj2Role.PublicId}:  {wantErr: handlers.ForbiddenError()},
					{Id: proj3Role.PublicId}:  {wantErr: handlers.ForbiddenError()},
				},
			},
			{
				name: "org role grant this and children can read self and projects roles",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org2.PublicId,
						Grants:      []string{"ids=*;type=role;actions=*;output_fields=id,updated_time,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				inputExpectMap: map[*pbs.GetRoleRequest]expect{
					{Id: globalRole.PublicId}: {wantErr: handlers.ForbiddenError()},
					{Id: org1Role.PublicId}:   {wantErr: handlers.ForbiddenError()},
					{Id: org2Role.PublicId}:   {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.AuthorizedActionsField}},
					{Id: proj2Role.PublicId}:  {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.AuthorizedActionsField}},
					{Id: proj3Role.PublicId}:  {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.AuthorizedActionsField}},
				},
			},
			{
				name: "project role grant this can read self",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj2.PublicId,
						Grants:      []string{"ids=*;type=role;actions=*;output_fields=id,version,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputExpectMap: map[*pbs.GetRoleRequest]expect{
					{Id: globalRole.PublicId}: {wantErr: handlers.ForbiddenError()},
					{Id: org1Role.PublicId}:   {wantErr: handlers.ForbiddenError()},
					{Id: org2Role.PublicId}:   {wantErr: handlers.ForbiddenError()},
					{Id: proj2Role.PublicId}:  {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
					{Id: proj3Role.PublicId}:  {wantErr: handlers.ForbiddenError()},
				},
			},
			{
				name: "individually granted scopes can read granted scopes roles",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=role;actions=*;output_fields=id,version,authorized_actions"},
						GrantScopes: []string{org2.PublicId, proj3.PublicId},
					},
				}),
				inputExpectMap: map[*pbs.GetRoleRequest]expect{
					{Id: globalRole.PublicId}: {wantErr: handlers.ForbiddenError()},
					{Id: org1Role.PublicId}:   {wantErr: handlers.ForbiddenError()},
					{Id: org2Role.PublicId}:   {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
					{Id: proj2Role.PublicId}:  {wantErr: handlers.ForbiddenError()},
					{Id: proj3Role.PublicId}:  {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
				},
			},
			{
				name: "multiple roles can read granted scopes roles",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=role;actions=*;output_fields=id,version,authorized_actions"},
						GrantScopes: []string{org2.PublicId, proj3.PublicId},
					},
					{
						RoleScopeId: proj2.PublicId,
						Grants:      []string{"ids=*;type=role;actions=*;output_fields=id,version,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputExpectMap: map[*pbs.GetRoleRequest]expect{
					{Id: globalRole.PublicId}: {wantErr: handlers.ForbiddenError()},
					{Id: org1Role.PublicId}:   {wantErr: handlers.ForbiddenError()},
					{Id: org2Role.PublicId}:   {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
					{Id: proj2Role.PublicId}:  {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
					{Id: proj3Role.PublicId}:  {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				for input, expected := range tc.inputExpectMap {
					got, finalErr := s.GetRole(fullGrantAuthCtx, input)
					if expected.wantErr != nil {
						require.ErrorIs(t, finalErr, expected.wantErr)
						continue
					}
					require.NoError(t, finalErr)
					handlers.TestAssertOutputFields(t, got.Item, expected.wantFields)
				}
			})
		}
	})
}

func TestGrants_CreateRole(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	kmsCache := kms.TestKms(t, conn, wrap)
	s, err := roles.NewService(ctx, repoFn, 1000)
	require.NoError(t, err)
	rw := db.New(conn)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	org1, _ := iam.TestScopes(t, iamRepo, iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	org2, proj2 := iam.TestScopes(t, iamRepo, iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	proj3 := iam.TestProject(t, iamRepo, org2.PublicId, iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))

	testcases := []struct {
		name                string
		userFunc            func() (*iam.User, auth.Account)
		inputScopeExpectMap map[string]expect
	}{
		{
			name: "global role grant this and descendants can create all roles",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=role;actions=create;output_fields=id,name,created_time"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
				},
			}),
			inputScopeExpectMap: map[string]expect{
				globals.GlobalPrefix: {wantFields: []string{globals.IdField, globals.NameField, globals.CreatedTimeField}},
				org1.PublicId:        {wantFields: []string{globals.IdField, globals.NameField, globals.CreatedTimeField}},
				org2.PublicId:        {wantFields: []string{globals.IdField, globals.NameField, globals.CreatedTimeField}},
				proj2.PublicId:       {wantFields: []string{globals.IdField, globals.NameField, globals.CreatedTimeField}},
				proj3.PublicId:       {wantFields: []string{globals.IdField, globals.NameField, globals.CreatedTimeField}},
			},
		},
		{
			name: "global role grant this and children can create global and org roles",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=role;actions=*;output_fields=id,updated_time,authorized_actions"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			inputScopeExpectMap: map[string]expect{
				globals.GlobalPrefix: {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.AuthorizedActionsField}},
				org1.PublicId:        {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.AuthorizedActionsField}},
				org2.PublicId:        {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.AuthorizedActionsField}},
				proj2.PublicId:       {wantErr: handlers.ForbiddenError()},
				proj3.PublicId:       {wantErr: handlers.ForbiddenError()},
			},
		},
		{
			name: "org role grant this and children can create self and projects roles",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org2.PublicId,
					Grants:      []string{"ids=*;type=role;actions=*;output_fields=id,updated_time,authorized_actions"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			inputScopeExpectMap: map[string]expect{
				globals.GlobalPrefix: {wantErr: handlers.ForbiddenError()},
				org1.PublicId:        {wantErr: handlers.ForbiddenError()},
				org2.PublicId:        {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.AuthorizedActionsField}},
				proj2.PublicId:       {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.AuthorizedActionsField}},
				proj3.PublicId:       {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.AuthorizedActionsField}},
			},
		},
		{
			name: "project role grant this can create self",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj2.PublicId,
					Grants:      []string{"ids=*;type=role;actions=*;output_fields=id,version,authorized_actions"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputScopeExpectMap: map[string]expect{
				globals.GlobalPrefix: {wantErr: handlers.ForbiddenError()},
				org1.PublicId:        {wantErr: handlers.ForbiddenError()},
				org2.PublicId:        {wantErr: handlers.ForbiddenError()},
				proj2.PublicId:       {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
				proj3.PublicId:       {wantErr: handlers.ForbiddenError()},
			},
		},
		{
			name: "individually granted scopes can create granted scopes roles",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=role;actions=*;output_fields=id,version,authorized_actions"},
					GrantScopes: []string{org2.PublicId, proj3.PublicId},
				},
			}),
			inputScopeExpectMap: map[string]expect{
				globals.GlobalPrefix: {wantErr: handlers.ForbiddenError()},
				org1.PublicId:        {wantErr: handlers.ForbiddenError()},
				org2.PublicId:        {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
				proj2.PublicId:       {wantErr: handlers.ForbiddenError()},
				proj3.PublicId:       {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
			},
		},
		{
			name: "multiple roles can create granted scopes roles",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=role;actions=*;output_fields=id,version,authorized_actions"},
					GrantScopes: []string{org2.PublicId, proj3.PublicId},
				},
				{
					RoleScopeId: proj2.PublicId,
					Grants:      []string{"ids=*;type=role;actions=*;output_fields=id,version,authorized_actions"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputScopeExpectMap: map[string]expect{
				globals.GlobalPrefix: {wantErr: handlers.ForbiddenError()},
				org1.PublicId:        {wantErr: handlers.ForbiddenError()},
				org2.PublicId:        {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
				proj2.PublicId:       {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
				proj3.PublicId:       {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			for inputScopeId, expected := range tc.inputScopeExpectMap {
				randomId, err := uuid.GenerateUUID()
				require.NoError(t, err)

				got, finalErr := s.CreateRole(fullGrantAuthCtx, &pbs.CreateRoleRequest{
					Item: &pb.Role{
						ScopeId:     inputScopeId,
						Name:        wrapperspb.String(randomId),
						Description: wrapperspb.String(randomId),
					},
				})
				if expected.wantErr != nil {
					require.ErrorIs(t, finalErr, expected.wantErr)
					continue
				}
				require.NoError(t, finalErr)
				handlers.TestAssertOutputFields(t, got.Item, expected.wantFields)
			}
		})
	}
}

func TestGrants_SetRoleGrants(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	kmsCache := kms.TestKms(t, conn, wrap)
	s, err := roles.NewService(ctx, repoFn, 1000)
	require.NoError(t, err)
	rw := db.New(conn)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	org1, _ := iam.TestScopes(t, iamRepo, iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	org2, proj2 := iam.TestScopes(t, iamRepo, iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	proj3 := iam.TestProject(t, iamRepo, org2.PublicId, iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))

	globalRole := iam.TestRole(t, conn, globals.GlobalPrefix)
	iam.TestRoleGrant(t, conn, globalRole.PublicId, "ids=*;type=*;actions=*")
	org1Role := iam.TestRole(t, conn, org1.GetPublicId())
	iam.TestRoleGrant(t, conn, org1Role.PublicId, "ids=*;type=*;actions=*")
	org2Role := iam.TestRole(t, conn, org2.GetPublicId())
	iam.TestRoleGrant(t, conn, org2Role.PublicId, "ids=*;type=*;actions=*")
	proj2Role := iam.TestRole(t, conn, proj2.GetPublicId())
	iam.TestRoleGrant(t, conn, proj2Role.PublicId, "ids=*;type=*;actions=*")
	proj3Role := iam.TestRole(t, conn, proj3.GetPublicId())
	iam.TestRoleGrant(t, conn, proj3Role.PublicId, "ids=*;type=*;actions=*")

	testcases := []struct {
		name                 string
		userFunc             func() (*iam.User, auth.Account)
		inputRoleIdExpectMap map[string]expect
	}{
		{
			name: "global role grant this and descendants can set role grants in all roles",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=role;actions=set-grants;output_fields=id,updated_time,created_time"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
				},
			}),
			inputRoleIdExpectMap: map[string]expect{
				globalRole.PublicId: {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.CreatedTimeField}},
				org1Role.PublicId:   {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.CreatedTimeField}},
				org2Role.PublicId:   {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.CreatedTimeField}},
				proj2Role.PublicId:  {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.CreatedTimeField}},
				proj3Role.PublicId:  {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.CreatedTimeField}},
			},
		},
		{
			name: "global role grant this and children can set role grants in global and org roles",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=role;actions=*;output_fields=id,updated_time,authorized_actions"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			inputRoleIdExpectMap: map[string]expect{
				globalRole.PublicId: {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.AuthorizedActionsField}},
				org1Role.PublicId:   {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.AuthorizedActionsField}},
				org2Role.PublicId:   {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.AuthorizedActionsField}},
				proj2Role.PublicId:  {wantErr: handlers.ForbiddenError()},
				proj3Role.PublicId:  {wantErr: handlers.ForbiddenError()},
			},
		},
		{
			name: "org role grant this and children can set role grants in self and projects roles",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org2.PublicId,
					Grants:      []string{"ids=*;type=role;actions=*;output_fields=id,updated_time,authorized_actions"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			inputRoleIdExpectMap: map[string]expect{
				globalRole.PublicId: {wantErr: handlers.ForbiddenError()},
				org1Role.PublicId:   {wantErr: handlers.ForbiddenError()},
				org2Role.PublicId:   {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.AuthorizedActionsField}},
				proj2Role.PublicId:  {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.AuthorizedActionsField}},
				proj3Role.PublicId:  {wantFields: []string{globals.IdField, globals.UpdatedTimeField, globals.AuthorizedActionsField}},
			},
		},
		{
			name: "project role grant this can set role grants in self",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj2.PublicId,
					Grants:      []string{"ids=*;type=role;actions=*;output_fields=id,version,authorized_actions"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputRoleIdExpectMap: map[string]expect{
				globalRole.PublicId: {wantErr: handlers.ForbiddenError()},
				org1Role.PublicId:   {wantErr: handlers.ForbiddenError()},
				org2Role.PublicId:   {wantErr: handlers.ForbiddenError()},
				proj2Role.PublicId:  {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
				proj3Role.PublicId:  {wantErr: handlers.ForbiddenError()},
			},
		},
		{
			name: "individually granted scopes can set role grants in granted scopes roles",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=role;actions=*;output_fields=id,version,authorized_actions"},
					GrantScopes: []string{org2.PublicId, proj3.PublicId},
				},
			}),
			inputRoleIdExpectMap: map[string]expect{
				globalRole.PublicId: {wantErr: handlers.ForbiddenError()},
				org1Role.PublicId:   {wantErr: handlers.ForbiddenError()},
				org2Role.PublicId:   {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
				proj2Role.PublicId:  {wantErr: handlers.ForbiddenError()},
				proj3Role.PublicId:  {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
			},
		},
		{
			name: "multiple roles can set role grants in granted scopes roles",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=role;actions=*;output_fields=id,version,authorized_actions"},
					GrantScopes: []string{org2.PublicId, proj3.PublicId},
				},
				{
					RoleScopeId: proj2.PublicId,
					Grants:      []string{"ids=*;type=role;actions=*;output_fields=id,version,authorized_actions"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputRoleIdExpectMap: map[string]expect{
				globalRole.PublicId: {wantErr: handlers.ForbiddenError()},
				org1Role.PublicId:   {wantErr: handlers.ForbiddenError()},
				org2Role.PublicId:   {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
				proj2Role.PublicId:  {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
				proj3Role.PublicId:  {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
			},
		},
		{
			name: "pinned id and action set role grants",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{fmt.Sprintf("ids=%s,%s;actions=read,set-grants;output_fields=id,version,authorized_actions", org2Role.PublicId, proj3Role.PublicId)},
					GrantScopes: []string{org2.PublicId, proj3.PublicId},
				},
				{
					RoleScopeId: proj2.PublicId,
					Grants:      []string{fmt.Sprintf("ids=%s;actions=read,set-grants;output_fields=id,version,authorized_actions", proj2Role.PublicId)},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputRoleIdExpectMap: map[string]expect{
				globalRole.PublicId: {wantErr: handlers.ForbiddenError()},
				org1Role.PublicId:   {wantErr: handlers.ForbiddenError()},
				org2Role.PublicId:   {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
				proj2Role.PublicId:  {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
				proj3Role.PublicId:  {wantFields: []string{globals.IdField, globals.VersionField, globals.AuthorizedActionsField}},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			for inputRoleId, expected := range tc.inputRoleIdExpectMap {
				readbackRole, _, _, _, err := iamRepo.LookupRole(ctx, inputRoleId)
				require.NoError(t, err)
				randomId, err := uuid.GenerateUUID()
				require.NoError(t, err)
				got, finalErr := s.SetRoleGrants(fullGrantAuthCtx, &pbs.SetRoleGrantsRequest{
					Id:      inputRoleId,
					Version: readbackRole.Version,
					// use any randomized grants string
					GrantStrings: []string{fmt.Sprintf("ids=ttcp_%s;actions=read", randomId[:6])},
				})
				if expected.wantErr != nil {
					require.ErrorIs(t, finalErr, expected.wantErr)
					continue
				}
				require.NoError(t, finalErr)
				handlers.TestAssertOutputFields(t, got.Item, expected.wantFields)
			}
		})
	}
}
