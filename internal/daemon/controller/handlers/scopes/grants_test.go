// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package scopes_test

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
	controllerauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/scopes"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/stretchr/testify/require"
)

func TestGrants_ListScopes(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := scopes.NewServiceFn(ctx, repoFn, kmsCache, 1000)
	require.NoError(t, err)
	rw := db.New(conn)
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
		wantOutfields map[string][]string
		wantErr       error
	}{
		{
			name:     "no grants returns no scopes",
			input:    &pbs.ListScopesRequest{ScopeId: globals.GlobalPrefix},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{}),
			wantErr:  handlers.ForbiddenError(),
		},
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
					Grants:      []string{"ids=*;type=scope;actions=list,read;output_fields=id,name"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
				},
			}),
			wantOutfields: map[string][]string{
				org1.PublicId:   {globals.IdField, globals.NameField},
				org2.PublicId:   {globals.IdField, globals.NameField},
				proj1.PublicId:  {globals.IdField, globals.NameField},
				proj2a.PublicId: {globals.IdField, globals.NameField},
				proj2b.PublicId: {globals.IdField, globals.NameField},
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

// expectedOutput consolidates common output fields for the test cases
type expectedOutput struct {
	err          error
	outputFields []string
}

func TestGrants_GetScope(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := scopes.NewServiceFn(ctx, repoFn, kmsCache, 1000)
	require.NoError(t, err)

	org1 := iam.TestOrg(t, iamRepo, iam.WithName("org1"), iam.WithDescription("test org 1"), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	org2 := iam.TestOrg(t, iamRepo, iam.WithName("org2"), iam.WithDescription("test org 2"), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	proj1 := iam.TestProject(t, iamRepo, org1.GetPublicId(), iam.WithName("proj1"), iam.WithDescription("test project 1"), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	proj2 := iam.TestProject(t, iamRepo, org2.GetPublicId(), iam.WithName("proj2"), iam.WithDescription("test project 2"), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))

	testcases := []struct {
		name     string
		userFunc func() (*iam.User, auth.Account)
		expected map[*pbs.GetScopeRequest]expectedOutput
	}{
		{
			name:     "no grants returns no scopes",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{}),
			expected: map[*pbs.GetScopeRequest]expectedOutput{
				{Id: scope.Global.String()}: {err: handlers.ForbiddenError()},
				{Id: org1.PublicId}:         {err: handlers.ForbiddenError()},
				{Id: org2.PublicId}:         {err: handlers.ForbiddenError()},
				{Id: proj1.PublicId}:        {err: handlers.ForbiddenError()},
				{Id: proj2.PublicId}:        {err: handlers.ForbiddenError()},
			},
		},
		{
			name: "global role grant this returns scopes under the global scope",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=scope;actions=read;output_fields=id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expected: map[*pbs.GetScopeRequest]expectedOutput{
				{Id: scope.Global.String()}: {outputFields: []string{globals.IdField}},
				{Id: org1.PublicId}:         {outputFields: []string{globals.IdField}},
				{Id: org2.PublicId}:         {outputFields: []string{globals.IdField}},
				{Id: proj1.PublicId}:        {err: handlers.ForbiddenError()},
				{Id: proj2.PublicId}:        {err: handlers.ForbiddenError()},
			},
		},
		{
			name: "global role grant this and children returns scopes under the global and org scopes",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=scope;actions=read;output_fields=id,name"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			expected: map[*pbs.GetScopeRequest]expectedOutput{
				{Id: scope.Global.String()}: {outputFields: []string{globals.IdField, globals.NameField}},
				{Id: org1.PublicId}:         {outputFields: []string{globals.IdField, globals.NameField}},
				{Id: org2.PublicId}:         {outputFields: []string{globals.IdField, globals.NameField}},
				{Id: proj1.PublicId}:        {outputFields: []string{globals.IdField, globals.NameField}},
				{Id: proj2.PublicId}:        {outputFields: []string{globals.IdField, globals.NameField}},
			},
		},
		{
			name: "global role grant children returns scopes under org scopes",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=scope;actions=read;output_fields=id,name,scope_id"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			expected: map[*pbs.GetScopeRequest]expectedOutput{
				{Id: scope.Global.String()}: {err: handlers.ForbiddenError()},
				{Id: org1.PublicId}:         {err: handlers.ForbiddenError()},
				{Id: org2.PublicId}:         {err: handlers.ForbiddenError()},
				{Id: proj1.PublicId}:        {outputFields: []string{globals.IdField, globals.NameField, globals.ScopeIdField}},
				{Id: proj2.PublicId}:        {outputFields: []string{globals.IdField, globals.NameField, globals.ScopeIdField}},
			},
		},
		{
			name: "global role grant descendants returns scopes under org scopes",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=scope;actions=read;output_fields=id,name,scope_id,description"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
			}),
			expected: map[*pbs.GetScopeRequest]expectedOutput{
				{Id: scope.Global.String()}: {err: handlers.ForbiddenError()},
				{Id: org1.PublicId}:         {err: handlers.ForbiddenError()},
				{Id: org2.PublicId}:         {err: handlers.ForbiddenError()},
				{Id: proj1.PublicId}:        {outputFields: []string{globals.IdField, globals.NameField, globals.ScopeIdField, globals.DescriptionField}},
				{Id: proj2.PublicId}:        {outputFields: []string{globals.IdField, globals.NameField, globals.ScopeIdField, globals.DescriptionField}},
			},
		},
		{
			name: "org1 role grant this returns scopes under the org1 scope",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org1.PublicId,
					Grants:      []string{"ids=*;type=scope;actions=read;output_fields=id,name,scope_id,description,version"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expected: map[*pbs.GetScopeRequest]expectedOutput{
				{Id: scope.Global.String()}: {err: handlers.ForbiddenError()},
				{Id: org1.PublicId}:         {err: handlers.ForbiddenError()},
				{Id: org2.PublicId}:         {err: handlers.ForbiddenError()},
				{Id: proj1.PublicId}:        {outputFields: []string{globals.IdField, globals.NameField, globals.ScopeIdField, globals.DescriptionField, globals.VersionField}},
				{Id: proj2.PublicId}:        {err: handlers.ForbiddenError()},
			},
		},
		{
			name: "org1 role grant children returns scopes under project scopes (nothing)",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org1.PublicId,
					Grants:      []string{"ids=*;type=scope;actions=read"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			expected: map[*pbs.GetScopeRequest]expectedOutput{
				{Id: scope.Global.String()}: {err: handlers.ForbiddenError()},
				{Id: org1.PublicId}:         {err: handlers.ForbiddenError()},
				{Id: org2.PublicId}:         {err: handlers.ForbiddenError()},
				{Id: proj1.PublicId}:        {err: handlers.ForbiddenError()},
				{Id: proj2.PublicId}:        {err: handlers.ForbiddenError()},
			},
		},
		{
			name: "org1 role grant this and children returns scopes under the org1 scope",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org1.PublicId,
					Grants:      []string{"ids=*;type=scope;actions=read;output_fields=id,name,scope_id,description,version,type"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			expected: map[*pbs.GetScopeRequest]expectedOutput{
				{Id: scope.Global.String()}: {err: handlers.ForbiddenError()},
				{Id: org1.PublicId}:         {err: handlers.ForbiddenError()},
				{Id: org2.PublicId}:         {err: handlers.ForbiddenError()},
				{Id: proj1.PublicId}:        {outputFields: []string{globals.IdField, globals.NameField, globals.ScopeIdField, globals.DescriptionField, globals.VersionField, globals.TypeField}},
				{Id: proj2.PublicId}:        {err: handlers.ForbiddenError()},
			},
		},
		{
			name: "proj1 role grant this returns scopes under proj1 scope (nothing)",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj1.PublicId,
					Grants:      []string{"ids=*;type=scope;actions=read"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expected: map[*pbs.GetScopeRequest]expectedOutput{
				{Id: scope.Global.String()}: {err: handlers.ForbiddenError()},
				{Id: org1.PublicId}:         {err: handlers.ForbiddenError()},
				{Id: org2.PublicId}:         {err: handlers.ForbiddenError()},
				{Id: proj1.PublicId}:        {err: handlers.ForbiddenError()},
				{Id: proj2.PublicId}:        {err: handlers.ForbiddenError()},
			},
		},
		{
			name: "global role grant this scope pinned to org1 scope returns org1 scope",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{fmt.Sprintf("ids=%s;types=scope;actions=read;output_fields=id,name,scope_id,description,version,type,authorized_actions", org1.PublicId)},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expected: map[*pbs.GetScopeRequest]expectedOutput{
				{Id: scope.Global.String()}: {err: handlers.ForbiddenError()},
				{Id: org1.PublicId}:         {outputFields: []string{globals.IdField, globals.NameField, globals.ScopeIdField, globals.DescriptionField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField}},
				{Id: org2.PublicId}:         {err: handlers.ForbiddenError()},
				{Id: proj1.PublicId}:        {err: handlers.ForbiddenError()},
				{Id: proj2.PublicId}:        {err: handlers.ForbiddenError()},
			},
		},
		{
			name: "global role grant individual scopes (org1) returns org1 scopes",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=scope;actions=read;output_fields=id,name,scope_id,description,version,type,authorized_actions,created_time,updated_time"},
					GrantScopes: []string{org1.PublicId},
				},
			}),
			expected: map[*pbs.GetScopeRequest]expectedOutput{
				{Id: scope.Global.String()}: {err: handlers.ForbiddenError()},
				{Id: org1.PublicId}:         {err: handlers.ForbiddenError()},
				{Id: org2.PublicId}:         {err: handlers.ForbiddenError()},
				{Id: proj1.PublicId}:        {outputFields: []string{globals.IdField, globals.NameField, globals.ScopeIdField, globals.DescriptionField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, globals.CreatedTimeField, globals.UpdatedTimeField}},
				{Id: proj2.PublicId}:        {err: handlers.ForbiddenError()},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			for input, expectedOutput := range tc.expected {
				got, err := s.GetScope(fullGrantAuthCtx, input)
				// not found means expect error
				if expectedOutput.err != nil {
					require.ErrorIs(t, err, expectedOutput.err)
					continue
				}
				// check if the output fields are as expected
				if expectedOutput.outputFields != nil {
					handlers.TestAssertOutputFields(t, got.Item, expectedOutput.outputFields)
				}
				require.NoError(t, err)
			}
		})
	}
}

func TestGrants_CreateScopes(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := scopes.NewServiceFn(ctx, repoFn, kmsCache, 1000)
	require.NoError(t, err)

	org1 := iam.TestOrg(t, iamRepo, iam.WithName("org1"), iam.WithDescription("test org 1"), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	org2 := iam.TestOrg(t, iamRepo, iam.WithName("org2"), iam.WithDescription("test org 2"), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))

	testcases := []struct {
		name              string
		userFunc          func() (*iam.User, auth.Account)
		canCreateInScopes map[*pbs.CreateScopeRequest]error
	}{
		{
			name:     "no grants returns no creatable scopes",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{}),
			canCreateInScopes: map[*pbs.CreateScopeRequest]error{
				{Item: &pb.Scope{ScopeId: scope.Global.String()}}: handlers.ForbiddenError(),
				{Item: &pb.Scope{ScopeId: org1.PublicId}}:         handlers.ForbiddenError(),
				{Item: &pb.Scope{ScopeId: org2.PublicId}}:         handlers.ForbiddenError(),
			},
		},
		{
			name: "global role grant this can create scopes in the global scope",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=scope;actions=create"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			canCreateInScopes: map[*pbs.CreateScopeRequest]error{
				{Item: &pb.Scope{ScopeId: scope.Global.String()}}: nil,
				{Item: &pb.Scope{ScopeId: org1.PublicId}}:         handlers.ForbiddenError(),
				{Item: &pb.Scope{ScopeId: org2.PublicId}}:         handlers.ForbiddenError(),
			},
		},
		{
			name: "global role grant children can create scopes in org scopes",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=scope;actions=create"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			canCreateInScopes: map[*pbs.CreateScopeRequest]error{
				{Item: &pb.Scope{ScopeId: scope.Global.String()}}: handlers.ForbiddenError(),
				{Item: &pb.Scope{ScopeId: org1.PublicId}}:         nil,
				{Item: &pb.Scope{ScopeId: org2.PublicId}}:         nil,
			},
		},
		{
			name: "global role grant descendants can create scopes in org scopes",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=scope;actions=create"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
			}),
			canCreateInScopes: map[*pbs.CreateScopeRequest]error{
				{Item: &pb.Scope{ScopeId: scope.Global.String()}}: handlers.ForbiddenError(),
				{Item: &pb.Scope{ScopeId: org1.PublicId}}:         nil,
				{Item: &pb.Scope{ScopeId: org2.PublicId}}:         nil,
			},
		},
		{
			name: "global role individual grant to org1 can create scopes in org1 scope",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=scope;actions=create"},
					GrantScopes: []string{org1.PublicId},
				},
			}),
			canCreateInScopes: map[*pbs.CreateScopeRequest]error{
				{Item: &pb.Scope{ScopeId: scope.Global.String()}}: handlers.ForbiddenError(),
				{Item: &pb.Scope{ScopeId: org1.PublicId}}:         nil,
				{Item: &pb.Scope{ScopeId: org2.PublicId}}:         handlers.ForbiddenError(),
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

			for req, wantErr := range tc.canCreateInScopes {
				_, err := s.CreateScope(fullGrantAuthCtx, req)
				if wantErr != nil {
					require.ErrorIs(t, err, wantErr)
					continue
				}
				require.NoError(t, err)
			}
		})
	}
}

func TestGrants_ListKeyVersionDestructionJobs(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := scopes.NewServiceFn(ctx, repoFn, kmsCache, 1000)
	require.NoError(t, err)

	org1 := iam.TestOrg(t, iamRepo, iam.WithName("org1"), iam.WithDescription("test org 1"), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	org2 := iam.TestOrg(t, iamRepo, iam.WithName("org2"), iam.WithDescription("test org 2"), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	proj1 := iam.TestProject(t, iamRepo, org1.GetPublicId(), iam.WithName("proj1"), iam.WithDescription("test project 1"), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	proj2 := iam.TestProject(t, iamRepo, org2.GetPublicId(), iam.WithName("proj2"), iam.WithDescription("test project 2"), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))

	testcases := []struct {
		name            string
		userFunc        func() (*iam.User, auth.Account)
		canListInScopes map[string]error
	}{
		{
			name:     "no grants cannot list key version destruction jobs",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{}),
			canListInScopes: map[string]error{
				scope.Global.String(): handlers.ForbiddenError(),
				org1.PublicId:         handlers.ForbiddenError(),
				org2.PublicId:         handlers.ForbiddenError(),
				proj1.PublicId:        handlers.ForbiddenError(),
				proj2.PublicId:        handlers.ForbiddenError(),
			},
		},
		{
			name: "global role grant this can list key version destruction jobs in the global scope",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix,
				password.TestAuthMethodWithAccount,
				[]iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=scope;actions=list-key-version-destruction-jobs"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
			canListInScopes: map[string]error{
				scope.Global.String(): nil,
				org1.PublicId:         handlers.ForbiddenError(),
				org2.PublicId:         handlers.ForbiddenError(),
				proj1.PublicId:        handlers.ForbiddenError(),
				proj2.PublicId:        handlers.ForbiddenError(),
			},
		},
		{
			name: "global role grant children can list key version destruction jobs in org scopes",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix,
				password.TestAuthMethodWithAccount,
				[]iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=scope;actions=list-key-version-destruction-jobs"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
			canListInScopes: map[string]error{
				scope.Global.String(): handlers.ForbiddenError(),
				org1.PublicId:         nil,
				org2.PublicId:         nil,
				proj1.PublicId:        handlers.ForbiddenError(),
				proj2.PublicId:        handlers.ForbiddenError(),
			},
		},
		{
			name: "org1 role grant this can list key version destruction jobs in the org1 scope",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix,
				password.TestAuthMethodWithAccount,
				[]iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=scope;actions=list-key-version-destruction-jobs"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
			canListInScopes: map[string]error{
				scope.Global.String(): handlers.ForbiddenError(),
				org1.PublicId:         nil,
				org2.PublicId:         handlers.ForbiddenError(),
				proj1.PublicId:        handlers.ForbiddenError(),
				proj2.PublicId:        handlers.ForbiddenError(),
			},
		},
		{
			name: "org1 role grant children can list key version destruction jobs in its project scopes",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix,
				password.TestAuthMethodWithAccount,
				[]iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=scope;actions=list-key-version-destruction-jobs"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
			canListInScopes: map[string]error{
				scope.Global.String(): handlers.ForbiddenError(),
				org1.PublicId:         handlers.ForbiddenError(),
				org2.PublicId:         handlers.ForbiddenError(),
				proj1.PublicId:        nil,
				proj2.PublicId:        handlers.ForbiddenError(),
			},
		},
		{
			name: "global role grant descendants can list key version destruction jobs in its project scopes",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix,
				password.TestAuthMethodWithAccount,
				[]iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=scope;actions=list-key-version-destruction-jobs"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
			canListInScopes: map[string]error{
				scope.Global.String(): handlers.ForbiddenError(),
				org1.PublicId:         nil,
				org2.PublicId:         nil,
				proj1.PublicId:        nil,
				proj2.PublicId:        nil,
			},
		},
		{
			name: "global role grant org1 scope can list key version destruction jobs in the org1 scope",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix,
				password.TestAuthMethodWithAccount,
				[]iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=scope;actions=list-key-version-destruction-jobs"},
						GrantScopes: []string{org1.PublicId},
					},
				}),
			canListInScopes: map[string]error{
				scope.Global.String(): handlers.ForbiddenError(),
				org1.PublicId:         nil,
				org2.PublicId:         handlers.ForbiddenError(),
				proj1.PublicId:        handlers.ForbiddenError(),
				proj2.PublicId:        handlers.ForbiddenError(),
			},
		},
		{
			name: "global role grant to proj1 and proj2 role grant this can list key version destruction in granted projects",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix,
				password.TestAuthMethodWithAccount,
				[]iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=scope;actions=list-key-version-destruction-jobs"},
						GrantScopes: []string{proj1.PublicId},
					},
					{
						RoleScopeId: proj2.PublicId,
						Grants:      []string{"ids=*;type=scope;actions=list-key-version-destruction-jobs"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
			canListInScopes: map[string]error{
				scope.Global.String(): handlers.ForbiddenError(),
				org1.PublicId:         handlers.ForbiddenError(),
				org2.PublicId:         handlers.ForbiddenError(),
				proj1.PublicId:        nil,
				proj2.PublicId:        nil,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

			for scopeId, wantErr := range tc.canListInScopes {
				_, err = s.ListKeyVersionDestructionJobs(fullGrantAuthCtx, &pbs.ListKeyVersionDestructionJobsRequest{
					ScopeId: scopeId,
				})
				if wantErr != nil {
					require.ErrorIs(t, err, wantErr)
					continue
				}
				require.NoError(t, err)
			}
		})
	}
}

func TestGrants_List_AuthorizedAction(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	_, _ = iam.TestScopes(t, iamRepo)
	_, _ = iam.TestScopes(t, iamRepo)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := scopes.NewServiceFn(ctx, repoFn, kmsCache, 1000)
	require.NoError(t, err)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	user, account := iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
		{
			RoleScopeId: globals.GlobalPrefix,
			Grants:      []string{"ids=*;type=*;actions=*"},
			GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
		},
	})()
	tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
	require.NoError(t, err)
	fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
	got, err := s.ListScopes(fullGrantAuthCtx, &pbs.ListScopesRequest{ScopeId: globals.GlobalPrefix, Recursive: true})
	require.NoError(t, err)
	for _, item := range got.Items {
		switch item.GetType() {
		case "global":
			require.ElementsMatch(t, item.AuthorizedActions, []string{"no-op", "read", "update", "delete", "attach-storage-policy", "detach-storage-policy"})
			require.Len(t, item.AuthorizedCollectionActions, 11)
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Alias.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.AuthMethod.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.StorageBucket.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.AuthToken.PluralString()].AsSlice(), []string{"list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Group.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Role.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Scope.PluralString()].AsSlice(), []string{"create", "list", "list-keys", "rotate-keys", "list-key-version-destruction-jobs", "destroy-key-version"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.User.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Worker.PluralString()].AsSlice(), []string{"read-certificate-authority", "create-controller-led", "create-worker-led", "reinitialize-certificate-authority", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.SessionRecording.PluralString()].AsSlice(), []string{"list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Policy.PluralString()].AsSlice(), []string{"create", "list"})
		case "org":
			require.ElementsMatch(t, item.AuthorizedActions, []string{"no-op", "read", "update", "delete", "attach-storage-policy", "detach-storage-policy"})
			require.Len(t, item.AuthorizedCollectionActions, 9)
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.AuthMethod.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.StorageBucket.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.AuthToken.PluralString()].AsSlice(), []string{"list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Group.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Role.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Scope.PluralString()].AsSlice(), []string{"create", "list", "list-keys", "rotate-keys", "list-key-version-destruction-jobs", "destroy-key-version"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.User.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.SessionRecording.PluralString()].AsSlice(), []string{"list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Policy.PluralString()].AsSlice(), []string{"create", "list"})
		case "project":
			require.ElementsMatch(t, item.AuthorizedActions, []string{"no-op", "read", "update", "delete"})
			require.Len(t, item.AuthorizedCollectionActions, 7)
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.CredentialStore.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Group.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.HostCatalog.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Role.PluralString()].AsSlice(), []string{"create", "list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Scope.PluralString()].AsSlice(), []string{"list-keys", "rotate-keys", "list-key-version-destruction-jobs", "destroy-key-version"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Session.PluralString()].AsSlice(), []string{"list"})
			require.ElementsMatch(t, item.AuthorizedCollectionActions[resource.Target.PluralString()].AsSlice(), []string{"create", "list"})
		default:
			t.Fatalf("unknown item type: %s", item.GetType())
		}
	}
}
