// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package authmethods_test

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	controllerauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/authmethods"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authmethods"
	"github.com/stretchr/testify/require"
)

// expectedOutput consolidates common output fields for the test cases
type expectedOutput struct {
	wantErr       error
	wantOutfields []string
}

// TestGrants_ReadActions tests read actions to assert that grants are being applied properly
func TestGrants_ReadActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kmsCache)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kmsCache)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return atRepo, nil
	}
	authMethodRepoFn := func() (*auth.AuthMethodRepository, error) {
		return auth.NewAuthMethodRepository(ctx, rw, rw, kmsCache)
	}

	s, err := authmethods.NewService(ctx,
		kmsCache,
		pwRepoFn,
		oidcRepoFn,
		iamRepoFn,
		atRepoFn,
		ldapRepoFn,
		authMethodRepoFn,
		1000)
	require.NoError(t, err)
	org1, _ := iam.TestScopes(t, iamRepo)
	org2, _ := iam.TestScopes(t, iamRepo)

	// Need to create a wrapper for each scope (global, org1, org2) to test grants against OIDC/LDAP at that scope
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), globals.GlobalPrefix, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	databaseWrapperOrg1, err := kmsCache.GetWrapper(context.Background(), org1.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)
	databaseWrapperOrg2, err := kmsCache.GetWrapper(context.Background(), org2.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)

	// Create OIDC/LDAP/Password auth methods for each scope
	oidcGlobal := oidc.TestAuthMethod(t, conn, databaseWrapper, globals.GlobalPrefix, oidc.InactiveState, "client-id", "secret", oidc.WithName("oidc-global"), oidc.WithDescription("test oidc desc"))
	oidcOrg1 := oidc.TestAuthMethod(t, conn, databaseWrapperOrg1, org1.GetPublicId(), oidc.InactiveState, "client-id", "secret", oidc.WithName("oidc-org-1"), oidc.WithDescription("test oidc desc"))
	oidcOrg2 := oidc.TestAuthMethod(t, conn, databaseWrapperOrg2, org2.GetPublicId(), oidc.InactiveState, "client-id", "secret", oidc.WithName("oidc-org-2"), oidc.WithDescription("test oidc desc"))

	ldapGlobal := ldap.TestAuthMethod(t, conn, databaseWrapper, globals.GlobalPrefix, []string{"ldaps://alice.com"}, ldap.WithName(ctx, "ldap-global"), ldap.WithDescription(ctx, "test ldap desc"))
	ldapOrg1 := ldap.TestAuthMethod(t, conn, databaseWrapperOrg1, org1.GetPublicId(), []string{"ldaps://alice.com"}, ldap.WithName(ctx, "ldap-org-1"), ldap.WithDescription(ctx, "test ldap desc"))
	ldapOrg2 := ldap.TestAuthMethod(t, conn, databaseWrapperOrg2, org2.GetPublicId(), []string{"ldaps://alice.com"}, ldap.WithName(ctx, "ldap-org-2"), ldap.WithDescription(ctx, "test ldap desc"))

	pwGlobal := password.TestAuthMethod(t, conn, globals.GlobalPrefix, password.WithName("pw-global"), password.WithDescription("test pw desc"))
	pwOrg1 := password.TestAuthMethod(t, conn, org1.GetPublicId(), password.WithName("pw-org-1"), password.WithDescription("test pw desc"))
	pwOrg2 := password.TestAuthMethod(t, conn, org2.GetPublicId(), password.WithName("pw-org-2"), password.WithDescription("test pw desc"))

	// ignoreList consists of auth method IDs to omit from the result set
	// this is to handle auth methods that are created during the auth token
	// creation
	ignoreList := []string{}

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name            string
			input           *pbs.ListAuthMethodsRequest
			userFunc        func() (*iam.User, auth.Account)
			wantErr         error
			wantIDs         []string
			expectOutfields map[string][]string
		}{
			{
				name:  "global role grant this only returns global auth methods",
				input: &pbs.ListAuthMethodsRequest{ScopeId: globals.GlobalPrefix},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope_id,name,description,type,created_time,updated_time,version,type"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantIDs: []string{
					oidcGlobal.PublicId,
					ldapGlobal.PublicId,
					pwGlobal.PublicId,
				},
				expectOutfields: map[string][]string{
					oidcGlobal.PublicId: {globals.IdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField},
					ldapGlobal.PublicId: {globals.IdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField},
					pwGlobal.PublicId:   {globals.IdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField},
				},
			},
			{
				name: "global role grant this recursively returns all auth methods",
				input: &pbs.ListAuthMethodsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-method;actions=list,no-op;output_fields=id,scope,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantIDs: []string{
					oidcGlobal.PublicId,
					oidcOrg1.PublicId,
					oidcOrg2.PublicId,
					ldapGlobal.PublicId,
					ldapOrg1.PublicId,
					ldapOrg2.PublicId,
					pwGlobal.PublicId,
					pwOrg1.PublicId,
					pwOrg2.PublicId,
				},
				expectOutfields: map[string][]string{
					oidcGlobal.PublicId: {globals.IdField, globals.ScopeField, globals.AuthorizedActionsField},
					ldapGlobal.PublicId: {globals.IdField, globals.ScopeField, globals.AuthorizedActionsField},
					pwGlobal.PublicId:   {globals.IdField, globals.ScopeField, globals.AuthorizedActionsField},
				},
			},
			{
				name: "global role grant this and children returns global auth methods",
				input: &pbs.ListAuthMethodsRequest{
					ScopeId: globals.GlobalPrefix,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-method;actions=list,no-op;output_fields=id,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantIDs: []string{
					oidcGlobal.PublicId,
					ldapGlobal.PublicId,
					pwGlobal.PublicId,
				},
				expectOutfields: map[string][]string{
					oidcGlobal.PublicId: {globals.IdField, globals.AuthorizedActionsField},
					ldapGlobal.PublicId: {globals.IdField, globals.AuthorizedActionsField},
					pwGlobal.PublicId:   {globals.IdField, globals.AuthorizedActionsField},
				},
			},
			{
				name: "global role grant this and children recursive returns all auth methods",
				input: &pbs.ListAuthMethodsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-method;actions=list,no-op;output_fields=id,name"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantIDs: []string{
					oidcGlobal.PublicId,
					oidcOrg1.PublicId,
					oidcOrg2.PublicId,
					ldapGlobal.PublicId,
					ldapOrg1.PublicId,
					ldapOrg2.PublicId,
					pwGlobal.PublicId,
					pwOrg1.PublicId,
					pwOrg2.PublicId,
				},
				expectOutfields: map[string][]string{
					oidcGlobal.PublicId: {globals.IdField, globals.NameField},
					oidcOrg1.PublicId:   {globals.IdField, globals.NameField},
					oidcOrg2.PublicId:   {globals.IdField, globals.NameField},
					ldapGlobal.PublicId: {globals.IdField, globals.NameField},
					ldapOrg1.PublicId:   {globals.IdField, globals.NameField},
					ldapOrg2.PublicId:   {globals.IdField, globals.NameField},
					pwGlobal.PublicId:   {globals.IdField, globals.NameField},
					pwOrg1.PublicId:     {globals.IdField, globals.NameField},
					pwOrg2.PublicId:     {globals.IdField, globals.NameField},
				},
			},
			{
				name: "no grants return children org",
				input: &pbs.ListAuthMethodsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{},
						GrantScopes: []string{},
					},
				}),
				wantErr: nil,
				// auth methods in `global` are filtered out because the user does not have grants to read
				// them in the global scope. Auth methods in org 1 and org 2 show up - my guess is because
				// the u_anon grants allow auth methods to be read on any org.
				wantIDs: []string{
					// oidcGlobal.PublicId,
					oidcOrg1.PublicId,
					oidcOrg2.PublicId,
					// ldapGlobal.PublicId,
					ldapOrg1.PublicId,
					ldapOrg2.PublicId,
					// pwGlobal.PublicId,
					pwOrg1.PublicId,
					pwOrg2.PublicId,
				},
				expectOutfields: map[string][]string{},
			},
			{
				name: "org role grant this and children returns auth methods in org1",
				input: &pbs.ListAuthMethodsRequest{
					ScopeId: org1.PublicId,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=auth-method;actions=list,no-op;output_fields=id,scope_id,name,description,type,created_time,updated_time,version,type"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantIDs: []string{
					oidcOrg1.PublicId,
					ldapOrg1.PublicId,
					pwOrg1.PublicId,
				},
				expectOutfields: map[string][]string{
					oidcOrg1.PublicId: {globals.IdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField},
					ldapOrg1.PublicId: {globals.IdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField},
					pwOrg1.PublicId:   {globals.IdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField},
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

				// auth method created during token generation will not be taken into considerations during this test
				// adding to the ignoreList so it can be ignored later
				ignoreList = append(ignoreList, tok.GetAuthMethodId())

				got, finalErr := s.ListAuthMethods(fullGrantAuthCtx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, finalErr, tc.wantErr)
					return
				}
				require.NoError(t, finalErr)
				var gotIDs []string
				for _, g := range got.Items {
					// do not include IDs in the ignore list in the result sets
					if slices.Contains(ignoreList, g.Id) {
						continue
					}
					gotIDs = append(gotIDs, g.GetId())

					// check if the output fields are as expected
					if tc.expectOutfields[g.Id] != nil {
						handlers.TestAssertOutputFields(t, g, tc.expectOutfields[g.Id])
					}
				}
				require.ElementsMatch(t, tc.wantIDs, gotIDs)
			})
		}
	})

	t.Run("Get", func(t *testing.T) {
		testcases := []struct {
			name             string
			userFunc         func() (*iam.User, auth.Account)
			canGetAuthMethod map[string]expectedOutput
		}{
			{
				name: "global role grant this can only get global auth methods",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope_id,name,description,type,created_time,updated_time,version,type"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canGetAuthMethod: map[string]expectedOutput{
					pwGlobal.PublicId:   {wantOutfields: []string{globals.IdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField}},
					pwOrg1.PublicId:     {wantErr: handlers.ForbiddenError()},
					pwOrg2.PublicId:     {wantErr: handlers.ForbiddenError()},
					oidcGlobal.PublicId: {wantOutfields: []string{globals.IdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField}},
					oidcOrg1.PublicId:   {wantErr: handlers.ForbiddenError()},
					oidcOrg2.PublicId:   {wantErr: handlers.ForbiddenError()},
					ldapGlobal.PublicId: {wantOutfields: []string{globals.IdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField}},
					ldapOrg1.PublicId:   {wantErr: handlers.ForbiddenError()},
					ldapOrg2.PublicId:   {wantErr: handlers.ForbiddenError()},
				},
			},
			{
				name: "global role grant children can only get org auth methods",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,name,description"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				canGetAuthMethod: map[string]expectedOutput{
					pwGlobal.PublicId:   {wantErr: handlers.ForbiddenError()},
					pwOrg1.PublicId:     {wantOutfields: []string{globals.IdField, globals.NameField, globals.DescriptionField}},
					pwOrg2.PublicId:     {wantOutfields: []string{globals.IdField, globals.NameField, globals.DescriptionField}},
					oidcGlobal.PublicId: {wantErr: handlers.ForbiddenError()},
					oidcOrg1.PublicId:   {wantOutfields: []string{globals.IdField, globals.NameField, globals.DescriptionField}},
					oidcOrg2.PublicId:   {wantOutfields: []string{globals.IdField, globals.NameField, globals.DescriptionField}},
					ldapGlobal.PublicId: {wantErr: handlers.ForbiddenError()},
					ldapOrg1.PublicId:   {wantOutfields: []string{globals.IdField, globals.NameField, globals.DescriptionField}},
					ldapOrg2.PublicId:   {wantOutfields: []string{globals.IdField, globals.NameField, globals.DescriptionField}},
				},
			},
			{
				name: "global role grant descendants can only get org auth methods",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,created_time,updated_time,version"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				canGetAuthMethod: map[string]expectedOutput{
					pwGlobal.PublicId:   {wantErr: handlers.ForbiddenError()},
					pwOrg1.PublicId:     {wantOutfields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
					pwOrg2.PublicId:     {wantOutfields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
					oidcGlobal.PublicId: {wantErr: handlers.ForbiddenError()},
					oidcOrg1.PublicId:   {wantOutfields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
					oidcOrg2.PublicId:   {wantOutfields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
					ldapGlobal.PublicId: {wantErr: handlers.ForbiddenError()},
					ldapOrg1.PublicId:   {wantOutfields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
					ldapOrg2.PublicId:   {wantOutfields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
				},
			},
			{
				name: "global role grant this and children with all permissions returns all auth methods",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,created_time,updated_time,version"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				canGetAuthMethod: map[string]expectedOutput{
					pwGlobal.PublicId:   {wantOutfields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
					pwOrg1.PublicId:     {wantOutfields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
					pwOrg2.PublicId:     {wantOutfields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
					oidcGlobal.PublicId: {wantOutfields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
					oidcOrg1.PublicId:   {wantOutfields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
					oidcOrg2.PublicId:   {wantOutfields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
					ldapGlobal.PublicId: {wantOutfields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
					ldapOrg1.PublicId:   {wantOutfields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
					ldapOrg2.PublicId:   {wantOutfields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
				},
			},
			{
				name: "org1 role grant this scope with all permissions",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.GetPublicId(),
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope_id,type"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canGetAuthMethod: map[string]expectedOutput{
					pwGlobal.PublicId:   {wantErr: handlers.ForbiddenError()},
					pwOrg1.PublicId:     {wantOutfields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField}},
					pwOrg2.PublicId:     {wantErr: handlers.ForbiddenError()},
					oidcGlobal.PublicId: {wantErr: handlers.ForbiddenError()},
					oidcOrg1.PublicId:   {wantOutfields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField}},
					oidcOrg2.PublicId:   {wantErr: handlers.ForbiddenError()},
					ldapGlobal.PublicId: {wantErr: handlers.ForbiddenError()},
					ldapOrg1.PublicId:   {wantOutfields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField}},
					ldapOrg2.PublicId:   {wantErr: handlers.ForbiddenError()},
				},
			},
			{
				name:     "no grants returns no auth methods",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, nil),
				canGetAuthMethod: map[string]expectedOutput{
					pwGlobal.PublicId:   {wantErr: handlers.ForbiddenError()},
					pwOrg1.PublicId:     {wantErr: handlers.ForbiddenError()},
					pwOrg2.PublicId:     {wantErr: handlers.ForbiddenError()},
					oidcGlobal.PublicId: {wantErr: handlers.ForbiddenError()},
					oidcOrg1.PublicId:   {wantErr: handlers.ForbiddenError()},
					oidcOrg2.PublicId:   {wantErr: handlers.ForbiddenError()},
					ldapGlobal.PublicId: {wantErr: handlers.ForbiddenError()},
					ldapOrg1.PublicId:   {wantErr: handlers.ForbiddenError()},
					ldapOrg2.PublicId:   {wantErr: handlers.ForbiddenError()},
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				for id, expectedOutput := range tc.canGetAuthMethod {
					input := &pbs.GetAuthMethodRequest{Id: id}
					_, err := s.GetAuthMethod(fullGrantAuthCtx, input)
					if expectedOutput.wantErr != nil {
						require.ErrorIs(t, err, expectedOutput.wantErr)
						continue
					}
					// check if the output fields are as expected
					if tc.canGetAuthMethod[id].wantOutfields != nil {
						handlers.TestAssertOutputFields(t, input, tc.canGetAuthMethod[id].wantOutfields)
					}
					require.NoError(t, err)
				}
			})
		}
	})
}

// TestGrants_WriteActions tests write actions to assert that grants are being applied properly
func TestGrants_WriteActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kmsCache)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kmsCache)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return atRepo, nil
	}
	authMethodRepoFn := func() (*auth.AuthMethodRepository, error) {
		return auth.NewAuthMethodRepository(ctx, rw, rw, kmsCache)
	}

	s, err := authmethods.NewService(ctx,
		kmsCache,
		pwRepoFn,
		oidcRepoFn,
		iamRepoFn,
		atRepoFn,
		ldapRepoFn,
		authMethodRepoFn,
		1000)
	require.NoError(t, err)
	org1, _ := iam.TestScopes(t, iamRepo)
	org2, _ := iam.TestScopes(t, iamRepo)

	t.Run("Create", func(t *testing.T) {
		testcases := []struct {
			name             string
			userFunc         func() (*iam.User, auth.Account)
			canCreateInScope map[string]expectedOutput
		}{
			{
				name: "direct grant all can create all",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope_id,name,description,type,created_time,updated_time,version"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				canCreateInScope: map[string]expectedOutput{
					globals.GlobalPrefix: {wantOutfields: []string{globals.IdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
					org1.PublicId:        {wantOutfields: []string{globals.IdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
					org2.PublicId:        {wantOutfields: []string{globals.IdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
				},
			},
			{
				name: "global role grant children can only create org auth methods",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-method;actions=create;output_fields=id,scope_id,created_time"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				canCreateInScope: map[string]expectedOutput{
					globals.GlobalPrefix: {wantErr: handlers.ForbiddenError()},
					org1.PublicId:        {wantOutfields: []string{globals.IdField, globals.ScopeIdField, globals.CreatedTimeField}},
					org2.PublicId:        {wantOutfields: []string{globals.IdField, globals.ScopeIdField, globals.CreatedTimeField}},
				},
			},
			{
				name: "org role can't create global auth methods nor auth methods in other orgs",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org2.PublicId,
						Grants:      []string{"ids=*;type=auth-method;actions=create;output_fields=id,name,description"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canCreateInScope: map[string]expectedOutput{
					globals.GlobalPrefix: {wantErr: handlers.ForbiddenError()},
					org1.PublicId:        {wantErr: handlers.ForbiddenError()},
					org2.PublicId:        {wantOutfields: []string{globals.IdField, globals.NameField, globals.DescriptionField}},
				},
			},
			{
				name: "incorrect grants returns 403 error",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-method;actions=list,read,update;output_fields=id,scope_id"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=auth-method;actions=list,read,update;output_fields=id,name"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canCreateInScope: map[string]expectedOutput{
					globals.GlobalPrefix: {wantErr: handlers.ForbiddenError()},
					org1.PublicId:        {wantErr: handlers.ForbiddenError()},
					org2.PublicId:        {wantErr: handlers.ForbiddenError()},
				},
			},
			{
				name:     "no grants returns 403 error",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, nil),
				canCreateInScope: map[string]expectedOutput{
					globals.GlobalPrefix: {wantErr: handlers.ForbiddenError()},
					org1.PublicId:        {wantErr: handlers.ForbiddenError()},
					org2.PublicId:        {wantErr: handlers.ForbiddenError()},
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

				for scopeId, expectedOutput := range tc.canCreateInScope {
					// Build a distinct name for each Auth Method
					name := fmt.Sprintf("[%s] ", tc.name)
					switch scopeId {
					case globals.GlobalPrefix:
						name += "global"
					case org1.PublicId:
						name += "org 1"
					case org2.PublicId:
						name += "org 2"
					default:
						t.Fatalf("Unexpected scope ID: %s", scopeId)
					}

					resp, err := s.CreateAuthMethod(fullGrantAuthCtx, &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
						Name:        wrapperspb.String(name),
						Description: wrapperspb.String("test description"),
						ScopeId:     scopeId,
						Type:        "password",
					}})
					if expectedOutput.wantErr != nil {
						require.ErrorIs(t, err, expectedOutput.wantErr)
						continue
					}
					require.NoError(t, err)
					handlers.TestAssertOutputFields(t, resp.Item, expectedOutput.wantOutfields)
				}
			})
		}
	})

	t.Run("Update", func(t *testing.T) {
		// Create global & org auth methods to test updates
		globalAmId := password.TestAuthMethod(t, conn, globals.GlobalPrefix, password.WithName("global name"), password.WithDescription("global desc")).PublicId
		org1AmId := password.TestAuthMethod(t, conn, org1.PublicId, password.WithName("org 1 name"), password.WithDescription("org 2 desc")).PublicId
		org2AmId := password.TestAuthMethod(t, conn, org2.PublicId, password.WithName("org 2 name"), password.WithDescription("org 2 desc")).PublicId

		testcases := []struct {
			name                string
			rolesToCreate       []authtoken.TestRoleGrantsForToken
			canUpdateAuthMethod map[string]expectedOutput
		}{
			{
				name: "global role grant this and children can update global auth method",
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=auth-method;actions=update;output_fields=id,scope_id,name,description,type,version"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
				canUpdateAuthMethod: map[string]expectedOutput{
					globalAmId: {wantOutfields: []string{globals.IdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.TypeField, globals.VersionField}},
					org1AmId:   {wantOutfields: []string{globals.IdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.TypeField, globals.VersionField}},
					org2AmId:   {wantOutfields: []string{globals.IdField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.TypeField, globals.VersionField}},
				},
			},
			{
				name: "global role grant this & org role grant this can update their respective auth methods",
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=auth-method;actions=update;output_fields=id,name,description,version"},
						GrantScopes:  []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId:  org1.PublicId,
						GrantStrings: []string{"ids=*;type=auth-method;actions=update;output_fields=id,scope_id,type,version"},
						GrantScopes:  []string{globals.GrantScopeThis},
					},
				},
				canUpdateAuthMethod: map[string]expectedOutput{
					globalAmId: {wantOutfields: []string{globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField}},
					org1AmId:   {wantOutfields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.VersionField}},
					org2AmId:   {wantErr: handlers.ForbiddenError()},
				},
			},
			{
				name: "org role can't update global auth methods",
				rolesToCreate: []authtoken.TestRoleGrantsForToken{{
					RoleScopeId:  org1.PublicId,
					GrantStrings: []string{"ids=*;type=auth-method;actions=update;output_fields=id,version,created_time,updated_time"},
					GrantScopes:  []string{globals.GrantScopeThis},
				}},
				canUpdateAuthMethod: map[string]expectedOutput{
					globalAmId: {wantErr: handlers.ForbiddenError()},
					org1AmId:   {wantOutfields: []string{globals.IdField, globals.VersionField, globals.CreatedTimeField, globals.UpdatedTimeField}},
					org2AmId:   {wantErr: handlers.ForbiddenError()},
				},
			},
			{
				name: "incorrect grants returns 403 error",
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=auth-method;actions=list,read,create"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
					{
						RoleScopeId:  org1.PublicId,
						GrantStrings: []string{"ids=*;type=auth-method;actions=list,read,create"},
						GrantScopes:  []string{globals.GrantScopeThis},
					},
				},
				canUpdateAuthMethod: map[string]expectedOutput{
					globalAmId: {wantErr: handlers.ForbiddenError()},
					org1AmId:   {wantErr: handlers.ForbiddenError()},
					org2AmId:   {wantErr: handlers.ForbiddenError()},
				},
			},
			{
				name:          "no grants returns 403 error",
				rolesToCreate: []authtoken.TestRoleGrantsForToken{},
				canUpdateAuthMethod: map[string]expectedOutput{
					globalAmId: {wantErr: handlers.ForbiddenError()},
					org1AmId:   {wantErr: handlers.ForbiddenError()},
					org2AmId:   {wantErr: handlers.ForbiddenError()},
				},
			},
		}

		for i, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				tok := authtoken.TestAuthTokenWithRoles(t, conn, kmsCache, globals.GlobalPrefix, tc.rolesToCreate)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

				for amId, expectedOutput := range tc.canUpdateAuthMethod {
					resp, err := s.UpdateAuthMethod(fullGrantAuthCtx, &pbs.UpdateAuthMethodRequest{
						Id: amId,
						UpdateMask: &field_mask.FieldMask{
							Paths: []string{"name", "description"},
						},
						Item: &pb.AuthMethod{
							Name:        &wrapperspb.StringValue{Value: fmt.Sprintf("updated name (%d)", i)},
							Description: &wrapperspb.StringValue{Value: fmt.Sprintf("updated description (%d)", i)},
							Version:     uint32(i + 1), // increment version to simulate an update
						},
					})
					if expectedOutput.wantErr != nil {
						require.ErrorIs(t, err, expectedOutput.wantErr)
						return
					}
					require.NoError(t, err)
					handlers.TestAssertOutputFields(t, resp.Item, expectedOutput.wantOutfields)
				}
			})
		}
	})

	t.Run("Delete", func(t *testing.T) {
		allScopeIDs := []string{globals.GlobalPrefix, org1.PublicId, org2.PublicId}
		testcases := []struct {
			name                    string
			am                      *password.AuthMethod
			userFunc                func() (*iam.User, auth.Account)
			deleteAllowedAtScopeIDs []string
		}{
			{
				name: "grant all can delete all",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				deleteAllowedAtScopeIDs: allScopeIDs,
			},
			{
				name: "grant children can only delete in orgs",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				deleteAllowedAtScopeIDs: []string{org1.PublicId, org2.PublicId},
			},
			{
				name: "org role can't delete global auth methods",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=auth-method;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				deleteAllowedAtScopeIDs: []string{org1.PublicId},
			},
			{
				name: "incorrect grants returns 403 error",
				am:   password.TestAuthMethod(t, conn, org1.PublicId),
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-method;actions=list,read,create,update"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
			},
			{
				name:     "no grants returns 403 error",
				am:       password.TestAuthMethod(t, conn, globals.GlobalPrefix),
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, nil),
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				// setup a map to track which scope correlates to an auth method
				scopeIdAuthMethodMap := map[string]*password.AuthMethod{}
				for _, scopeId := range allScopeIDs {
					am := password.TestAuthMethod(t, conn, scopeId)
					scopeIdAuthMethodMap[scopeId] = am
				}
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				for scope, am := range scopeIdAuthMethodMap {
					_, err = s.DeleteAuthMethod(fullGrantAuthCtx, &pbs.DeleteAuthMethodRequest{Id: am.PublicId})
					if !slices.Contains(tc.deleteAllowedAtScopeIDs, scope) {
						require.ErrorIs(t, err, handlers.ForbiddenError())
						continue
					}
					require.NoErrorf(t, err, "failed to delete auth method in scope %s", scope)
				}
			})
		}
	})

	t.Run("Authenticate", func(t *testing.T) {
		pwRepo, err := pwRepoFn()
		require.NoError(t, err)

		// We need a sys eventer in order to authenticate
		eventConfig := event.TestEventerConfig(t, "TestGrants_WriteActions", event.TestWithObservationSink(t))
		testLock := &sync.Mutex{}
		testLogger := hclog.New(&hclog.LoggerOptions{
			Mutex: testLock,
			Name:  "test",
		})

		require.NoError(t, event.InitSysEventer(testLogger, testLock, "TestGrants_WriteActions", event.WithEventerConfig(&eventConfig.EventerConfig)))
		sinkFileName := eventConfig.ObservationEvents.Name()
		t.Cleanup(func() {
			require.NoError(t, os.Remove(sinkFileName))
			event.TestResetSystEventer(t)
		})

		testcases := []struct {
			name          string
			scopeId       string
			input         *pbs.AuthenticateRequest
			userFunc      func() (*iam.User, auth.Account)
			rolesToCreate []authtoken.TestRoleGrantsForToken
			wantErr       error
		}{
			{
				name:    "global role grant this and children can authenticate against a global auth method",
				scopeId: globals.GlobalPrefix,
				input: &pbs.AuthenticateRequest{
					TokenType: "token",
					Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
						PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
							LoginName: testLoginName,
							Password:  testPassword,
						},
					},
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-method;actions=authenticate"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				rolesToCreate: []authtoken.TestRoleGrantsForToken{{
					RoleScopeId:  globals.GlobalPrefix,
					GrantStrings: []string{"ids=*;type=auth-method;actions=authenticate"},
					GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				}},
			},
			{
				name:    "org role can't authenticate against a global auth method",
				scopeId: globals.GlobalPrefix,
				input: &pbs.AuthenticateRequest{
					TokenType: "token",
					Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
						PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
							LoginName: testLoginName,
							Password:  testPassword,
						},
					},
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{{
					RoleScopeId:  org1.PublicId,
					GrantStrings: []string{"ids=*;type=auth-method;actions=authenticate"},
					GrantScopes:  []string{globals.GrantScopeThis},
				}},
				wantErr: handlers.ForbiddenError(),
			},
			{
				name:    "no grants returns 403 error for a global auth method",
				scopeId: globals.GlobalPrefix,
				input: &pbs.AuthenticateRequest{
					TokenType: "token",
					Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
						PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
							LoginName: testLoginName,
							Password:  testPassword,
						},
					},
				},
				wantErr: handlers.ForbiddenError(),
			},
			{
				name:    "org scopes grant anyone permission to authenticate (and list) auth methods by default",
				scopeId: org1.PublicId,
				input: &pbs.AuthenticateRequest{
					TokenType: "token",
					Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
						PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
							LoginName: testLoginName,
							Password:  testPassword,
						},
					},
				},
			},
			{
				name:    "granting authenticate again at the org scope allows authentication",
				scopeId: org1.PublicId,
				input: &pbs.AuthenticateRequest{
					TokenType: "token",
					Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
						PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
							LoginName: testLoginName,
							Password:  testPassword,
						},
					},
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{{
					RoleScopeId:  org1.PublicId,
					GrantStrings: []string{"ids=*;type=auth-method;actions=authenticate"},
					GrantScopes:  []string{globals.GrantScopeThis},
				}},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				// Create auth method
				if tc.scopeId == globals.GlobalPrefix {
					tc.input.AuthMethodId = password.TestAuthMethod(t, conn, globals.GlobalPrefix).PublicId
				} else {
					tc.input.AuthMethodId = password.TestAuthMethod(t, conn, org1.PublicId).PublicId
				}

				// Create account for the auth method
				account, err := password.NewAccount(ctx, tc.input.AuthMethodId, password.WithLoginName(testLoginName))
				require.NoError(t, err)
				account, err = pwRepo.CreateAccount(context.Background(), tc.scopeId, account, password.WithPassword(testPassword))
				require.NoError(t, err)
				require.NotNil(t, account)

				// Create user linked to the account
				user := iam.TestUser(t, iamRepo, tc.scopeId, iam.WithAccountIds(account.PublicId))

				// Create the desired role/grants for the user
				for _, roleToCreate := range tc.rolesToCreate {
					role := iam.TestRoleWithGrants(t, conn, roleToCreate.RoleScopeId, roleToCreate.GrantScopes, roleToCreate.GrantStrings)
					iam.TestUserRole(t, conn, role.PublicId, user.PublicId)
				}
				// user, accountID := tc.userFunc()

				// Create auth token for the user
				tok, err := atRepo.CreateAuthToken(ctx, user, account.PublicId)
				require.NoError(t, err)
				ctx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

				_, err = s.Authenticate(ctx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, err, tc.wantErr)
					return
				}
				require.NoError(t, err)
			})
		}
	})
}
