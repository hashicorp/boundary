// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credentials_test

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
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static"
	controllerauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/credentials"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentials"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	// UsernamePasswordAttributesField is the field name for the UsernamePassword subtype of the `Credential.Attrs` attributes field
	//
	// When the "attributes" field is specified as an output_field and can be one of many sub-types, the expected output field must be the corresponding sub-type and not `globals.AttributesField`
	UsernamePasswordAttributesField = "username_password_attributes"
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
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kmsCache)
	}
	s, err := credentials.NewService(ctx, iamRepoFn, staticRepoFn, 1000)
	require.NoError(t, err)

	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	org, proj := iam.TestScopes(t, iamRepo)

	credStore := static.TestCredentialStore(t, conn, wrap, proj.GetPublicId())
	var credIds []string
	for i := range 5 {
		user := fmt.Sprintf("user-%d", i)
		pass := fmt.Sprintf("pass-%d", i)
		c := static.TestUsernamePasswordCredential(t, conn, wrap, user, pass, credStore.GetPublicId(), proj.GetPublicId(), static.WithName(fmt.Sprintf("cred-%d", i)), static.WithDescription(fmt.Sprintf("desc-%d", i)))
		credIds = append(credIds, c.GetPublicId())
	}

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name          string
			userFunc      func() (*iam.User, auth.Account)
			wantErr       error
			wantOutfields map[string][]string
		}{
			{
				name: "global role grant this returns 403 because credentials live on projects",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "org role grant this returns 403 because credentials live on projects",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.GetPublicId(),
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "project role grant this returns all credentials on the project",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantOutfields: map[string][]string{
					credIds[0]: {globals.IdField},
					credIds[1]: {globals.IdField},
					credIds[2]: {globals.IdField},
					credIds[3]: {globals.IdField},
					credIds[4]: {globals.IdField},
				},
			},
			{
				name: "global role grant this & children returns 403 because credentials live on projects",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "org role grant children returns all credentials on child projects",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,credential_store_id,scope,name,description,created_time,updated_time,version,type,authorized_actions,attributes"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				wantOutfields: map[string][]string{
					credIds[0]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, UsernamePasswordAttributesField},
					credIds[1]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, UsernamePasswordAttributesField},
					credIds[2]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, UsernamePasswordAttributesField},
					credIds[3]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, UsernamePasswordAttributesField},
					credIds[4]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, UsernamePasswordAttributesField},
				},
			},
			{
				name: "global role grant this & descendants returns all credentials on descendant projects",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantOutfields: map[string][]string{
					credIds[0]: {globals.IdField, globals.ScopeField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					credIds[1]: {globals.IdField, globals.ScopeField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					credIds[2]: {globals.IdField, globals.ScopeField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					credIds[3]: {globals.IdField, globals.ScopeField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					credIds[4]: {globals.IdField, globals.ScopeField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField},
				},
			},
			{
				name: "project role grant this returns all credentials on the project",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,credential_store_id,scope,name,description,created_time,updated_time,version,type,authorized_actions,attributes"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantOutfields: map[string][]string{
					credIds[0]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, UsernamePasswordAttributesField},
					credIds[1]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, UsernamePasswordAttributesField},
					credIds[2]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, UsernamePasswordAttributesField},
					credIds[3]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, UsernamePasswordAttributesField},
					credIds[4]: {globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, UsernamePasswordAttributesField},
				},
			},
			{
				name: "global role grant with credential-store id, list action, credential type, and descendant scope returns all credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=" + credStore.PublicId + ";type=credential;actions=list,no-op;output_fields=id,name,description,credential_store_id"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				wantOutfields: map[string][]string{
					credIds[0]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.CredentialStoreIdField},
					credIds[1]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.CredentialStoreIdField},
					credIds[2]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.CredentialStoreIdField},
					credIds[3]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.CredentialStoreIdField},
					credIds[4]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.CredentialStoreIdField},
				},
			},
			{
				name: "org role grant with credential-store id, list action, credential type, and children scope returns all credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=" + credStore.PublicId + ";type=credential;actions=list,no-op;output_fields=id,name,description,version,credential_store_id"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				wantOutfields: map[string][]string{
					credIds[0]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
					credIds[1]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
					credIds[2]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
					credIds[3]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
					credIds[4]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
				},
			},
			{
				name: "project role grant with credential-store id, list action, credential type, and this scope returns all credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + credStore.PublicId + ";type=credential;actions=list,no-op;output_fields=id,name,description,version,credential_store_id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantOutfields: map[string][]string{
					credIds[0]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
					credIds[1]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
					credIds[2]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
					credIds[3]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
					credIds[4]: {globals.IdField, globals.NameField, globals.DescriptionField, globals.VersionField, globals.CredentialStoreIdField},
				},
			},
			{
				name: "incorrect grants can't list credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=credential;actions=read,create,update,delete"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name:     "no grants returns 403",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, nil),
				wantErr:  handlers.ForbiddenError(),
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

				got, finalErr := s.ListCredentials(fullGrantAuthCtx, &pbs.ListCredentialsRequest{CredentialStoreId: credStore.GetPublicId()})
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
			name             string
			userFunc         func() (*iam.User, auth.Account)
			canGetCredential map[string]expectedOutput
		}{
			{
				name: "global role grant this returns 403",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canGetCredential: map[string]expectedOutput{
					credIds[0]: {err: handlers.ForbiddenError()},
					credIds[1]: {err: handlers.ForbiddenError()},
					credIds[2]: {err: handlers.ForbiddenError()},
					credIds[3]: {err: handlers.ForbiddenError()},
					credIds[4]: {err: handlers.ForbiddenError()},
				},
			},
			{
				name: "org role grant this returns 403",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canGetCredential: map[string]expectedOutput{
					credIds[0]: {err: handlers.ForbiddenError()},
					credIds[1]: {err: handlers.ForbiddenError()},
					credIds[2]: {err: handlers.ForbiddenError()},
					credIds[3]: {err: handlers.ForbiddenError()},
					credIds[4]: {err: handlers.ForbiddenError()},
				},
			},
			{
				name: "project role grant this returns all credentials on the project",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canGetCredential: map[string]expectedOutput{
					credIds[0]: {outputFields: []string{globals.IdField}},
					credIds[1]: {outputFields: []string{globals.IdField}},
					credIds[2]: {outputFields: []string{globals.IdField}},
					credIds[3]: {outputFields: []string{globals.IdField}},
					credIds[4]: {outputFields: []string{globals.IdField}},
				},
			},
			{
				name: "global role grant this & children returns 403 because credentials live on projects",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				canGetCredential: map[string]expectedOutput{
					credIds[0]: {err: handlers.ForbiddenError()},
					credIds[1]: {err: handlers.ForbiddenError()},
					credIds[2]: {err: handlers.ForbiddenError()},
					credIds[3]: {err: handlers.ForbiddenError()},
					credIds[4]: {err: handlers.ForbiddenError()},
				},
			},
			{
				name: "org role grant children returns all credentials on child projects",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				canGetCredential: map[string]expectedOutput{
					credIds[0]: {outputFields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField}},
					credIds[1]: {outputFields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField}},
					credIds[2]: {outputFields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField}},
					credIds[3]: {outputFields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField}},
					credIds[4]: {outputFields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField}},
				},
			},
			{
				name: "global role grant this & descendants returns all credentials on descendant projects",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				canGetCredential: map[string]expectedOutput{
					credIds[0]: {outputFields: []string{globals.IdField, globals.ScopeField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
					credIds[1]: {outputFields: []string{globals.IdField, globals.ScopeField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
					credIds[2]: {outputFields: []string{globals.IdField, globals.ScopeField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
					credIds[3]: {outputFields: []string{globals.IdField, globals.ScopeField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
					credIds[4]: {outputFields: []string{globals.IdField, globals.ScopeField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
				},
			},
			{
				name: "project role grant this returns all credentials on the project",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,credential_store_id,scope,name,description,created_time,updated_time,version,type,authorized_actions,attributes"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canGetCredential: map[string]expectedOutput{
					credIds[0]: {outputFields: []string{globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, UsernamePasswordAttributesField}},
					credIds[1]: {outputFields: []string{globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, UsernamePasswordAttributesField}},
					credIds[2]: {outputFields: []string{globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, UsernamePasswordAttributesField}},
					credIds[3]: {outputFields: []string{globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, UsernamePasswordAttributesField}},
					credIds[4]: {outputFields: []string{globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, UsernamePasswordAttributesField}},
				},
			},
			{
				name: "incorrect grants returns no credential",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=credential;actions=list,create,update,delete;output_fields=id,name,description,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canGetCredential: map[string]expectedOutput{
					credIds[0]: {err: handlers.ForbiddenError()},
					credIds[1]: {err: handlers.ForbiddenError()},
					credIds[2]: {err: handlers.ForbiddenError()},
					credIds[3]: {err: handlers.ForbiddenError()},
					credIds[4]: {err: handlers.ForbiddenError()},
				},
			},
			{
				name:     "no grants returns no credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, nil),
				canGetCredential: map[string]expectedOutput{
					credIds[0]: {err: handlers.ForbiddenError()},
					credIds[1]: {err: handlers.ForbiddenError()},
					credIds[2]: {err: handlers.ForbiddenError()},
					credIds[3]: {err: handlers.ForbiddenError()},
					credIds[4]: {err: handlers.ForbiddenError()},
				},
			},
			{
				name: "project role grant with credential id, get action, and this scope returns the id'd credential",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + credIds[0] + ";actions=read;output_fields=id,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canGetCredential: map[string]expectedOutput{
					credIds[0]: {outputFields: []string{globals.IdField, globals.AuthorizedActionsField}},
					credIds[1]: {err: handlers.ForbiddenError()},
					credIds[2]: {err: handlers.ForbiddenError()},
					credIds[3]: {err: handlers.ForbiddenError()},
					credIds[4]: {err: handlers.ForbiddenError()},
				},
			},
			{
				name: "org role grant with credential id, get action, and this & children scope returns the id'd credential",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=" + credIds[4] + ";actions=read;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				canGetCredential: map[string]expectedOutput{
					credIds[0]: {err: handlers.ForbiddenError()},
					credIds[1]: {err: handlers.ForbiddenError()},
					credIds[2]: {err: handlers.ForbiddenError()},
					credIds[3]: {err: handlers.ForbiddenError()},
					credIds[4]: {outputFields: []string{globals.IdField}},
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)

				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				for id, expected := range tc.canGetCredential {
					input := &pbs.GetCredentialRequest{Id: id}
					got, err := s.GetCredential(fullGrantAuthCtx, input)
					if expected.err != nil {
						require.ErrorIs(t, err, expected.err)
						continue
					}
					// check if the output fields are as expected
					if tc.canGetCredential[id].outputFields != nil {
						handlers.TestAssertOutputFields(t, got.Item, tc.canGetCredential[id].outputFields)
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
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kmsCache)
	}
	s, err := credentials.NewService(ctx, iamRepoFn, staticRepoFn, 1000)
	require.NoError(t, err)

	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	org, proj := iam.TestScopes(t, iamRepo)

	t.Run("Create", func(t *testing.T) {
		credStore := static.TestCredentialStore(t, conn, wrap, proj.GetPublicId())

		testcases := []struct {
			name     string
			userFunc func() (*iam.User, auth.Account)
			expected expectedOutput
		}{
			{
				name: "global role grant this can't create credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "org role grant this can't create credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "project role grant this can create credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField}},
			},
			{
				name: "global role grant this & descendants can create credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=credential;actions=create,read,update;output_fields=id,credential_store_id,scope,name,description,created_time,updated_time,version,type,authorized_actions,attributes"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, UsernamePasswordAttributesField}},
			},
			{
				name: "org role grant this & children can create credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=credential;actions=create;output_fields=id,scope,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.ScopeField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
			},
			{
				name: "global role grant pinned to credential-store id, credential type, and descendant scope can create credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=" + credStore.PublicId + ";type=credential;actions=create;output_fields=id,credential_store_id,name,scope,description,created_time,updated_time,version"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.CredentialStoreIdField, globals.NameField, globals.ScopeField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
			},
			{
				name: "global role grant pinned to credential-store id, credential type, and children scope cannot create credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=" + credStore.PublicId + ";type=credential;actions=create;output_fields=id,credential_store_id,name,scope,description,created_time,updated_time,version"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "org role grant pinned to credential-store id, credential type, and children scope can create credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=" + credStore.PublicId + ";type=credential;actions=create;output_fields=id,credential_store_id,name,scope,description,created_time,updated_time,version"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.CredentialStoreIdField, globals.NameField, globals.ScopeField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
			},
			{
				name: "project role grant pinned to credential-store id, credential type, and this scope can create credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=" + credStore.PublicId + ";type=credential;actions=create;output_fields=id,credential_store_id,name,scope,description,created_time,updated_time,version"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.CredentialStoreIdField, globals.NameField, globals.ScopeField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField}},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

				got, err := s.CreateCredential(fullGrantAuthCtx, &pbs.CreateCredentialRequest{Item: &pb.Credential{
					CredentialStoreId: credStore.GetPublicId(),
					Name:              &wrappers.StringValue{Value: "test credential - " + tc.name},
					Description:       &wrappers.StringValue{Value: "test desc"},
					Type:              credential.UsernamePasswordSubtype.String(),
					Attrs: &pb.Credential_UsernamePasswordAttributes{
						UsernamePasswordAttributes: &pb.UsernamePasswordAttributes{
							Username: wrapperspb.String("static-username"),
							Password: wrapperspb.String("static-password"),
						},
					},
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
				name: "global role grant this can't update credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "org role grant this can't update credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name: "project role grant this can update credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField}},
			},
			{
				name: "global role grant this & descendants can update credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=credential;actions=update;output_fields=id,credential_store_id,scope,name,description,created_time,updated_time,version,type,authorized_actions,attributes"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.CredentialStoreIdField, globals.ScopeField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField, UsernamePasswordAttributesField}},
			},
			{
				name: "org role grant this & children can update credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=credential;actions=update;output_fields=id,scope,type,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				expected: expectedOutput{outputFields: []string{globals.IdField, globals.ScopeField, globals.TypeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
			},
			{
				name: "incorrect grants can't update credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=credential;actions=list,create,delete;output_fields=id,name,description,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
			{
				name:     "no grants can't update credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, nil),
				expected: expectedOutput{err: handlers.ForbiddenError()},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				credStore := static.TestCredentialStore(t, conn, wrap, proj.GetPublicId())
				cred := static.TestUsernamePasswordCredential(t, conn, wrap, "user", "pass", credStore.GetPublicId(), proj.GetPublicId(), static.WithName("cred"), static.WithDescription("desc"))

				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

				got, err := s.UpdateCredential(fullGrantAuthCtx, &pbs.UpdateCredentialRequest{
					Id: cred.PublicId,
					Item: &pb.Credential{
						Name:        &wrappers.StringValue{Value: "updated credential name (" + tc.name + ")"},
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
				name: "global role grant this can't delete credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "org role grant this can't delete credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "project role grant this can delete credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
			},
			{
				name: "global role grant this & descendants can delete credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=credential;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
			},
			{
				name: "org role grant this & children can delete credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=credential;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
			},
			{
				name: "incorrect grants can't delete credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=credential;actions=list,create,update"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name:     "no grants can't delete credentials",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, nil),
				wantErr:  handlers.ForbiddenError(),
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				credStore := static.TestCredentialStore(t, conn, wrap, proj.GetPublicId())
				cred := static.TestUsernamePasswordCredential(t, conn, wrap, "user", "pass", credStore.GetPublicId(), proj.GetPublicId(), static.WithName("cred"), static.WithDescription("desc"))

				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

				_, err = s.DeleteCredential(fullGrantAuthCtx, &pbs.DeleteCredentialRequest{Id: cred.PublicId})
				if tc.wantErr != nil {
					require.ErrorIs(t, err, tc.wantErr)
					return
				}
				require.NoError(t, err)
			})
		}
	})
}
