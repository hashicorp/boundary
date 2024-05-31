package apptokens

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/apptoken"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	requestauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/apptokens"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var testAuthorizedActions = []string{"no-op", "read", "update", "delete", "add-principals", "set-principals", "remove-principals", "add-grants", "set-grants", "remove-grants", "add-grant-scopes", "set-grant-scopes", "remove-grant-scopes"}

func TestService_CreateAppToken(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrap)

	tokenRepo, _ := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repo := apptoken.TestRepo(t, conn, wrap, iamRepo)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func(opts ...apptoken.Option) (*apptoken.Repository, error) {
		return repo, nil
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return tokenRepo, nil
	}

	service, err := NewService(ctx, repoFn, iamRepoFn)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	org, proj := iam.TestScopes(t, iamRepo)
	authMethod := password.TestAuthMethods(t, conn, "global", 1)[0]
	acct := password.TestAccount(t, conn, authMethod.GetPublicId(), "test_user")
	user := iam.TestUser(t, iamRepo, "global", iam.WithAccountIds(acct.PublicId))
	userHistoryId, err := repo.ResolveUserHistoryId(ctx, user.GetPublicId())
	require.NoError(t, err)

	privProjRole := iam.TestRole(t, conn, proj.GetPublicId())
	iam.TestRoleGrant(t, conn, privProjRole.GetPublicId(), "ids=*;type=*;actions=*")
	iam.TestUserRole(t, conn, privProjRole.GetPublicId(), user.GetPublicId())
	privOrgRole := iam.TestRole(t, conn, org.GetPublicId())
	iam.TestRoleGrant(t, conn, privOrgRole.GetPublicId(), "ids=*;type=*;actions=*")
	iam.TestUserRole(t, conn, privOrgRole.GetPublicId(), user.GetPublicId())

	at, _ := tokenRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
	requestInfo := authpb.RequestInfo{
		TokenFormat: uint32(requestauth.AuthTokenTypeBearer),
		PublicId:    at.GetPublicId(),
		Token:       at.GetToken(),
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsCache)
	}
	requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
	ctx = requestauth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kmsCache, &requestInfo)

	appTokenMutatorFn := func(mod func(*apptokens.AppToken)) *services.CreateAppTokenRequest {
		token := &apptokens.AppToken{
			Scope:           &scopes.ScopeInfo{Id: org.GetPublicId(), Type: scope.Org.String(), ParentScopeId: org.GetParentId()},
			Name:            wrapperspb.String("test-app-token"),
			Description:     wrapperspb.String("test-app-token-description"),
			ExpirationTime:  timestamppb.New(time.Now().Add(365 * 24 * time.Minute)),
			CreatedByUserId: userHistoryId,
			GrantStrings: []string{
				"id=*;type=*;actions=read",
			},
			Grants: []*apptokens.Grant{
				{
					Canonical: "id=*;type=*;actions=read",
					Raw:       "id=*;type=*;actions=read",
				},
			},
			ExpirationInterval: 60,
			ScopeId:            org.GetPublicId(),
			AuthorizedActions:  testAuthorizedActions,
			GrantScopeId:       wrapperspb.String(proj.GetPublicId()),
		}
		if mod != nil {
			mod(token)
		}
		return &services.CreateAppTokenRequest{
			Item: token,
		}
	}

	tests := []struct {
		name     string
		request  *services.CreateAppTokenRequest
		expected *services.CreateAppTokenResponse
		err      error
	}{
		{
			name:    "valid-request",
			request: appTokenMutatorFn(nil),
			expected: &services.CreateAppTokenResponse{
				Item: &apptokens.AppToken{},
			},
		},
		// {
		// 	name: "valid-request-with-no-grants",
		// 	request: appTokenMutatorFn(func(token *apptokens.AppToken) {
		// 		token.Grants = nil
		// 	}),
		// 	expected: &services.CreateAppTokenResponse{},
		// 	err:      nil,
		// },
		// {
		// 	name: "valid-request-with-empty-grants",
		// 	request: appTokenMutatorFn(func(token *apptokens.AppToken) {
		// 		token.Grants = []*apptokens.Grant{}
		// 	}),
		// 	expected: &services.CreateAppTokenResponse{},
		// 	err:      nil,
		// },
		// {
		// 	name: "valid-request-with-invalid-scope",
		// 	request: appTokenMutatorFn(func(token *apptokens.AppToken) {
		// 		token.Scope = &scopes.ScopeInfo{Id: "invalid-scope-id", Type: scope.Project.String(), ParentScopeId: proj.GetParentId()}
		// 	}),
		// 	err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		// },
		// {
		// 	name: "valid-request-with-invalid-authorized-action",
		// 	request: appTokenMutatorFn(func(token *apptokens.AppToken) {
		// 		token.AuthorizedActions = []string{"invalid-action"}
		// 	}),
		// 	err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		// },
		// {
		// 	name: "invalid-request-with-past-expiration-time",
		// 	request: appTokenMutatorFn(func(token *apptokens.AppToken) {
		// 		token.ExpirationTime = timestamppb.New(time.Now().Add(-1 * time.Minute))
		// 	}),
		// 	err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		// },
		// {
		// 	name: "valid-request-with-invalid-scope-id",
		// 	request: appTokenMutatorFn(func(token *apptokens.AppToken) {
		// 		token.ScopeId = "invalid-scope-id"
		// 	}),
		// 	err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		// },
	}

	// TODO: Address error from repo `"column \"grant_scope_id\" of relation \"app_token\" does not exist"`
	// https://github.com/hashicorp/boundary/blob/930bfa038ef9fbc07af7a00d68f887bbf3f6731c/internal/apptoken/repository_create.go#L135
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn.Debug(true)
			response, err := service.CreateAppToken(ctx, tt.request)

			assert.Equal(t, tt.expected, response)
			assert.Equal(t, tt.err, err)
			assert.NotNil(t, response)
		})
	}
}
