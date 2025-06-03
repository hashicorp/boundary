// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package workers_test

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
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/workers"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/workers"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// TestGrants_ReadActions tests read actions to assert that grants are being applied properly
//
//	 Role - which scope the role is created in
//			- global level
//		Scopes [resource]:
//			- globalWorker1
//			- globalWorker2
func TestGrants_ReadActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	org, _ := iam.TestScopes(t, iamRepo)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsCache)
	}

	workerAuthRepo, err := server.NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return workerAuthRepo, nil
	}

	s, err := workers.NewService(context.Background(), repoFn, iamRepoFn, workerAuthRepoFn, nil)
	require.NoError(t, err)
	globalWorker1 := server.TestPkiWorker(t, conn, wrapper,
		server.WithName("worker-1"),
		server.WithDescription("worker-1"),
		server.WithNewIdFunc(func(ctx context.Context) (string, error) {
			return server.NewWorkerIdFromScopeAndName(ctx, scope.Global.String(), "worker-1")
		}),
	)
	globalWorker2 := server.TestPkiWorker(t, conn, wrapper,
		server.WithName("worker-2"),
		server.WithDescription("worker-2"),
		server.WithNewIdFunc(func(ctx context.Context) (string, error) {
			return server.NewWorkerIdFromScopeAndName(ctx, scope.Global.String(), "worker-2")
		}),
	)
	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name     string
			input    *pbs.ListWorkersRequest
			userFunc func() (*iam.User, auth.Account)
			wantErr  error
			wantIDs  []string
		}{
			{
				name: "global role grant this returns all created workers",
				input: &pbs.ListWorkersRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=worker;actions=list,no-op"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: []string{globalWorker1.PublicId, globalWorker2.PublicId},
			},
			{
				name: "global role grant this with a non-applicable type returns an error",
				input: &pbs.ListWorkersRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=group;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
			},
			{
				name: "global role grant descendants recursive list returns empty list",
				input: &pbs.ListWorkersRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				wantIDs: []string{},
			},
			{
				name: "global role grant descendants non-recursive list returns error",
				input: &pbs.ListWorkersRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: false,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
			},
			{
				name: "org role grant this and children recursive list returns empty list",
				input: &pbs.ListWorkersRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantIDs: []string{},
			},
			{
				name: "org role grant this and children non-recursive list returns error",
				input: &pbs.ListWorkersRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: false,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, accountID := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrapper, tok, iamRepo)
				got, finalErr := s.ListWorkers(fullGrantAuthCtx, tc.input)
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
	t.Run("Read", func(t *testing.T) {
		testcases := []struct {
			name     string
			input    *pbs.GetWorkerRequest
			userFunc func() (*iam.User, auth.Account)
			wantErr  error
		}{
			{
				name: "global role grant read on all workers return success",
				input: &pbs.GetWorkerRequest{
					Id: globalWorker1.PublicId,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=worker;actions=read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
			},
			{
				name: "global role grant this with specific ID success",
				input: &pbs.GetWorkerRequest{
					Id: globalWorker2.PublicId,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, org.PublicId, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;actions=read", globalWorker2.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
			},
			{
				name: "global role grant allow different ID returns error",
				input: &pbs.GetWorkerRequest{
					Id: globalWorker1.PublicId,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, org.PublicId, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;actions=read", globalWorker2.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
			},
			{
				name: "global role grant different action returns error",
				input: &pbs.GetWorkerRequest{
					Id: globalWorker1.PublicId,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, org.PublicId, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=set-worker-tags"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
			},
			{
				name: "global role grant different resource returns error",
				input: &pbs.GetWorkerRequest{
					Id: globalWorker1.PublicId,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=group;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
			},
			{
				name: "global role grant descendants resource returns error",
				input: &pbs.GetWorkerRequest{
					Id: globalWorker1.PublicId,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, accountID := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrapper, tok, iamRepo)
				got, finalErr := s.GetWorker(fullGrantAuthCtx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, finalErr, tc.wantErr)
					return
				}
				require.NoError(t, finalErr)
				// validate that we're getting the right ID back
				require.Equal(t, tc.input.Id, got.GetItem().GetId())
			})
		}
	})
}

func TestGrants_CreateControllerLed(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsCache)
	}

	workerAuthRepo, err := server.NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return workerAuthRepo, nil
	}
	s, err := workers.NewService(context.Background(), repoFn, iamRepoFn, workerAuthRepoFn, nil)
	org, proj := iam.TestScopes(t, iamRepo)
	ider := func() string {
		id, _ := uuid.GenerateUUID()
		return id
	}
	testcases := []struct {
		name     string
		input    *pbs.CreateControllerLedRequest
		userFunc func() (*iam.User, auth.Account)
		wantErr  error
	}{
		{
			name: "valid grants success",
			input: &pbs.CreateControllerLedRequest{Item: &pb.Worker{
				ScopeId: scope.Global.String(),
				Name:    &wrapperspb.StringValue{Value: ider()},
			}},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
		},
		{
			name: "specific valid grants success",
			input: &pbs.CreateControllerLedRequest{Item: &pb.Worker{
				ScopeId: scope.Global.String(),
				Name:    &wrapperspb.StringValue{Value: ider()},
			}},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=worker;actions=create"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
		},
		{
			name: "no create actions grant returns error",
			input: &pbs.CreateControllerLedRequest{Item: &pb.Worker{
				ScopeId: scope.Global.String(),
				Name:    &wrapperspb.StringValue{Value: ider()},
			}},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=list,read,no-op,set-worker-tags"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
		{
			name: "no worker type grant returns error",
			input: &pbs.CreateControllerLedRequest{Item: &pb.Worker{
				ScopeId: scope.Global.String(),
				Name:    &wrapperspb.StringValue{Value: ider()},
			}},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants: []string{
						"ids=*;type=scope;actions=create",
						"ids=*;type=session;actions=create",
						"ids=*;type=user;actions=create",
						"ids=*;type=group;actions=create",
						"ids=*;type=role;actions=create",
						"ids=*;type=auth-token;actions=create",
					},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
		{
			name: "no worker type grant returns error",
			input: &pbs.CreateControllerLedRequest{Item: &pb.Worker{
				ScopeId: scope.Global.String(),
				Name:    &wrapperspb.StringValue{Value: ider()},
			}},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
				{
					RoleScopeId: org.PublicId,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
				{
					RoleScopeId: proj.PublicId,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, accountID := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, accountID.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrapper, tok, iamRepo)
			_, finalErr := s.CreateControllerLed(fullGrantAuthCtx, tc.input)
			if tc.wantErr != nil {
				require.ErrorIs(t, finalErr, tc.wantErr)
				return
			}
			require.NoError(t, finalErr)
		})
	}
}
func TestGrants_CreateWorkerLed(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsCache)
	}

	workerAuthRepo, err := server.NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return workerAuthRepo, nil
	}
	s, err := workers.NewService(context.Background(), repoFn, iamRepoFn, workerAuthRepoFn, nil)
	org, proj := iam.TestScopes(t, iamRepo)

	// Get an initial set of authorized node credentials
	rootStorage, err := server.NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	_, err = rotation.RotateRootCertificates(ctx, rootStorage)
	require.NoError(t, err)
	fetchReqFn := func() string {
		// This happens on the worker
		fileStorage, err := file.New(ctx)
		require.NoError(t, err)
		defer func() { fileStorage.Cleanup(ctx) }()

		nodeCreds, err := types.NewNodeCredentials(ctx, fileStorage)
		require.NoError(t, err)
		// Create request using worker id
		fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx)
		require.NoError(t, err)

		fetchEncoded, err := proto.Marshal(fetchReq)
		require.NoError(t, err)

		return base58.Encode(fetchEncoded)
	}

	testcases := []struct {
		name     string
		input    *pbs.CreateWorkerLedRequest
		userFunc func() (*iam.User, auth.Account)
		wantErr  error
	}{
		{
			name: "valid grants success",
			input: &pbs.CreateWorkerLedRequest{Item: &pb.Worker{
				ScopeId:                  scope.Global.String(),
				WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
			}},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
		},
		{
			name: "specific valid grants success",
			input: &pbs.CreateWorkerLedRequest{Item: &pb.Worker{
				ScopeId:                  scope.Global.String(),
				WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
			}},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=worker;actions=create"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
		},
		{
			name: "no create actions grant returns error",
			input: &pbs.CreateWorkerLedRequest{Item: &pb.Worker{
				ScopeId:                  scope.Global.String(),
				WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
			}},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=list,read,no-op,set-worker-tags"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
		{
			name: "no worker type grant returns error",
			input: &pbs.CreateWorkerLedRequest{Item: &pb.Worker{
				ScopeId:                  scope.Global.String(),
				WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
			}},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants: []string{
						"ids=*;type=scope;actions=create",
						"ids=*;type=session;actions=create",
						"ids=*;type=user;actions=create",
						"ids=*;type=group;actions=create",
						"ids=*;type=role;actions=create",
						"ids=*;type=auth-token;actions=create",
					},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
		{
			name: "no worker type grant returns error",
			input: &pbs.CreateWorkerLedRequest{Item: &pb.Worker{
				ScopeId:                  scope.Global.String(),
				WorkerGeneratedAuthToken: &wrapperspb.StringValue{Value: fetchReqFn()},
			}},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
				{
					RoleScopeId: org.PublicId,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
				{
					RoleScopeId: proj.PublicId,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, accountID := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, accountID.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrapper, tok, iamRepo)
			_, finalErr := s.CreateWorkerLed(fullGrantAuthCtx, tc.input)
			if tc.wantErr != nil {
				require.ErrorIs(t, finalErr, tc.wantErr)
				return
			}
			require.NoError(t, finalErr)
		})
	}
}
