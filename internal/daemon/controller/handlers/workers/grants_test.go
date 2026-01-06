// Copyright IBM Corp. 2020, 2025
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
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestGrants_ListWorkers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
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
		server.WithWorkerTags(&server.Tag{
			Key:   "worker",
			Value: "1",
		}),
		server.WithNewIdFunc(func(ctx context.Context) (string, error) {
			return server.NewWorkerIdFromScopeAndName(ctx, scope.Global.String(), "worker-1")
		}),
	)
	globalWorker2 := server.TestPkiWorker(t, conn, wrapper,
		server.WithName("worker-2"),
		server.WithDescription("worker-2"),
		server.WithWorkerTags(&server.Tag{
			Key:   "worker",
			Value: "2",
		}),
		server.WithNewIdFunc(func(ctx context.Context) (string, error) {
			return server.NewWorkerIdFromScopeAndName(ctx, scope.Global.String(), "worker-2")
		}),
	)
	globalWorker3 := server.TestPkiWorker(t, conn, wrapper,
		server.WithName("worker-3"),
		server.WithDescription("worker-3"),
		server.WithWorkerTags(&server.Tag{
			Key:   "worker",
			Value: "3",
		}),
		server.WithNewIdFunc(func(ctx context.Context) (string, error) {
			return server.NewWorkerIdFromScopeAndName(ctx, scope.Global.String(), "worker-3")
		}),
	)

	testcases := []struct {
		name             string
		input            *pbs.ListWorkersRequest
		userFunc         func() (*iam.User, auth.Account)
		wantErr          error
		wantIds          []string
		wantOutputFields []string
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
					Grants:      []string{"ids=*;type=worker;actions=list,read;output_fields=id,name,description,created_time,updated_time"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr:          nil,
			wantIds:          []string{globalWorker1.PublicId, globalWorker2.PublicId, globalWorker3.PublicId},
			wantOutputFields: []string{globals.IdField, globals.NameField, globals.DescriptionField, globals.CreatedTimeField, globals.UpdatedTimeField},
		},
		{
			name: "global role grant this returns all created workers different output fields",
			input: &pbs.ListWorkersRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: false,
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=worker;actions=list,read;output_fields=id,version,canonical_tags,config_tags,authorized_actions,local_storage_state"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr:          nil,
			wantIds:          []string{globalWorker1.PublicId, globalWorker2.PublicId, globalWorker3.PublicId},
			wantOutputFields: []string{globals.IdField, globals.VersionField, globals.CanonicalTagsField, globals.ConfigTagsField, globals.AuthorizedActionsField, globals.LocalStorageStateField},
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
			var gotIds []string
			for _, item := range got.Items {
				gotIds = append(gotIds, item.GetId())
				handlers.TestAssertOutputFields(t, item, tc.wantOutputFields)
			}
			require.ElementsMatch(t, gotIds, tc.wantIds)
		})
	}
}

func TestGrants_GetWorker(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
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
		server.WithWorkerTags(&server.Tag{
			Key:   "key",
			Value: "val",
		}),
		server.WithNewIdFunc(func(ctx context.Context) (string, error) {
			return server.NewWorkerIdFromScopeAndName(ctx, scope.Global.String(), "worker-1")
		}),
	)
	globalWorker2 := server.TestPkiWorker(t, conn, wrapper,
		server.WithName("worker-2"),
		server.WithDescription("worker-2"),
		server.WithWorkerTags(&server.Tag{
			Key:   "key",
			Value: "val",
		}, &server.Tag{
			Key:   "another tag",
			Value: "for output fields",
		}),
		server.WithNewIdFunc(func(ctx context.Context) (string, error) {
			return server.NewWorkerIdFromScopeAndName(ctx, scope.Global.String(), "worker-2")
		}),
	)

	testcases := []struct {
		name             string
		input            *pbs.GetWorkerRequest
		userFunc         func() (*iam.User, auth.Account)
		wantErr          error
		wantOutputFields []string
	}{
		{
			name: "global role grant read on all workers return success",
			input: &pbs.GetWorkerRequest{
				Id: globalWorker1.PublicId,
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=worker;actions=read;output_fields=id,name,description,created_time,updated_time,authorized_actions"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr:          nil,
			wantOutputFields: []string{globals.IdField, globals.NameField, globals.DescriptionField, globals.AuthorizedActionsField, globals.CreatedTimeField, globals.UpdatedTimeField},
		},
		{
			name: "global role grant this with specific ID success",
			input: &pbs.GetWorkerRequest{
				Id: globalWorker2.PublicId,
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, org.PublicId, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{fmt.Sprintf("ids=%s;actions=read;output_fields=id,version,config_tags,type", globalWorker2.PublicId)},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantOutputFields: []string{globals.IdField, globals.VersionField, globals.ConfigTagsField, globals.TypeField},
			wantErr:          nil,
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
			handlers.TestAssertOutputFields(t, got.GetItem(), tc.wantOutputFields)
		})
	}
}

func TestGrants_Delete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
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
	// Store CA and check that initial version updates
	_, err = rotation.RotateRootCertificates(ctx, workerAuthRepo)
	require.NoError(t, err)
	s, err := workers.NewService(context.Background(), repoFn, iamRepoFn, workerAuthRepoFn, nil)
	require.NoError(t, err)
	testcases := []struct {
		name     string
		input    func(w *server.Worker) *pbs.DeleteWorkerRequest
		userFunc func(w *server.Worker) func() (*iam.User, auth.Account)
		wantErr  error
	}{
		{
			name: "valid specific grants success",
			input: func(w *server.Worker) *pbs.DeleteWorkerRequest {
				return &pbs.DeleteWorkerRequest{
					Id: w.PublicId,
				}
			},
			userFunc: func(w *server.Worker) func() (*iam.User, auth.Account) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=worker;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
		},
		{
			name: "valid grants success",
			input: func(w *server.Worker) *pbs.DeleteWorkerRequest {
				return &pbs.DeleteWorkerRequest{
					Id: w.PublicId,
				}
			},
			userFunc: func(w *server.Worker) func() (*iam.User, auth.Account) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
		},
		{
			name: "no actions grant returns error",
			input: func(w *server.Worker) *pbs.DeleteWorkerRequest {
				return &pbs.DeleteWorkerRequest{
					Id: w.PublicId,
				}
			},
			userFunc: func(w *server.Worker) func() (*iam.User, auth.Account) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=create,list,read-certificate-authority"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
		{
			name: "wrong scope grants returns error",
			input: func(w *server.Worker) *pbs.DeleteWorkerRequest {
				return &pbs.DeleteWorkerRequest{
					Id: w.PublicId,
				}
			},
			userFunc: func(w *server.Worker) func() (*iam.User, auth.Account) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				})
			},
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
		{
			name: "specific worker id succeed",
			input: func(w *server.Worker) *pbs.DeleteWorkerRequest {
				return &pbs.DeleteWorkerRequest{
					Id: w.PublicId,
				}
			},
			userFunc: func(w *server.Worker) func() (*iam.User, auth.Account) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;actions=*", w.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			workerId, err := uuid.GenerateUUID()
			require.NoError(t, err)
			worker := server.TestPkiWorker(t, conn, wrapper,
				server.WithName(workerId),
				server.WithDescription(workerId),
				server.WithTestUseInputTagsAsApiTags(true),
				server.WithNewIdFunc(func(ctx context.Context) (string, error) {
					return server.NewWorkerIdFromScopeAndName(ctx, scope.Global.String(), workerId)
				}),
			)
			user, accountID := tc.userFunc(worker)()
			tok, err := atRepo.CreateAuthToken(ctx, user, accountID.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrapper, tok, iamRepo)
			_, finalErr := s.DeleteWorker(fullGrantAuthCtx, tc.input(worker))
			if tc.wantErr != nil {
				require.ErrorIs(t, finalErr, tc.wantErr)
				return
			}
			require.NoError(t, finalErr)
		})
	}
}

func TestGrants_Update(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsCache)
	}
	org, proj := iam.TestScopes(t, iamRepo)

	workerAuthRepo, err := server.NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return workerAuthRepo, nil
	}
	// Store CA and check that initial version updates
	_, err = rotation.RotateRootCertificates(ctx, workerAuthRepo)
	require.NoError(t, err)
	s, err := workers.NewService(context.Background(), repoFn, iamRepoFn, workerAuthRepoFn, nil)
	require.NoError(t, err)
	testcases := []struct {
		name             string
		input            func(w *server.Worker) *pbs.UpdateWorkerRequest
		userFunc         func(w *server.Worker) func() (*iam.User, auth.Account)
		wantErr          error
		wantOutputFields []string
	}{
		{
			name: "valid specific grants success",
			input: func(w *server.Worker) *pbs.UpdateWorkerRequest {
				description, err := uuid.GenerateUUID()
				require.NoError(t, err)
				return &pbs.UpdateWorkerRequest{
					Id: w.PublicId,
					Item: &pb.Worker{
						Version:     w.Version,
						Description: wrapperspb.String(description),
					},
					UpdateMask: &field_mask.FieldMask{Paths: []string{"description"}},
				}
			},
			userFunc: func(w *server.Worker) func() (*iam.User, auth.Account) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=worker;actions=update;output_fields=id,version,scope_id,name,description,config_tags"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			wantOutputFields: []string{globals.IdField, globals.VersionField, globals.ScopeIdField, globals.NameField, globals.DescriptionField, globals.ConfigTagsField},
		},
		{
			name: "valid grants success",
			input: func(w *server.Worker) *pbs.UpdateWorkerRequest {
				description, err := uuid.GenerateUUID()
				require.NoError(t, err)
				return &pbs.UpdateWorkerRequest{
					Id: w.PublicId,
					Item: &pb.Worker{
						Version:     w.Version,
						Description: wrapperspb.String(description),
					},
					UpdateMask: &field_mask.FieldMask{Paths: []string{"description"}},
				}
			},
			userFunc: func(w *server.Worker) func() (*iam.User, auth.Account) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,version,type,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			wantOutputFields: []string{globals.IdField, globals.VersionField, globals.TypeField, globals.AuthorizedActionsField},
		},
		{
			name: "no actions grant returns error",
			input: func(w *server.Worker) *pbs.UpdateWorkerRequest {
				description, err := uuid.GenerateUUID()
				require.NoError(t, err)
				return &pbs.UpdateWorkerRequest{
					Id: w.PublicId,
					Item: &pb.Worker{
						Version:     w.Version,
						Description: wrapperspb.String(description),
					},
					UpdateMask: &field_mask.FieldMask{Paths: []string{"description"}},
				}
			},
			userFunc: func(w *server.Worker) func() (*iam.User, auth.Account) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=create,list,delete,read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
		{
			name: "wrong scope grants returns error",
			input: func(w *server.Worker) *pbs.UpdateWorkerRequest {
				description, err := uuid.GenerateUUID()
				require.NoError(t, err)
				return &pbs.UpdateWorkerRequest{
					Id: w.PublicId,
					Item: &pb.Worker{
						Version:     w.Version,
						Description: wrapperspb.String(description),
					},
					UpdateMask: &field_mask.FieldMask{Paths: []string{"description"}},
				}
			},
			userFunc: func(w *server.Worker) func() (*iam.User, auth.Account) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				})
			},
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
		{
			name: "org role scope grants this returns error",
			input: func(w *server.Worker) *pbs.UpdateWorkerRequest {
				description, err := uuid.GenerateUUID()
				require.NoError(t, err)
				return &pbs.UpdateWorkerRequest{
					Id: w.PublicId,
					Item: &pb.Worker{
						Version:     w.Version,
						Description: wrapperspb.String(description),
					},
					UpdateMask: &field_mask.FieldMask{Paths: []string{"description"}},
				}
			},
			userFunc: func(w *server.Worker) func() (*iam.User, auth.Account) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
		{
			name: "proj role scope grants this returns error",
			input: func(w *server.Worker) *pbs.UpdateWorkerRequest {
				description, err := uuid.GenerateUUID()
				require.NoError(t, err)
				return &pbs.UpdateWorkerRequest{
					Id: w.PublicId,
					Item: &pb.Worker{
						Version:     w.Version,
						Description: wrapperspb.String(description),
					},
					UpdateMask: &field_mask.FieldMask{Paths: []string{"description"}},
				}
			},
			userFunc: func(w *server.Worker) func() (*iam.User, auth.Account) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
		{
			name: "specific worker id succeed",
			input: func(w *server.Worker) *pbs.UpdateWorkerRequest {
				description, err := uuid.GenerateUUID()
				require.NoError(t, err)
				return &pbs.UpdateWorkerRequest{
					Id: w.PublicId,
					Item: &pb.Worker{
						Version:     w.Version,
						Description: wrapperspb.String(description),
					},
					UpdateMask: &field_mask.FieldMask{Paths: []string{"description"}},
				}
			},
			userFunc: func(w *server.Worker) func() (*iam.User, auth.Account) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;actions=*;output_fields=id,version,description,scope_id,config_tags,authorized_actions", w.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			wantOutputFields: []string{globals.IdField, globals.VersionField, globals.ScopeIdField, globals.DescriptionField, globals.ConfigTagsField, globals.AuthorizedActionsField},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			workerId, err := uuid.GenerateUUID()
			require.NoError(t, err)
			worker := server.TestPkiWorker(t, conn, wrapper,
				server.WithName(workerId),
				server.WithDescription(workerId),
				server.WithWorkerTags(&server.Tag{
					Key:   workerId,
					Value: workerId,
				}, &server.Tag{
					Key:   "another tag",
					Value: "for output fields",
				}))
			user, accountID := tc.userFunc(worker)()
			tok, err := atRepo.CreateAuthToken(ctx, user, accountID.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrapper, tok, iamRepo)
			got, finalErr := s.UpdateWorker(fullGrantAuthCtx, tc.input(worker))
			if tc.wantErr != nil {
				require.ErrorIs(t, finalErr, tc.wantErr)
				return
			}
			require.NoError(t, finalErr)
			handlers.TestAssertOutputFields(t, got.Item, tc.wantOutputFields)
		})
	}
}

func TestGrants_CreateWorkerLed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
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
		defer func() { _ = fileStorage.Cleanup(ctx) }()

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

func TestGrants_CreateControllerLed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
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

func TestGrants_ReadCertificateAuthority(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
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
	// Store CA and check that initial version updates
	_, err = rotation.RotateRootCertificates(ctx, workerAuthRepo)
	require.NoError(t, err)
	s, err := workers.NewService(context.Background(), repoFn, iamRepoFn, workerAuthRepoFn, nil)
	require.NoError(t, err)
	org, proj := iam.TestScopes(t, iamRepo)
	testcases := []struct {
		name     string
		input    *pbs.ReadCertificateAuthorityRequest
		userFunc func() (*iam.User, auth.Account)
		wantErr  error
	}{
		{
			name: "valid specific grants success",
			input: &pbs.ReadCertificateAuthorityRequest{
				ScopeId: globals.GlobalPrefix,
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=worker;actions=read-certificate-authority"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
		},
		{
			name: "valid grants success",
			input: &pbs.ReadCertificateAuthorityRequest{
				ScopeId: globals.GlobalPrefix,
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=worker;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
		},
		{
			name: "no actions grant returns error",
			input: &pbs.ReadCertificateAuthorityRequest{
				ScopeId: globals.GlobalPrefix,
			},
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
			name: "org role scope grant this returns error",
			input: &pbs.ReadCertificateAuthorityRequest{
				ScopeId: globals.GlobalPrefix,
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org.PublicId,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
		{
			name: "proj role scope grant this returns error",
			input: &pbs.ReadCertificateAuthorityRequest{
				ScopeId: globals.GlobalPrefix,
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj.PublicId,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
		{
			name: "wrong scope grants returns error",
			input: &pbs.ReadCertificateAuthorityRequest{
				ScopeId: globals.GlobalPrefix,
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
			_, finalErr := s.ReadCertificateAuthority(fullGrantAuthCtx, tc.input)
			if tc.wantErr != nil {
				require.ErrorIs(t, finalErr, tc.wantErr)
				return
			}
			require.NoError(t, finalErr)
		})
	}
}

func TestGrants_ReinitializeCertificateAuthority(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
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
	// Store CA and check that initial version updates
	_, err = rotation.RotateRootCertificates(ctx, workerAuthRepo)
	require.NoError(t, err)
	s, err := workers.NewService(context.Background(), repoFn, iamRepoFn, workerAuthRepoFn, nil)
	require.NoError(t, err)
	org, proj := iam.TestScopes(t, iamRepo)
	testcases := []struct {
		name     string
		input    *pbs.ReinitializeCertificateAuthorityRequest
		userFunc func() (*iam.User, auth.Account)
		wantErr  error
	}{
		{
			name: "valid specific grants success",
			input: &pbs.ReinitializeCertificateAuthorityRequest{
				ScopeId: globals.GlobalPrefix,
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=worker;actions=reinitialize-certificate-authority"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
		},
		{
			name: "valid grants success",
			input: &pbs.ReinitializeCertificateAuthorityRequest{
				ScopeId: globals.GlobalPrefix,
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=worker;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
		},
		{
			name: "no actions grant returns error",
			input: &pbs.ReinitializeCertificateAuthorityRequest{
				ScopeId: globals.GlobalPrefix,
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=create,list,read-certificate-authority"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
		{
			name: "org role scope grant this returns error",
			input: &pbs.ReinitializeCertificateAuthorityRequest{
				ScopeId: globals.GlobalPrefix,
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org.PublicId,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
		{
			name: "proj role scope grant this returns error",
			input: &pbs.ReinitializeCertificateAuthorityRequest{
				ScopeId: globals.GlobalPrefix,
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj.PublicId,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
		{
			name: "wrong scope grants returns error",
			input: &pbs.ReinitializeCertificateAuthorityRequest{
				ScopeId: globals.GlobalPrefix,
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
			_, finalErr := s.ReinitializeCertificateAuthority(fullGrantAuthCtx, tc.input)
			if tc.wantErr != nil {
				require.ErrorIs(t, finalErr, tc.wantErr)
				return
			}
			require.NoError(t, finalErr)
		})
	}
}

func TestGrants_AddWorkerTags(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
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
	// Store CA and check that initial version updates
	_, err = rotation.RotateRootCertificates(ctx, workerAuthRepo)
	require.NoError(t, err)
	s, err := workers.NewService(context.Background(), repoFn, iamRepoFn, workerAuthRepoFn, nil)
	require.NoError(t, err)
	worker := server.TestPkiWorker(t, conn, wrapper,
		server.WithName("worker-1"),
		server.WithDescription("worker-1"),
		server.WithWorkerTags(&server.Tag{
			Key:   "worker",
			Value: "1",
		}),
		server.WithNewIdFunc(func(ctx context.Context) (string, error) {
			return server.NewWorkerIdFromScopeAndName(ctx, scope.Global.String(), "worker-1")
		}),
	)
	testcases := []struct {
		name             string
		input            func() *pbs.AddWorkerTagsRequest
		userFunc         func() (*iam.User, auth.Account)
		wantErr          error
		wantOutputFields []string
	}{
		{
			name: "valid specific grants success",
			input: func() *pbs.AddWorkerTagsRequest {
				randomTag, _ := uuid.GenerateUUID()
				return &pbs.AddWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{
						randomTag: {Values: []*structpb.Value{structpb.NewStringValue(randomTag)}},
					},
				}
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=worker;actions=add-worker-tags;output_fields=id,version,scope_id,name,description"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantOutputFields: []string{globals.IdField, globals.VersionField, globals.ScopeIdField, globals.NameField, globals.DescriptionField},
		},
		{
			name: "valid grants success",
			input: func() *pbs.AddWorkerTagsRequest {
				randomTag, _ := uuid.GenerateUUID()
				return &pbs.AddWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{
						randomTag: {Values: []*structpb.Value{structpb.NewStringValue(randomTag)}},
					},
				}
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=worker;actions=*;output_fields=id,version,type,api_tags,authorized_actions"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantOutputFields: []string{globals.IdField, globals.VersionField, globals.TypeField, globals.ApiTagsField, globals.AuthorizedActionsField},
		},
		{
			name: "specific id valid grants success",
			input: func() *pbs.AddWorkerTagsRequest {
				randomTag, _ := uuid.GenerateUUID()
				return &pbs.AddWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{
						randomTag: {Values: []*structpb.Value{structpb.NewStringValue(randomTag)}},
					},
				}
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{fmt.Sprintf("ids=%s;actions=add-worker-tags;output_fields=id,version,scope_id,config_tags,api_tags,authorized_actions", worker.PublicId)},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantOutputFields: []string{globals.IdField, globals.VersionField, globals.ScopeIdField, globals.ConfigTagsField, globals.ApiTagsField, globals.AuthorizedActionsField},
		},
		{
			name: "no actions grant returns error",
			input: func() *pbs.AddWorkerTagsRequest {
				randomTag, _ := uuid.GenerateUUID()
				return &pbs.AddWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{
						randomTag: {Values: []*structpb.Value{structpb.NewStringValue(randomTag)}},
					},
				}
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=create,list,read-certificate-authority"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
		{
			name: "wrong scope grants returns error",
			input: func() *pbs.AddWorkerTagsRequest {
				randomTag, _ := uuid.GenerateUUID()
				return &pbs.AddWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{
						randomTag: {Values: []*structpb.Value{structpb.NewStringValue(randomTag)}},
					},
				}
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
			out, finalErr := s.AddWorkerTags(fullGrantAuthCtx, tc.input())
			if tc.wantErr != nil {
				require.ErrorIs(t, finalErr, tc.wantErr)
				return
			}
			worker.Version = out.Item.Version
			require.NoError(t, finalErr)
			handlers.TestAssertOutputFields(t, out.Item, tc.wantOutputFields)
		})
	}
}

func TestGrants_SetWorkerTags(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
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
	// Store CA and check that initial version updates
	_, err = rotation.RotateRootCertificates(ctx, workerAuthRepo)
	require.NoError(t, err)
	s, err := workers.NewService(context.Background(), repoFn, iamRepoFn, workerAuthRepoFn, nil)
	require.NoError(t, err)
	worker := server.TestPkiWorker(t, conn, wrapper,
		server.WithName("worker-1"),
		server.WithDescription("worker-1"),
		server.WithWorkerTags(&server.Tag{
			Key:   "worker",
			Value: "1",
		}),
		server.WithNewIdFunc(func(ctx context.Context) (string, error) {
			return server.NewWorkerIdFromScopeAndName(ctx, scope.Global.String(), "worker-1")
		}),
	)
	testcases := []struct {
		name             string
		input            func() *pbs.SetWorkerTagsRequest
		userFunc         func() (*iam.User, auth.Account)
		wantErr          error
		wantOutputFields []string
	}{
		{
			name: "valid specific grants success",
			input: func() *pbs.SetWorkerTagsRequest {
				randomTag, _ := uuid.GenerateUUID()
				return &pbs.SetWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{
						randomTag: {Values: []*structpb.Value{structpb.NewStringValue(randomTag)}},
					},
				}
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=worker;actions=set-worker-tags;output_fields=id,version,scope_id,name,description"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantOutputFields: []string{globals.IdField, globals.VersionField, globals.ScopeIdField, globals.NameField, globals.DescriptionField},
		},
		{
			name: "valid grants success",
			input: func() *pbs.SetWorkerTagsRequest {
				randomTag, _ := uuid.GenerateUUID()
				return &pbs.SetWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{
						randomTag: {Values: []*structpb.Value{structpb.NewStringValue(randomTag)}},
					},
				}
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=worker;actions=*;output_fields=id,version,type,api_tags,authorized_actions"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantOutputFields: []string{globals.IdField, globals.VersionField, globals.TypeField, globals.ApiTagsField, globals.AuthorizedActionsField},
		},
		{
			name: "specific id valid grants success",
			input: func() *pbs.SetWorkerTagsRequest {
				randomTag, _ := uuid.GenerateUUID()
				return &pbs.SetWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{
						randomTag: {Values: []*structpb.Value{structpb.NewStringValue(randomTag)}},
					},
				}
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{fmt.Sprintf("ids=%s;actions=set-worker-tags;output_fields=id,version,scope_id,config_tags,api_tags,authorized_actions", worker.PublicId)},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantOutputFields: []string{globals.IdField, globals.VersionField, globals.ScopeIdField, globals.ConfigTagsField, globals.ApiTagsField, globals.AuthorizedActionsField},
		},
		{
			name: "no actions grant returns error",
			input: func() *pbs.SetWorkerTagsRequest {
				randomTag, _ := uuid.GenerateUUID()
				return &pbs.SetWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{
						randomTag: {Values: []*structpb.Value{structpb.NewStringValue(randomTag)}},
					},
				}
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=create,list,read-certificate-authority"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
		{
			name: "wrong scope grants returns error",
			input: func() *pbs.SetWorkerTagsRequest {
				randomTag, _ := uuid.GenerateUUID()
				return &pbs.SetWorkerTagsRequest{
					Id:      worker.PublicId,
					Version: worker.Version,
					ApiTags: map[string]*structpb.ListValue{
						randomTag: {Values: []*structpb.Value{structpb.NewStringValue(randomTag)}},
					},
				}
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
			out, finalErr := s.SetWorkerTags(fullGrantAuthCtx, tc.input())
			if tc.wantErr != nil {
				require.ErrorIs(t, finalErr, tc.wantErr)
				return
			}
			worker.Version = out.Item.Version
			require.NoError(t, finalErr)
			handlers.TestAssertOutputFields(t, out.Item, tc.wantOutputFields)
		})
	}
}

func TestGrants_RemoveWorkerTags(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
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
	// Store CA and check that initial version updates
	_, err = rotation.RotateRootCertificates(ctx, workerAuthRepo)
	require.NoError(t, err)
	s, err := workers.NewService(context.Background(), repoFn, iamRepoFn, workerAuthRepoFn, nil)
	require.NoError(t, err)
	testcases := []struct {
		name             string
		input            func(w *server.Worker) *pbs.RemoveWorkerTagsRequest
		userFunc         func(w *server.Worker) func() (*iam.User, auth.Account)
		wantErr          error
		wantOutputFields []string
	}{
		{
			name: "valid specific grants success",
			input: func(w *server.Worker) *pbs.RemoveWorkerTagsRequest {
				return &pbs.RemoveWorkerTagsRequest{
					Id:      w.PublicId,
					Version: w.Version,
					ApiTags: map[string]*structpb.ListValue{
						w.Name: {Values: []*structpb.Value{structpb.NewStringValue(w.Name)}},
					},
				}
			},
			userFunc: func(w *server.Worker) func() (*iam.User, auth.Account) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=worker;actions=remove-worker-tags;output_fields=id,version,scope_id,name,description"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			wantOutputFields: []string{globals.IdField, globals.VersionField, globals.ScopeIdField, globals.NameField, globals.DescriptionField},
		},
		{
			name: "valid grants success",
			input: func(w *server.Worker) *pbs.RemoveWorkerTagsRequest {
				return &pbs.RemoveWorkerTagsRequest{
					Id:      w.PublicId,
					Version: w.Version,
					ApiTags: map[string]*structpb.ListValue{
						w.Name: {Values: []*structpb.Value{structpb.NewStringValue(w.Name)}},
					},
				}
			},
			userFunc: func(w *server.Worker) func() (*iam.User, auth.Account) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=worker;actions=*;output_fields=id,version,type,api_tags,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			wantOutputFields: []string{globals.IdField, globals.VersionField, globals.TypeField, globals.ApiTagsField, globals.AuthorizedActionsField},
		},
		{
			name: "specific resource grants success",
			input: func(w *server.Worker) *pbs.RemoveWorkerTagsRequest {
				return &pbs.RemoveWorkerTagsRequest{
					Id:      w.PublicId,
					Version: w.Version,
					ApiTags: map[string]*structpb.ListValue{
						w.Name: {Values: []*structpb.Value{structpb.NewStringValue(w.Name)}},
					},
				}
			},
			userFunc: func(w *server.Worker) func() (*iam.User, auth.Account) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;actions=*;output_fields=id,scope_id,api_tags,authorized_actions", w.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			wantOutputFields: []string{globals.IdField, globals.ScopeIdField, globals.ApiTagsField, globals.AuthorizedActionsField},
		},
		{
			name: "no actions grant returns error",
			input: func(w *server.Worker) *pbs.RemoveWorkerTagsRequest {
				return &pbs.RemoveWorkerTagsRequest{
					Id:      w.PublicId,
					Version: w.Version,
					ApiTags: map[string]*structpb.ListValue{
						w.Name: {Values: []*structpb.Value{structpb.NewStringValue(w.Name)}},
					},
				}
			},
			userFunc: func(w *server.Worker) func() (*iam.User, auth.Account) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=create,list,read-certificate-authority"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
		{
			name: "wrong scope grants returns error",
			input: func(w *server.Worker) *pbs.RemoveWorkerTagsRequest {
				return &pbs.RemoveWorkerTagsRequest{
					Id:      w.PublicId,
					Version: w.Version,
					ApiTags: map[string]*structpb.ListValue{
						w.Name: {Values: []*structpb.Value{structpb.NewStringValue(w.Name)}},
					},
				}
			},
			userFunc: func(w *server.Worker) func() (*iam.User, auth.Account) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				})
			},
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			workerId, err := uuid.GenerateUUID()
			require.NoError(t, err)
			worker := server.TestPkiWorker(t, conn, wrapper,
				server.WithName(workerId),
				server.WithDescription(workerId),
				server.WithTestUseInputTagsAsApiTags(true),
				server.WithWorkerTags(&server.Tag{
					Key:   workerId,
					Value: workerId,
				}, &server.Tag{
					Key:   "another tag",
					Value: "for output fields",
				}),
				server.WithNewIdFunc(func(ctx context.Context) (string, error) {
					return server.NewWorkerIdFromScopeAndName(ctx, scope.Global.String(), workerId)
				}),
			)
			user, accountID := tc.userFunc(worker)()
			tok, err := atRepo.CreateAuthToken(ctx, user, accountID.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrapper, tok, iamRepo)
			out, finalErr := s.RemoveWorkerTags(fullGrantAuthCtx, tc.input(worker))
			if tc.wantErr != nil {
				require.ErrorIs(t, finalErr, tc.wantErr)
				return
			}
			require.NoError(t, finalErr)
			handlers.TestAssertOutputFields(t, out.Item, tc.wantOutputFields)
		})
	}
}
