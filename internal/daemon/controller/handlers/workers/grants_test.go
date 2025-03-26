// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package workers_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/workers"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
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
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}

	workerAuthRepo, err := server.NewRepositoryStorage(ctx, rw, rw, kms)
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
			name          string
			input         *pbs.ListWorkersRequest
			rolesToCreate []authtoken.TestRoleGrantsForToken
			wantErr       error
			wantIDs       []string
		}{
			{
				name: "global role grant this returns all created workers",
				input: &pbs.ListWorkersRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=worker;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis},
					},
				},
				wantErr: nil,
				wantIDs: []string{globalWorker1.PublicId, globalWorker2.PublicId},
			},
			{
				name: "global role grant this with a non-applicable type throws an error",
				input: &pbs.ListWorkersRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=group;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis},
					},
				},
				wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				tok := authtoken.TestAuthTokenWithRoles(t, conn, kms, globals.GlobalPrefix, tc.rolesToCreate)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrapper, tok, iamRepo)
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
}
