// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package tcp_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	controllerauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/stretchr/testify/require"
)

// TestGrants_ReadActions tests read actions to assert that grants are being applied properly
//
//	 Role - which scope the role is created in
//			- global level
//		Scopes [resource]:
//			- org1
//				- proj1
//				- proj2
func TestGrants_ReadActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	s, err := testService(t, ctx, conn, kms, wrapper)
	require.NoError(t, err)
	rw := db.New(conn)

	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	org1, proj1 := iam.TestScopes(t, iamRepo)
	_, proj2 := iam.TestScopes(t, iamRepo)

	target1 := tcp.TestTarget(ctx, t, conn, proj1.GetPublicId(), "test address-1", target.WithAddress("8.8.8.8"))
	target2 := tcp.TestTarget(ctx, t, conn, proj1.GetPublicId(), "test address-2", target.WithAddress("8.8.8.8"))
	target3 := tcp.TestTarget(ctx, t, conn, proj2.GetPublicId(), "test address-2", target.WithAddress("8.8.8.8"))

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name     string
			input    *pbs.ListTargetsRequest
			userFunc func() (*iam.User, auth.Account)
			wantErr  error
			wantIDs  []string
		}{
			{
				name: "org role grant this returns all created targets",
				input: &pbs.ListTargetsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.GetPublicId(),
						Grants:      []string{"ids=*;type=target;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				wantIDs: []string{target1.GetPublicId(), target2.GetPublicId()},
			},
			{
				name: "project role grant this returns all created targets",
				input: &pbs.ListTargetsRequest{
					ScopeId:   proj2.GetPublicId(),
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj2.GetPublicId(),
						Grants:      []string{"ids=*;type=target;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: []string{target3.GetPublicId()},
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
				var gotIDs []string
				for _, g := range got.Items {
					gotIDs = append(gotIDs, g.GetId())
				}
				require.ElementsMatch(t, tc.wantIDs, gotIDs)
			})
		}
	})
}
