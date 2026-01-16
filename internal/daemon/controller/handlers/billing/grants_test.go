// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package billing_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/billing"
	cauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	billingservice "github.com/hashicorp/boundary/internal/daemon/controller/handlers/billing"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/require"
)

// TestGrants_MonthlyActiveUsers tests read actions to assert that grants are being applied properly
//
//	 Role - which scope the role is created in
//			- global level
func TestGrants_MonthlyActiveUsers(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))

	repoFn := func() (*billing.Repository, error) {
		return billing.TestRepo(t, conn), nil
	}
	billing.TestGenerateActiveUsers(t, conn)

	today := time.Now().UTC()
	monthStart := time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, time.UTC)
	threeMonthsAgo := time.Date(monthStart.AddDate(0, -3, 0).Year(), monthStart.AddDate(0, -3, 0).Month(), 1, 0, 0, 0, 0, time.UTC).Format("2006-01")
	oneMonthAgo := time.Date(monthStart.AddDate(0, -1, 0).Year(), monthStart.AddDate(0, -1, 0).Month(), 1, 0, 0, 0, 0, time.UTC).Format("2006-01")

	s, err := billingservice.NewService(ctx, repoFn)
	require.NoError(t, err)

	t.Run("MonthlyActiveUsers", func(t *testing.T) {
		testcases := []struct {
			name                  string
			input                 *pbs.MonthlyActiveUsersRequest
			userFunc              func() (*iam.User, auth.Account)
			wantErr               error
			expectedItemsReturned int
		}{
			{
				name: "global role with wildcard returns monthly active users",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				input: &pbs.MonthlyActiveUsersRequest{
					StartTime: threeMonthsAgo,
					EndTime:   oneMonthAgo,
				},
				expectedItemsReturned: 2,
			},
			{
				name: "global role + direct association with type billing returns monthly active users",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=billing;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				input: &pbs.MonthlyActiveUsersRequest{
					StartTime: threeMonthsAgo,
					EndTime:   oneMonthAgo,
				},
				expectedItemsReturned: 2,
			},
			{
				name: "global role + direct association with multiple roles returns monthly active users",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=group;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=billing;actions=no-op"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=billing;actions=monthly-active-users"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				input: &pbs.MonthlyActiveUsersRequest{
					StartTime: threeMonthsAgo,
					EndTime:   oneMonthAgo,
				},
				expectedItemsReturned: 2,
			},
			{
				name: "global role + group association with type billing returns monthly active users",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=billing;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				input: &pbs.MonthlyActiveUsersRequest{
					StartTime: threeMonthsAgo,
					EndTime:   oneMonthAgo,
				},
				expectedItemsReturned: 2,
			},
			{
				name: "global role + managed group association with type billing returns monthly active users",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=billing;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				input: &pbs.MonthlyActiveUsersRequest{
					StartTime: threeMonthsAgo,
					EndTime:   oneMonthAgo,
				},
				expectedItemsReturned: 2,
			},
			{
				name: "global role with type billing and actions monthly-active-users returns monthly active users",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=billing;actions=monthly-active-users"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				input: &pbs.MonthlyActiveUsersRequest{
					StartTime: threeMonthsAgo,
					EndTime:   oneMonthAgo,
				},
				expectedItemsReturned: 2,
			},
			{
				name: "global role with non-applicable type returns an error",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=group;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				input: &pbs.MonthlyActiveUsersRequest{
					StartTime: threeMonthsAgo,
					EndTime:   oneMonthAgo,
				},
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "global role with billing type and non-applicable actions returns an error",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=billing;actions=no-op"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				input: &pbs.MonthlyActiveUsersRequest{
					StartTime: threeMonthsAgo,
					EndTime:   oneMonthAgo,
				},
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "global role grant this with a non-applicable type returns a permission error",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=group;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				input: &pbs.MonthlyActiveUsersRequest{
					StartTime: threeMonthsAgo,
					EndTime:   oneMonthAgo,
				},
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "global role grant descendant returns no monthly active users",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=billing;actions=*"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				input: &pbs.MonthlyActiveUsersRequest{
					StartTime: threeMonthsAgo,
					EndTime:   oneMonthAgo,
				},
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "global role grant descendant returns no monthly active users",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org.PublicId,
						Grants:      []string{"ids=*;type=billing;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				input: &pbs.MonthlyActiveUsersRequest{
					StartTime: threeMonthsAgo,
					EndTime:   oneMonthAgo,
				},
				wantErr: handlers.ForbiddenError(),
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, accountID := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, finalErr := s.MonthlyActiveUsers(fullGrantAuthCtx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, finalErr, tc.wantErr)
					return
				}
				require.NoError(t, finalErr)
				require.Len(t, got.Items, tc.expectedItemsReturned)
			})
		}
	})
}
