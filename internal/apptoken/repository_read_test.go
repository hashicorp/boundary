// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/apptoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestLookupToken(t *testing.T) {
	testCtx := context.Background()
	testConn, _ := db.TestSetup(t, "postgres")
	testRootWrapper := db.TestWrapper(t)
	testRw := db.New(testConn)
	testKms := kms.TestKms(t, testConn, testRootWrapper)
	testIamRepo := iam.TestRepo(t, testConn, testRootWrapper)
	testOrg, _ := iam.TestScopes(t, testIamRepo)
	testUser := iam.TestUser(t, testIamRepo, testOrg.GetPublicId())
	testRepo, err := apptoken.NewRepository(testCtx, testRw, testRw, testKms, testIamRepo)
	require.NoError(t, err)
	testUserHistoryId, err := testRepo.ResolveUserHistoryId(testCtx, testUser.GetPublicId())
	require.NoError(t, err)

	tests := []struct {
		name            string
		repo            *apptoken.Repository
		setup           func(t *testing.T, repo *apptoken.Repository) (string, *apptoken.AppToken)
		opts            []apptoken.Option
		wantErrContains string
		wantErrMatch    *errors.Template
	}{
		{
			name: "success",
			repo: func() *apptoken.Repository {
				testRepo, err := apptoken.NewRepository(testCtx, testRw, testRw, testKms, testIamRepo)
				require.NoError(t, err)
				return testRepo
			}(),
			setup: func(t *testing.T, repo *apptoken.Repository) (string, *apptoken.AppToken) {
				tk := apptoken.TestAppToken(t, testConn, testOrg.GetPublicId(), testUserHistoryId, "id=*;type=*;actions=read")
				return tk.PublicId, tk
			},
		},
		{
			name: "not-found",
			repo: func() *apptoken.Repository {
				testRepo, err := apptoken.NewRepository(testCtx, testRw, testRw, testKms, testIamRepo)
				require.NoError(t, err)
				return testRepo
			}(),
			setup: func(t *testing.T, repo *apptoken.Repository) (string, *apptoken.AppToken) {
				return "not-found", nil
			},
		},
		{
			name: "err-more-than-one-tokens",
			repo: func() *apptoken.Repository {
				conn, mock := db.TestSetupWithMock(t)
				mock.ExpectQuery(`select`).WillReturnRows(sqlmock.NewRows([]string{
					"public_id",
					"create_time",
					"expiration_time",
					"name",
					"description",
					"created_by",
					"scope_id",
					"expiration_interval_in_max_seconds",
					"canonical_grants",
					"raw_grants",
				}).AddRow(
					"test-id", time.Now(), time.Now(), "name", "desc", "created-by", "scope-id", 0, "id=*;type=*;actions=read", "id=*;type=*;actions=read").AddRow(
					"test-id", time.Now(), time.Now(), "name", "desc", "created-by", "scope-id", 0, "id=*;type=*;actions=read", "id=*;type=*;actions=read"))
				testMockRw := db.New(conn)
				r, err := apptoken.NewRepository(testCtx, testMockRw, testMockRw, testKms, testIamRepo)
				require.NoError(t, err)
				return r
			}(),
			setup: func(t *testing.T, repo *apptoken.Repository) (string, *apptoken.AppToken) {
				return "test-id", nil
			},
			wantErrContains: "test-id matched more than one app token",
			wantErrMatch:    errors.T(errors.NotSpecificIntegrity),
		},
		{
			name: "err-unknown",
			repo: func() *apptoken.Repository {
				conn, mock := db.TestSetupWithMock(t)
				mock.ExpectQuery(`select`).WillReturnError(fmt.Errorf("err-unknown"))
				testMockRw := db.New(conn)
				r, err := apptoken.NewRepository(testCtx, testMockRw, testMockRw, testKms, testIamRepo)
				require.NoError(t, err)
				return r
			}(),
			setup: func(t *testing.T, repo *apptoken.Repository) (string, *apptoken.AppToken) {
				return "test-id", nil
			},
			wantErrContains: "err-unknown",
		},
		{
			name: "missing-id",
			repo: func() *apptoken.Repository {
				testRepo, err := apptoken.NewRepository(testCtx, testRw, testRw, testKms, testIamRepo)
				require.NoError(t, err)
				return testRepo
			}(),
			setup: func(t *testing.T, repo *apptoken.Repository) (string, *apptoken.AppToken) {
				return "", nil
			},
			wantErrContains: "missing app token id",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name: "err-opts",
			repo: func() *apptoken.Repository {
				testRepo, err := apptoken.NewRepository(testCtx, testRw, testRw, testKms, testIamRepo)
				require.NoError(t, err)
				return testRepo
			}(),
			setup: func(t *testing.T, repo *apptoken.Repository) (string, *apptoken.AppToken) {
				return "test-id", nil
			},
			opts:            []apptoken.Option{apptoken.TestWithOptError(testCtx)},
			wantErrContains: "with opt error",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NotNil(tc.setup)
			require.NotNil(tc.repo)
			wantTokenId, wantTk := tc.setup(t, tc.repo)
			got, err := tc.repo.LookupAppToken(testCtx, wantTokenId, tc.opts...)
			if tc.wantErrContains != "" {
				require.Error(err)
				assert.Empty(got)
				assert.Contains(err.Error(), tc.wantErrContains)
				if tc.wantErrMatch != nil {
					assert.Truef(errors.Match(tc.wantErrMatch, err), "want err code: %q got: %q", tc.wantErrMatch, err)
				}
				return
			}
			require.NoErrorf(err, "unexpected error: %s", err)
			switch {
			case wantTk == nil:
				assert.Nil(got)
			default:
				assert.Empty(cmp.Diff(wantTk.AppToken, got.AppToken, protocmp.Transform()))
			}
		})
	}
}
