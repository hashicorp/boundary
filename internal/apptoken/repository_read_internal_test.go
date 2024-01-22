// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1
package apptoken

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func Test_queryAppTokens(t *testing.T) {
	testCtx := context.Background()
	testConn, _ := db.TestSetup(t, "postgres")
	testRootWrapper := db.TestWrapper(t)
	testRw := db.New(testConn)
	testKms := kms.TestKms(t, testConn, testRootWrapper)
	testIamRepo := iam.TestRepo(t, testConn, testRootWrapper)
	testOrg, _ := iam.TestScopes(t, testIamRepo)
	testUser := iam.TestUser(t, testIamRepo, testOrg.GetPublicId())
	testRepo, err := NewRepository(testCtx, testRw, testRw, testKms, testIamRepo)
	require.NoError(t, err)
	testUserHistoryId, err := testRepo.ResolveUserHistoryId(testCtx, testUser.GetPublicId())
	require.NoError(t, err)

	tests := []struct {
		name            string
		repo            *Repository
		setup           func(t *testing.T, repo *Repository) (string, []any, []*AppToken)
		opts            []Option
		wantErrContains string
		wantErrMatch    *errors.Template
	}{
		{
			name: "success",
			repo: func() *Repository {
				testRepo, err := NewRepository(testCtx, testRw, testRw, testKms, testIamRepo)
				require.NoError(t, err)
				return testRepo
			}(),
			setup: func(t *testing.T, repo *Repository) (string, []any, []*AppToken) {
				tk := TestAppToken(t, testConn, testOrg.GetPublicId(), testUserHistoryId, "id=*;type=*;actions=read")
				return "select * from app_token_agg where public_id = @public_id limit %d",
					[]any{sql.Named("public_id", tk.PublicId)},
					[]*AppToken{tk}
			},
			opts: []Option{WithLimit(testCtx, 1)},
		},
		{
			name: "missing-query",
			repo: func() *Repository {
				testRepo, err := NewRepository(testCtx, testRw, testRw, testKms, testIamRepo)
				require.NoError(t, err)
				return testRepo
			}(),
			setup: func(t *testing.T, repo *Repository) (string, []any, []*AppToken) {
				tk := TestAppToken(t, testConn, testOrg.GetPublicId(), testUserHistoryId, "id=*;type=*;actions=read")
				return "", []any{sql.Named("public_id", tk.PublicId)}, nil
			},
			wantErrContains: "missing query",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name: "missing-limit",
			repo: func() *Repository {
				testRepo, err := NewRepository(testCtx, testRw, testRw, testKms, testIamRepo)
				require.NoError(t, err)
				return testRepo
			}(),
			setup: func(t *testing.T, repo *Repository) (string, []any, []*AppToken) {
				tk := TestAppToken(t, testConn, testOrg.GetPublicId(), testUserHistoryId, "id=*;type=*;actions=read")
				return "select * from app_token_agg where public_id = @public_id",
					[]any{sql.Named("public_id", tk.PublicId)},
					nil
			},
			wantErrContains: "query (select * from app_token_agg where public_id = @public_id must end with 'limit %d'",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name: "err-opts",
			repo: func() *Repository {
				testRepo, err := NewRepository(testCtx, testRw, testRw, testKms, testIamRepo)
				require.NoError(t, err)
				return testRepo
			}(),
			setup: func(t *testing.T, repo *Repository) (string, []any, []*AppToken) {
				tk := TestAppToken(t, testConn, testOrg.GetPublicId(), testUserHistoryId, "id=*;type=*;actions=read")
				return "select * from app_token_agg where public_id = @public_id limit %d",
					[]any{sql.Named("public_id", tk.PublicId)},
					nil
			},
			opts:            []Option{TestWithOptError(testCtx)},
			wantErrContains: "with opt error",
		},
		{
			name: "err-unknown",
			repo: func() *Repository {
				conn, mock := db.TestSetupWithMock(t)
				mock.ExpectBegin()
				mock.ExpectQuery(`select`).WillReturnError(fmt.Errorf("err-unknown"))
				mock.ExpectRollback()
				testMockRw := db.New(conn)
				r, err := NewRepository(testCtx, testMockRw, testMockRw, testKms, testIamRepo)
				require.NoError(t, err)
				return r
			}(),
			setup: func(t *testing.T, repo *Repository) (string, []any, []*AppToken) {
				tk := TestAppToken(t, testConn, testOrg.GetPublicId(), testUserHistoryId, "id=*;type=*;actions=read")
				return "select * from app_token_agg where public_id = @public_id limit %d",
					[]any{sql.Named("public_id", tk.PublicId)},
					nil
			},
			wantErrContains: "err-unknown",
		},
		{
			name: "err-unmatched-grants",
			repo: func() *Repository {
				conn, mock := db.TestSetupWithMock(t)
				mock.ExpectBegin()
				mock.ExpectQuery(`select`).WillReturnRows(sqlmock.NewRows(
					[]string{
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
					"test-id", time.Now(), time.Now(), "name", "desc", "created-by", "scope-id", 0, "id=*;type=*;actions=read|id=*;type=*;actions=write", "id=*;type=*;actions=read"))
				mock.ExpectQuery(`select`).WillReturnRows(sqlmock.NewRows(
					[]string{"now"}).AddRow(time.Now()))
				mock.ExpectCommit()
				testMockRw := db.New(conn)
				r, err := NewRepository(testCtx, testMockRw, testMockRw, testKms, testIamRepo)
				require.NoError(t, err)
				return r
			}(),
			setup: func(t *testing.T, repo *Repository) (string, []any, []*AppToken) {
				tk := TestAppToken(t, testConn, testOrg.GetPublicId(), testUserHistoryId, "id=*;type=*;actions=read")
				return "select * from app_token_agg where public_id = @public_id limit %d",
					[]any{sql.Named("public_id", tk.PublicId)},
					nil
			},
			wantErrContains: "canonical (2) and raw grants (1) are not the same len: integrity violation: error #1003",
		},
	}
	for _, tc := range tests {
		tc = tc
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NotNil(tc.setup)
			require.NotNil(tc.repo)
			query, args, wantTk := tc.setup(t, tc.repo)
			got, _, err := tc.repo.queryAppTokens(testCtx, query, args, tc.opts...)
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
				assert.Empty(cmp.Diff(wantTk, got, protocmp.Transform()))
			}
		})
	}
}
