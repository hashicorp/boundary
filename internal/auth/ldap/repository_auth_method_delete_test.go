// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_DeleteAuthMethod(t *testing.T) {
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testWrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, testConn, testWrapper)
	testCtx := context.Background()

	tests := []struct {
		name            string
		reader          db.Reader
		writer          db.Writer
		kms             kms.GetWrapperer
		authMethod      *AuthMethod
		wantRowsDeleted int
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:   "valid",
			reader: testRw,
			writer: testRw,
			kms:    testKms,
			authMethod: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, testConn, testWrapper))
				databaseWrapper, err := testKms.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"}, WithOperationalState(testCtx, InactiveState))
			}(),
			wantRowsDeleted: 1,
		},
		{
			name:            "no-public-id",
			reader:          testRw,
			writer:          testRw,
			kms:             testKms,
			authMethod:      func() *AuthMethod { am := AllocAuthMethod(); return &am }(),
			wantErrMatch:    errors.T(errors.InvalidPublicId),
			wantErrContains: "missing public id",
		},
		{
			name:   "not-found",
			reader: testRw,
			writer: testRw,
			kms:    testKms,
			authMethod: func() *AuthMethod {
				am := AllocAuthMethod()
				var err error
				am.PublicId, err = newAuthMethodId(testCtx)
				require.NoError(t, err)
				return &am
			}(),
		},
		{
			name: "lookup-err",
			reader: func() db.Reader {
				conn, mock := db.TestSetupWithMock(t)
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New(context.Background(), errors.Internal, "test", "lookup-error"))
				return db.New(conn)
			}(),
			writer: testRw,
			kms:    testKms,
			authMethod: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, testConn, testWrapper))
				databaseWrapper, err := testKms.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"}, WithOperationalState(testCtx, InactiveState))
			}(),
			wantErrMatch:    errors.T(errors.Internal),
			wantErrContains: "lookup-err",
		},
		{
			name:   "delete-err",
			reader: testRw,
			writer: func() db.Writer {
				conn, mock := db.TestSetupWithMock(t)
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New(context.Background(), errors.Internal, "test", "delete-error"))
				mock.ExpectRollback()
				return db.New(conn)
			}(),
			kms: testKms,
			authMethod: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, testConn, testWrapper))
				databaseWrapper, err := testKms.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"}, WithOperationalState(testCtx, InactiveState))
			}(),
			wantErrMatch:    errors.T(errors.Internal),
			wantErrContains: "delete-err",
		},
		{
			name:   "multiple-rows-err",
			reader: testRw,
			writer: func() db.Writer {
				conn, mock := db.TestSetupWithMock(t)
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id", "version"}).AddRow("1", 1)) // oplog: get ticket
				mock.ExpectExec(`DELETE`).WillReturnResult(sqlmock.NewResult(0, 10))
				mock.ExpectQuery(`INSERT`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("1"))               // oplog: insert metadata
				mock.ExpectQuery(`INSERT`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("1"))               // oplog: insert entry
				mock.ExpectExec(`UPDATE`).WillReturnResult(sqlmock.NewResult(0, 1))                                  // oplog: update ticket version
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id", "version"}).AddRow("1", 1)) // oplog: get ticket again
				mock.ExpectRollback()
				return db.New(conn)
			}(),
			kms: testKms,
			authMethod: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, testConn, testWrapper))
				databaseWrapper, err := testKms.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"}, WithOperationalState(testCtx, InactiveState))
			}(),
			wantErrMatch:    errors.T(errors.MultipleRecords),
			wantErrContains: "more than 1 auth method would have been deleted",
		},
		{
			name:   "getWrapper-err",
			reader: testRw,
			writer: testRw,
			kms: &mockGetWrapperer{
				getErr: errors.New(testCtx, errors.Encrypt, "test", "get-db-wrapper-err"),
			},
			authMethod: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, testConn, testWrapper))
				databaseWrapper, err := testKms.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"}, WithOperationalState(testCtx, InactiveState))
			}(),
			wantErrMatch:    errors.T(errors.Encrypt),
			wantErrContains: "unable to get oplog wrapper",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(testCtx, tc.reader, tc.writer, tc.kms)
			require.NoError(err)
			deletedRows, err := repo.DeleteAuthMethod(testCtx, tc.authMethod.PublicId)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "want err: %q got: %q", tc.wantErrMatch.Msg, err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}

				assert.Equalf(0, deletedRows, "expected 0 deleted rows and got %d", deletedRows)

				err := db.TestVerifyOplog(t, testRw, tc.authMethod.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				require.Errorf(err, "should not have found oplog entry for %s", tc.authMethod.PublicId)
				assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "expected error code %s and got %s", errors.RecordNotFound, err)

				return
			}
			require.NoError(err)
			assert.Equalf(tc.wantRowsDeleted, deletedRows, "expected rows deleted == %d and got %d", tc.wantRowsDeleted, deletedRows)

			if tc.wantRowsDeleted > 0 {
				err = db.TestVerifyOplog(t, testRw, tc.authMethod.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				require.NoErrorf(err, "unexpected error verifying oplog entry: %s", err)
			}
			found, err := repo.LookupAuthMethod(testCtx, tc.authMethod.PublicId)
			require.NoError(err)
			assert.Nil(found)
		})
	}
}
