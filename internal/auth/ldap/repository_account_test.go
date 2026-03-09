// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRepository_CreateAccount(t *testing.T) {
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testWrapper := db.TestWrapper(t)

	testKms := kms.TestKms(t, testConn, testWrapper)
	iamRepo := iam.TestRepo(t, testConn, testWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	testCtx := context.Background()
	databaseWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	testRepo, err := NewRepository(testCtx, testRw, testRw, testKms)
	assert.NoError(t, err)

	authMethod := TestAuthMethod(t, testConn, databaseWrapper, org.GetPublicId(), []string{"ldaps://ldap1"})

	tests := []struct {
		name            string
		repo            *Repository
		in              *Account
		opts            []Option
		want            *Account
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-account",
			repo:            testRepo,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing account: parameter violation: error #100",
		},
		{
			name:            "missing-embedded-account",
			in:              &Account{},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing embedded account: parameter violation: error #100",
		},
		{
			name: "missing-auth-method-id",
			in: &Account{
				Account: &store.Account{
					ScopeId: org.PublicId,
				},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method id: parameter violation: error #100",
		},
		{
			name: "missing-scope-id",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
				},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing scope id: parameter violation: error #100",
		},
		{
			name: "invalid-public-id-set",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					PublicId:     "invalid-public-id-set",
					LoginName:    "invalid-public-id-set",
				},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "public id must be empty: parameter violation: error #100",
		},
		{
			name: "missing-login-name",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					ScopeId:      org.PublicId,
				},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing login name: parameter violation: error #100",
		},
		{
			name: "valid-no-options",
			repo: testRepo,
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					ScopeId:      org.PublicId,
					LoginName:    "valid-no-options",
				},
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					ScopeId:      org.PublicId,
					LoginName:    "valid-no-options",
				},
			},
		},
		{
			name: "valid-with-name",
			repo: testRepo,
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					ScopeId:      org.PublicId,
					LoginName:    "valid-with-name",
					Name:         "test-name-repo",
				},
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					ScopeId:      org.PublicId,
					LoginName:    "valid-with-name",
					Name:         "test-name-repo",
				},
			},
		},
		{
			name: "valid-with-description",
			repo: testRepo,
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					ScopeId:      org.PublicId,
					LoginName:    "valid-with-description",
					Description:  ("test-description-repo"),
				},
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					ScopeId:      org.PublicId,
					LoginName:    "valid-with-description",
					Description:  ("test-description-repo"),
				},
			},
		},
		{
			name: "get-wrapper-err",
			repo: func() *Repository {
				kms := &mockGetWrapperer{
					getErr: errors.New(testCtx, errors.Encrypt, "test", "get-db-wrapper-err"),
				}
				r, err := NewRepository(testCtx, testRw, testRw, kms)
				require.NoError(t, err)
				return r
			}(),
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					ScopeId:      org.PublicId,
					LoginName:    "get-wrapper-err",
				},
			},
			wantErrMatch:    errors.T(errors.Encrypt),
			wantErrContains: "get-db-wrapper-err: encryption issue",
		},
		{
			name: "write-err",
			repo: func() *Repository {
				conn, mock := db.TestSetupWithMock(t)
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id", "version"}).AddRow("1", 1)) // oplog: get ticket
				mock.ExpectQuery(`INSERT`).WillReturnError(fmt.Errorf("write-err"))
				mock.ExpectRollback()
				rw := db.New(conn)
				r, err := NewRepository(testCtx, rw, rw, testKms)
				require.NoError(t, err)
				return r
			}(),
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					ScopeId:      org.PublicId,
					LoginName:    "get-wrapper-err",
				},
			},
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "write-err",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := tc.repo.CreateAccount(testCtx, tc.in, tc.opts...)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "Unexpected error %s", err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assertPublicId(t, globals.LdapAccountPrefix, got.PublicId)
			assert.NotSame(tc.in, got)
			assert.NotEmpty(got.CreateTime)
			assert.NotEmpty(got.UpdateTime)
			assert.Equal(got.CreateTime, got.UpdateTime)
			tc.want.CreateTime = got.CreateTime
			tc.want.UpdateTime = got.UpdateTime
			tc.want.PublicId = got.PublicId
			tc.want.Version = 1
			assert.Empty(cmp.Diff(tc.want, got, protocmp.Transform()))
			assert.NoError(db.TestVerifyOplog(t, testRw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}
}

func TestRepository_CreateAccount_DuplicateFields(t *testing.T) {
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testWrapper := db.TestWrapper(t)

	testKms := kms.TestKms(t, testConn, testWrapper)
	iamRepo := iam.TestRepo(t, testConn, testWrapper)
	testCtx := context.Background()

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(testCtx, testRw, testRw, testKms)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		databaseWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		authMethod := TestAuthMethod(t, testConn, databaseWrapper, org.GetPublicId(), []string{"ldaps://ldap1"})

		in := &Account{
			Account: &store.Account{
				AuthMethodId: authMethod.GetPublicId(),
				ScopeId:      org.GetPublicId(),
				Name:         "test-name-repo",
				LoginName:    "login-name",
			},
		}

		got, err := repo.CreateAccount(context.Background(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.LdapAccountPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in.PublicId = ""
		got2, err := repo.CreateAccount(context.Background(), in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "Unexpected error %s", err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-parents", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(testCtx, testRw, testRw, testKms)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		databaseWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		authMethodA := TestAuthMethod(t, testConn, databaseWrapper, org.GetPublicId(), []string{"ldaps://ldap1"})
		authMethodB := TestAuthMethod(t, testConn, databaseWrapper, org.GetPublicId(), []string{"ldaps://ldap2"})
		in := &Account{
			Account: &store.Account{
				ScopeId:   org.PublicId,
				Name:      "test-name-repo",
				LoginName: "login1",
			},
		}
		in2 := in.clone()

		in.AuthMethodId = authMethodA.GetPublicId()
		got, err := repo.CreateAccount(context.Background(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.LdapAccountPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.AuthMethodId = authMethodB.GetPublicId()
		got2, err := repo.CreateAccount(context.Background(), in2)
		assert.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, globals.LdapAccountPrefix, got2.PublicId)
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})

	t.Run("invalid-duplicate-login-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(testCtx, testRw, testRw, testKms)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		databaseWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		authMethod := TestAuthMethod(t, testConn, databaseWrapper, org.GetPublicId(), []string{"ldaps://ldap1"})
		in := &Account{
			Account: &store.Account{
				AuthMethodId: authMethod.GetPublicId(),
				ScopeId:      org.PublicId,
				LoginName:    "login-name-1",
			},
		}

		got, err := repo.CreateAccount(context.Background(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.LdapAccountPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in.PublicId = ""
		got2, err := repo.CreateAccount(context.Background(), in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "Unexpected error %s", err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-login-name-diff-auth-method", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(testCtx, testRw, testRw, testKms)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		databaseWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		authMethodA := TestAuthMethod(t, testConn, databaseWrapper, org.GetPublicId(), []string{"ldaps://ldap1"})
		authMethodB := TestAuthMethod(t, testConn, databaseWrapper, org.GetPublicId(), []string{"ldaps://ldap2"})
		in := &Account{
			Account: &store.Account{
				AuthMethodId: authMethodA.PublicId,
				ScopeId:      org.PublicId,
				LoginName:    "login-name-1",
			},
		}
		in2 := in.clone()

		in.AuthMethodId = authMethodA.GetPublicId()
		got, err := repo.CreateAccount(context.Background(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.LdapAccountPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(in.LoginName, got.LoginName)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.AuthMethodId = authMethodB.GetPublicId()
		got2, err := repo.CreateAccount(context.Background(), in2)
		assert.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, globals.LdapAccountPrefix, got2.PublicId)
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(in2.LoginName, got2.LoginName)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})
}

func TestRepository_LookupAccount(t *testing.T) {
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testWrapper := db.TestWrapper(t)

	testKms := kms.TestKms(t, testConn, testWrapper)
	iamRepo := iam.TestRepo(t, testConn, testWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	testCtx := context.Background()
	databaseWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	testRepo, err := NewRepository(testCtx, testRw, testRw, testKms)
	assert.NoError(t, err)

	authMethod := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
	account := TestAccount(t, testConn, authMethod, "test-login-name")

	newAcctId, err := newAccountId(testCtx, authMethod.PublicId, "test-not-matching")
	require.NoError(t, err)
	tests := []struct {
		name            string
		repo            *Repository
		publicId        string
		want            *Account
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-public-id",
			repo:            testRepo,
			wantErrMatch:    errors.T(errors.InvalidPublicId),
			wantErrContains: "missing public id: parameter violation: error #102",
		},
		{
			name:     "not-found",
			repo:     testRepo,
			publicId: newAcctId,
		},
		{
			name: "read-err",
			repo: func() *Repository {
				conn, mock := db.TestSetupWithMock(t)
				mock.ExpectQuery(`SELECT`).WillReturnError(fmt.Errorf("read-err"))
				rw := db.New(conn)
				r, err := NewRepository(testCtx, rw, rw, testKms)
				require.NoError(t, err)
				return r
			}(),
			publicId:        newAcctId,
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "read-err",
		},
		{
			name:     "with-existing-account-id",
			repo:     testRepo,
			publicId: account.GetPublicId(),
			want:     account,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := tc.repo.LookupAccount(testCtx, tc.publicId)
			if tc.wantErrMatch != nil {
				assert.Truef(errors.Match(tc.wantErrMatch, err), "Unexpected error %s", err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.EqualValues(tc.want, got)
		})
	}
}

func TestRepository_DeleteAccount(t *testing.T) {
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testWrapper := db.TestWrapper(t)

	testCtx := context.Background()
	testKms := kms.TestKms(t, testConn, testWrapper)
	iamRepo := iam.TestRepo(t, testConn, testWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	authMethod := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
	account := TestAccount(t, testConn, authMethod, "create-success")
	newAcctId, err := newAccountId(testCtx, authMethod.PublicId, "not-matching")
	require.NoError(t, err)

	testRepo, err := NewRepository(testCtx, testRw, testRw, testKms)
	assert.NoError(t, err)
	require.NotNil(t, testRepo)

	tests := []struct {
		name            string
		repo            *Repository
		publicId        string
		want            int
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-public-id",
			repo:            testRepo,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing public id: parameter violation: error #100",
		},
		{
			name:            "not-found",
			repo:            testRepo,
			publicId:        newAcctId,
			wantErrMatch:    errors.T(errors.RecordNotFound),
			wantErrContains: "account not found",
		},
		{
			name: "get-wrapper-err",
			repo: func() *Repository {
				kms := &mockGetWrapperer{
					getErr: errors.New(testCtx, errors.Encrypt, "test", "get-db-wrapper-err"),
				}
				r, err := NewRepository(testCtx, testRw, testRw, kms)
				require.NoError(t, err)
				return r
			}(),
			publicId:        account.GetPublicId(),
			wantErrMatch:    errors.T(errors.Encrypt),
			wantErrContains: "unable to get oplog wrapper",
		},
		{
			name: "oplog-metadata-err",
			repo: func() *Repository {
				conn, mock := db.TestSetupWithMock(t)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id"}).AddRow("1", "global")) // get account without auth method id
				rw := db.New(conn)
				r, err := NewRepository(testCtx, rw, rw, testKms)
				require.NoError(t, err)
				return r
			}(),
			publicId:        account.GetPublicId(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "ldap.(Account).oplog: missing auth method id",
		},
		{
			name: "write-err",
			repo: func() *Repository {
				conn, mock := db.TestSetupWithMock(t)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "auth_method_id"}).AddRow("1", "global", "1")) // get account
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT`).WillReturnError(fmt.Errorf("write-err")) // oplog: get ticket
				mock.ExpectRollback()
				rw := db.New(conn)
				r, err := NewRepository(testCtx, rw, rw, testKms)
				require.NoError(t, err)
				return r
			}(),
			publicId:        account.GetPublicId(),
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "write-err",
		},
		{
			name: "too-many-rows-affected",
			repo: func() *Repository {
				conn, mock := db.TestSetupWithMock(t)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "auth_method_id"}).AddRow("1", "global", "1")) // get account
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id", "version"}).AddRow("1", 1)) // oplog: get ticket
				mock.ExpectExec(`DELETE`).WillReturnResult(sqlmock.NewResult(1, 2))
				mock.ExpectQuery(`INSERT`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("1"))               // oplog: entry
				mock.ExpectQuery(`INSERT`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("1"))               // oplog: metadata
				mock.ExpectExec(`UPDATE`).WillReturnResult(sqlmock.NewResult(0, 1))                                  // oplog: update ticket version
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id", "version"}).AddRow("1", 1)) // oplog: get ticket
				mock.ExpectRollback()
				rw := db.New(conn)
				r, err := NewRepository(testCtx, rw, rw, testKms)
				require.NoError(t, err)
				return r
			}(),
			publicId:        account.GetPublicId(),
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "more than 1 resource would have been deleted",
		},
		{
			name: "delete-err",
			repo: func() *Repository {
				conn, mock := db.TestSetupWithMock(t)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "auth_method_id"}).AddRow("1", "global", "1")) // get account
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id", "version"}).AddRow("1", 1)) // oplog: get ticket
				mock.ExpectExec(`DELETE`).WillReturnError(fmt.Errorf("delete-err"))
				mock.ExpectRollback()
				rw := db.New(conn)
				r, err := NewRepository(testCtx, rw, rw, testKms)
				require.NoError(t, err)
				return r
			}(),
			publicId:        account.GetPublicId(),
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "delete-err",
		},
		{
			name:     "success",
			repo:     testRepo,
			publicId: account.GetPublicId(),
			want:     1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.repo.DeleteAccount(context.Background(), tc.publicId)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "Unexpected error %s", err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.EqualValues(tc.want, got)
		})
	}
}

func TestRepository_listAccounts(t *testing.T) {
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})

	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testWrapper := db.TestWrapper(t)

	testCtx := context.Background()
	testKms := kms.TestKms(t, testConn, testWrapper)
	iamRepo := iam.TestRepo(t, testConn, testWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	testRepo, err := NewRepository(testCtx, testRw, testRw, testKms)
	assert.NoError(t, err)

	authMethod1 := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
	authMethod2 := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap2"})
	authMethod3 := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap2"})
	accounts1 := []*Account{
		TestAccount(t, testConn, authMethod1, "create-success"),
		TestAccount(t, testConn, authMethod1, "create-success2"),
		TestAccount(t, testConn, authMethod1, "create-success3"),
	}
	accounts2 := []*Account{
		TestAccount(t, testConn, authMethod2, "create-success"),
		TestAccount(t, testConn, authMethod2, "create-success2"),
		TestAccount(t, testConn, authMethod2, "create-success3"),
	}
	slices.Reverse(accounts1)
	slices.Reverse(accounts2)

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			Account{},
			store.Account{},
			timestamp.Timestamp{},
			timestamppb.Timestamp{},
		),
	}

	tests := []struct {
		name            string
		repo            *Repository
		publicId        string
		opts            []Option
		want            []*Account
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-auth-method-id",
			repo:            testRepo,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method id: parameter violation: error #100",
		},
		{
			name:     "with-no-account-ids",
			repo:     testRepo,
			publicId: authMethod3.GetPublicId(),
			want:     []*Account{},
		},
		{
			name:     "with-first-auth-method-id",
			repo:     testRepo,
			publicId: authMethod1.GetPublicId(),
			want:     accounts1,
		},
		{
			name: "read-err",
			repo: func() *Repository {
				conn, mock := db.TestSetupWithMock(t)
				mock.ExpectQuery(`SELECT`).WillReturnError(fmt.Errorf("read-err"))
				rw := db.New(conn)
				r, err := NewRepository(testCtx, rw, rw, testKms)
				require.NoError(t, err)
				return r
			}(),
			publicId:        authMethod1.GetPublicId(),
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "read-err",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, ttime, err := tc.repo.listAccounts(testCtx, tc.publicId, tc.opts...)
			if tc.wantErrMatch != nil {
				assert.Truef(errors.Match(tc.wantErrMatch, err), "Unexpected error %s", err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

			require.Empty(cmp.Diff(got, tc.want, cmpOpts...))
		})
	}

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing auth method id", func(t *testing.T) {
			t.Parallel()
			_, _, err := testRepo.listAccounts(testCtx, "", WithLimit(testCtx, 1))
			require.ErrorContains(t, err, "missing auth method id")
		})
	})

	t.Run("success-without-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := testRepo.listAccounts(testCtx, authMethod1.PublicId, WithLimit(testCtx, 10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, accounts1, cmpOpts...))
	})
	t.Run("success-with-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := testRepo.listAccounts(testCtx, authMethod1.PublicId, WithStartPageAfterItem(testCtx, accounts1[0]), WithLimit(testCtx, 10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, accounts1[1:], cmpOpts...))
	})
}

func TestRepository_listAccountsRefresh(t *testing.T) {
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	testWrapper := db.TestWrapper(t)

	ctx := context.Background()
	testKms := kms.TestKms(t, conn, testWrapper)
	iamRepo := iam.TestRepo(t, conn, testWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := testKms.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	repo, err := NewRepository(ctx, rw, rw, testKms)
	assert.NoError(t, err)

	fiveDaysAgo := time.Now().AddDate(0, 0, -5)

	authMethod1 := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
	authMethod2 := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, []string{"ldaps://ldap2"})
	accounts1 := []*Account{
		TestAccount(t, conn, authMethod1, "create-success"),
		TestAccount(t, conn, authMethod1, "create-success2"),
		TestAccount(t, conn, authMethod1, "create-success3"),
	}
	accounts2 := []*Account{
		TestAccount(t, conn, authMethod2, "create-success"),
		TestAccount(t, conn, authMethod2, "create-success2"),
		TestAccount(t, conn, authMethod2, "create-success3"),
	}

	slices.Reverse(accounts1)
	_ = accounts2

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			Account{},
			store.Account{},
			timestamp.Timestamp{},
			timestamppb.Timestamp{},
		),
		cmpopts.SortSlices(func(i, j string) bool { return i < j }),
	}

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing updated after", func(t *testing.T) {
			t.Parallel()
			_, _, err := repo.listAccountsRefresh(ctx, authMethod1.PublicId, time.Time{}, WithLimit(ctx, 1))
			require.ErrorContains(t, err, "missing updated after time")
		})
		t.Run("missing auth method id", func(t *testing.T) {
			t.Parallel()
			_, _, err := repo.listAccountsRefresh(ctx, "", fiveDaysAgo, WithLimit(ctx, 1))
			require.ErrorContains(t, err, "missing auth method id")
		})
	})

	t.Run("success-without-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.listAccountsRefresh(ctx, authMethod1.PublicId, fiveDaysAgo, WithLimit(ctx, 10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, accounts1, cmpOpts...))
	})
	t.Run("success-with-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.listAccountsRefresh(ctx, authMethod1.PublicId, fiveDaysAgo, WithStartPageAfterItem(ctx, accounts1[0]), WithLimit(ctx, 10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, accounts1[1:], cmpOpts...))
	})
	t.Run("success-without-after-item-recent-updated-after", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.listAccountsRefresh(ctx, authMethod1.PublicId, accounts1[len(accounts1)-1].GetUpdateTime().AsTime(), WithLimit(ctx, 10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, accounts1[:len(accounts1)-1], cmpOpts...))
	})
	t.Run("success-with-after-item-recent-updated-after", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.listAccountsRefresh(ctx, authMethod1.PublicId, accounts1[len(accounts1)-1].GetUpdateTime().AsTime(), WithStartPageAfterItem(ctx, accounts1[0]), WithLimit(ctx, 10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, accounts1[1:len(accounts1)-1], cmpOpts...))
	})
}

func TestRepository_estimatedCount(t *testing.T) {
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	testWrapper := db.TestWrapper(t)

	ctx := context.Background()
	testKms := kms.TestKms(t, conn, testWrapper)
	iamRepo := iam.TestRepo(t, conn, testWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := testKms.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	repo, err := NewRepository(ctx, rw, rw, testKms)
	assert.NoError(t, err)

	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)

	// Check total entries at start, expect 0
	numItems, err := repo.estimatedAccountCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	// create account and check count, expect 1
	authMethod1 := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
	acct := TestAccount(t, conn, authMethod1, "create-success")
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	numItems, err = repo.estimatedAccountCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, numItems)

	// Delete acct and check count, expect 0 again
	_, err = repo.DeleteAccount(ctx, acct.GetPublicId())
	require.NoError(t, err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	numItems, err = repo.estimatedAccountCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)
}

func TestRepository_listDeletedIds(t *testing.T) {
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	testWrapper := db.TestWrapper(t)

	ctx := context.Background()
	testKms := kms.TestKms(t, conn, testWrapper)
	iamRepo := iam.TestRepo(t, conn, testWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := testKms.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	repo, err := NewRepository(ctx, rw, rw, testKms)
	assert.NoError(t, err)

	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)

	// Check total entries at start, expect 0
	numItems, err := repo.estimatedAccountCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	// create account and check deleted ids, should be empty
	authMethod1 := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
	acct := TestAccount(t, conn, authMethod1, "create-success")
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	deletedIds, ttime, err := repo.listDeletedAccountIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Delete acct and check count, expect 1 entry
	_, err = repo.DeleteAccount(ctx, acct.GetPublicId())
	require.NoError(t, err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	deletedIds, ttime, err = repo.listDeletedAccountIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	assert.Empty(
		t,
		cmp.Diff(
			[]string{acct.GetPublicId()},
			deletedIds,
			cmpopts.SortSlices(func(i, j string) bool { return i < j }),
		),
	)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = repo.listDeletedAccountIds(ctx, time.Now())
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func TestRepository_ListAccounts_Limits(t *testing.T) {
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testWrapper := db.TestWrapper(t)

	testCtx := context.Background()
	testKms := kms.TestKms(t, testConn, testWrapper)
	iamRepo := iam.TestRepo(t, testConn, testWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})

	accountCount := 10
	for i := 0; i < accountCount; i++ {
		TestAccount(t, testConn, am, fmt.Sprintf("create-success-%d", i))
	}

	tests := []struct {
		name     string
		repoOpts []Option
		listOpts []Option
		wantLen  int
	}{
		{
			name:    "with-no-limits",
			wantLen: accountCount,
		},
		{
			name:     "with-repo-limit",
			repoOpts: []Option{WithLimit(testCtx, 3)},
			wantLen:  3,
		},
		{
			name:     "with-negative-repo-limit",
			repoOpts: []Option{WithLimit(testCtx, -1)},
			wantLen:  accountCount,
		},
		{
			name:     "with-list-limit",
			listOpts: []Option{WithLimit(testCtx, 3)},
			wantLen:  3,
		},
		{
			name:     "with-negative-list-limit",
			listOpts: []Option{WithLimit(testCtx, -1)},
			wantLen:  accountCount,
		},
		{
			name:     "with-repo-smaller-than-list-limit",
			repoOpts: []Option{WithLimit(testCtx, 2)},
			listOpts: []Option{WithLimit(testCtx, 6)},
			wantLen:  6,
		},
		{
			name:     "with-repo-larger-than-list-limit",
			repoOpts: []Option{WithLimit(testCtx, 6)},
			listOpts: []Option{WithLimit(testCtx, 2)},
			wantLen:  2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(testCtx, testRw, testRw, testKms, tc.repoOpts...)
			assert.NoError(err)
			require.NotNil(repo)
			got, ttime, err := repo.listAccounts(context.Background(), am.GetPublicId(), tc.listOpts...)
			require.NoError(err)
			assert.Len(got, tc.wantLen)
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		})
	}
}

func TestRepository_UpdateAccount(t *testing.T) {
	testCtx := context.Background()
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testWrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, testConn, testWrapper)
	iamRepo := iam.TestRepo(t, testConn, testWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})

	testRepo, err := NewRepository(testCtx, testRw, testRw, testKms)
	assert.NoError(t, err)
	require.NotNil(t, testRepo)

	changeName := func(s string) func(*Account) *Account {
		return func(a *Account) *Account {
			a.Name = s
			return a
		}
	}

	changeDescription := func(s string) func(*Account) *Account {
		return func(a *Account) *Account {
			a.Description = s
			return a
		}
	}

	makeNil := func() func(*Account) *Account {
		return func(a *Account) *Account {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*Account) *Account {
		return func(a *Account) *Account {
			return &Account{}
		}
	}

	deletePublicId := func() func(*Account) *Account {
		return func(a *Account) *Account {
			a.PublicId = ""
			return a
		}
	}

	nonExistentPublicId := func() func(*Account) *Account {
		return func(a *Account) *Account {
			a.PublicId = "abcd_OOOOOOOOOO"
			return a
		}
	}

	combine := func(fns ...func(a *Account) *Account) func(*Account) *Account {
		return func(a *Account) *Account {
			for _, fn := range fns {
				a = fn(a)
			}
			return a
		}
	}

	tests := []struct {
		name            string
		repo            *Repository
		scopeId         string
		version         uint32
		orig            *Account
		chgFn           func(*Account) *Account
		masks           []string
		want            *Account
		wantCount       int
		wantIsErr       errors.Code
		wantErrContains string
	}{
		{
			name:    "nil-account",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{},
			},
			chgFn:           makeNil(),
			masks:           []string{NameField, DescriptionField},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "missing Account: parameter violation: error #100",
		},
		{
			name:    "nil-embedded-account",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{},
			},
			chgFn:           makeEmbeddedNil(),
			masks:           []string{NameField, DescriptionField},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "missing embedded Account: parameter violation: error #100",
		},
		{
			name:    "no-scope-id",
			repo:    testRepo,
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name: "no-scope-id-test-name-repo",
				},
			},
			chgFn:           changeName("no-scope-id-test-update-name-repo"),
			masks:           []string{NameField},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "missing scope id: parameter violation: error #100",
		},
		{
			name:    "missing-version",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			orig: &Account{
				Account: &store.Account{
					Name: "missing-version-test-name-repo",
				},
			},
			chgFn:           changeName("test-update-name-repo"),
			masks:           []string{NameField},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "missing version: parameter violation: error #100",
		},
		{
			name:    "no-public-id",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{},
			},
			chgFn:           deletePublicId(),
			masks:           []string{NameField, DescriptionField},
			wantIsErr:       errors.InvalidPublicId,
			wantErrContains: "missing public id: parameter violation: error #102",
		},
		{
			name:    "updating-non-existent-account",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name: "updating-non-existent-Account-test-name-repo",
				},
			},
			chgFn:           combine(nonExistentPublicId(), changeName("updating-non-existent-Account-test-update-name-repo")),
			masks:           []string{NameField},
			wantIsErr:       errors.RecordNotFound,
			wantErrContains: "record not found",
		},
		{
			name:    "empty-field-mask",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name: "empty-field-mask-test-name-repo",
				},
			},
			chgFn:           changeName("empty-field-mask-test-update-name-repo"),
			wantIsErr:       errors.EmptyFieldMask,
			wantErrContains: "missing field mask: parameter violation: error #104",
		},
		{
			name:    "read-only-fields-in-field-mask",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name: "read-only-fields-in-field-mask-test-name-repo",
				},
			},
			chgFn:           changeName("read-only-fields-in-field-mask-test-update-name-repo"),
			masks:           []string{"PublicId", "CreateTime", "UpdateTime", "AuthMethodId"},
			wantIsErr:       errors.InvalidFieldMask,
			wantErrContains: "PublicId: parameter violation: error #103",
		},
		{
			name:    "unknown-field-in-field-mask",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name: "unknown-field-in-field-mask-test-name-repo",
				},
			},
			chgFn:           changeName("unknown-field-in-field-mask-test-update-name-repo"),
			masks:           []string{"Bilbo"},
			wantIsErr:       errors.InvalidFieldMask,
			wantErrContains: "Bilbo: parameter violation: error #103",
		},
		{
			name:    "change-name",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name: "change-name-test-name-repo",
				},
			},
			chgFn: changeName("change-name-test-update-name-repo"),
			masks: []string{NameField},
			want: &Account{
				Account: &store.Account{
					Name: "change-name-test-update-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "change-description",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Description: "test-description-repo",
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{DescriptionField},
			want: &Account{
				Account: &store.Account{
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "change-name-and-description",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name:        "change-name-and-description-test-name-repo",
					Description: "test-description-repo",
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("change-name-and-description-test-update-name-repo")),
			masks: []string{NameField, DescriptionField},
			want: &Account{
				Account: &store.Account{
					Name:        "change-name-and-description-test-update-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "delete-name",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name:        "delete-name-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{NameField},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &Account{
				Account: &store.Account{
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "delete-description",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name:        "delete-description-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{DescriptionField},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &Account{
				Account: &store.Account{
					Name: "delete-description-test-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "do-not-delete-name",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name:        "do-not-delete-name-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{DescriptionField},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &Account{
				Account: &store.Account{
					Name:        "do-not-delete-name-test-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "do-not-delete-description",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name:        "do-not-delete-description-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{NameField},
			chgFn: combine(changeDescription(""), changeName("do-not-delete-description-test-update-name-repo")),
			want: &Account{
				Account: &store.Account{
					Name:        "do-not-delete-description-test-update-name-repo",
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "get-wrapper-err",
			repo: func() *Repository {
				kms := &mockGetWrapperer{
					getErr: errors.New(testCtx, errors.Encrypt, "test", "get-db-wrapper-err"),
				}
				r, err := NewRepository(testCtx, testRw, testRw, kms)
				require.NoError(t, err)
				return r
			}(),
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name:        "get-wrapper-err",
					Description: "test-description-repo",
				},
			},
			masks:           []string{NameField},
			chgFn:           combine(changeDescription(""), changeName("get-wrapper-err-test-update-name-repo")),
			wantIsErr:       errors.Encrypt,
			wantErrContains: "get-db-wrapper-err: encryption issue",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			orig := TestAccount(t, testConn, am, tc.name, WithName(testCtx, tc.orig.GetName()), WithDescription(testCtx, tc.orig.GetDescription()))

			tc.orig.AuthMethodId = am.PublicId
			if tc.chgFn != nil {
				orig = tc.chgFn(orig)
			}
			got, gotCount, err := tc.repo.UpdateAccount(context.Background(), tc.scopeId, orig, tc.version, tc.masks)
			if tc.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tc.wantIsErr), err), "want err: %q got: %q", tc.wantIsErr, err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				assert.Equal(tc.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.Empty(tc.orig.PublicId)
			if tc.wantCount == 0 {
				assert.Equal(tc.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			require.NotNil(got)
			assertPublicId(t, globals.LdapAccountPrefix, got.PublicId)
			assert.Equal(tc.wantCount, gotCount, "row count")
			assert.NotSame(tc.orig, got)
			assert.Equal(tc.orig.AuthMethodId, got.AuthMethodId)
			underlyingDB, err := testConn.SqlDB(testCtx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
			if tc.want.Name == "" {
				dbassert.IsNull(got, "name")
				return
			}
			assert.Equal(tc.want.Name, got.Name)
			if tc.want.Description == "" {
				dbassert.IsNull(got, "description")
				return
			}
			assert.Equal(tc.want.Description, got.Description)
			if tc.wantCount > 0 {
				assert.NoError(db.TestVerifyOplog(t, testRw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
			}
		})
	}
}

func TestRepository_UpdateAccount_DupeNames(t *testing.T) {
	testCtx := context.Background()
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testWrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, testConn, testWrapper)
	iamRepo := iam.TestRepo(t, testConn, testWrapper)

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(testCtx, testRw, testRw, testKms)
		assert.NoError(err)
		require.NotNil(repo)

		name := "test-dup-name"
		org, _ := iam.TestScopes(t, iamRepo)
		databaseWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
		aa := TestAccount(t, testConn, am, "create-success1")
		ab := TestAccount(t, testConn, am, "create-success2")

		aa.Name = name
		got1, gotCount1, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), aa, 1, []string{NameField})
		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(name, got1.Name)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, testRw, aa.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))

		ab.Name = name
		got2, gotCount2, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), ab, 1, []string{NameField})
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "Unexpected error %s", err)
		assert.Nil(got2)
		assert.Equal(db.NoRowsAffected, gotCount2, "row count")
		err = db.TestVerifyOplog(t, testRw, ab.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
		assert.Error(err)
		assert.True(errors.IsNotFoundError(err))
	})

	t.Run("valid-duplicate-names-diff-AuthMethods", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(testCtx, testRw, testRw, testKms)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		databaseWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		ama := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
		aa := TestAccount(t, testConn, ama, "create-success1", WithName(testCtx, "test-name-aa"))

		amb := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap2"})
		ab := TestAccount(t, testConn, amb, "create-success2", WithName(testCtx, "test-name-ab"))

		ab.Name = aa.Name
		got3, gotCount3, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), ab, 1, []string{NameField})
		assert.NoError(err)
		require.NotNil(got3)
		assert.NotSame(ab, got3)
		assert.Equal(aa.Name, got3.Name)
		assert.Equal(1, gotCount3, "row count")
		assert.NoError(db.TestVerifyOplog(t, testRw, ab.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	})

	t.Run("change-auth-method-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(testCtx, testRw, testRw, testKms)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		databaseWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		ama := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
		aa := TestAccount(t, testConn, ama, "create-success1")

		amb := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap2"})
		ab := TestAccount(t, testConn, amb, "create-success2")

		assert.NotEqual(aa.AuthMethodId, ab.AuthMethodId)
		orig := aa.clone()

		aa.AuthMethodId = ab.AuthMethodId
		assert.Equal(aa.AuthMethodId, ab.AuthMethodId)

		got1, gotCount1, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), aa, 1, []string{NameField})

		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(orig.AuthMethodId, got1.AuthMethodId)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, testRw, aa.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	})
}

func assertPublicId(t *testing.T, prefix, actual string) {
	t.Helper()
	assert.NotEmpty(t, actual)
	parts := strings.Split(actual, "_")
	assert.Equalf(t, 2, len(parts), "want one '_' in PublicId, got multiple in %q", actual)
	assert.Equalf(t, prefix, parts[0], "PublicId want prefix: %q, got: %q in %q", prefix, parts[0], actual)
}
