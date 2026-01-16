// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
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
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRepository_CreateManagedGroup(t *testing.T) {
	t.Parallel()
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testRootWrapper := db.TestWrapper(t)

	testKms := kms.TestKms(t, testConn, testRootWrapper)
	iamRepo := iam.TestRepo(t, testConn, testRootWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	testCtx := context.Background()
	orgDbWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	testAuthMethod := TestAuthMethod(t, testConn, orgDbWrapper, org.GetPublicId(), []string{"ldaps://ldap1"})

	testRepo, err := NewRepository(testCtx, testRw, testRw, testKms)
	assert.NoError(t, err)
	require.NotNil(t, testRepo)

	acct1 := TestAccount(t, testConn, testAuthMethod, "alice", WithMemberOfGroups(testCtx, testGrpNames...))
	acct2 := TestAccount(t, testConn, testAuthMethod, "eve", WithMemberOfGroups(testCtx, testGrpNames...))
	const notTestGroupName = "not-test-group-name"
	acct3 := TestAccount(t, testConn, testAuthMethod, "bob", WithMemberOfGroups(testCtx, notTestGroupName))

	tests := []struct {
		name            string
		ctx             context.Context
		repo            *Repository
		scopeId         string
		in              *ManagedGroup
		opts            []Option
		want            *ManagedGroup
		wantMgmAcctIds  []string
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "nil-ManagedGroup",
			ctx:             testCtx,
			repo:            testRepo,
			scopeId:         org.GetPublicId(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing managed group: parameter violation: error #100",
		},
		{
			name:            "nil-embedded-ManagedGroup",
			ctx:             testCtx,
			repo:            testRepo,
			scopeId:         org.GetPublicId(),
			in:              &ManagedGroup{},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing embedded managed group: parameter violation: error #100",
		},
		{
			name:    "invalid-no-auth-method-id",
			ctx:     testCtx,
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method id: parameter violation: error #100",
		},
		{
			name:    "invalid-no-group-names",
			ctx:     testCtx,
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: testAuthMethod.PublicId,
				},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing group names: parameter violation: error #100",
		},
		{
			name:    "invalid-public-id-set",
			ctx:     testCtx,
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: testAuthMethod.PublicId,
					GroupNames:   string(TestEncodedGrpNames(t, testGrpNames...)),
					PublicId:     "mgldap_OOOOOOOOOO",
				},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "public id must be empty: parameter violation: error #100",
		},
		{
			name: "no-scope",
			ctx:  testCtx,
			repo: testRepo,
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: testAuthMethod.PublicId,
					GroupNames:   string(TestEncodedGrpNames(t, testGrpNames...)),
				},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing scope id: parameter violation: error #100",
		},
		{
			name:    "valid-no-options",
			ctx:     testCtx,
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: testAuthMethod.PublicId,
					GroupNames:   string(TestEncodedGrpNames(t, testGrpNames...)),
				},
			},
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: testAuthMethod.PublicId,
					GroupNames:   string(TestEncodedGrpNames(t, testGrpNames...)),
				},
			},
			wantMgmAcctIds: []string{acct1.PublicId, acct2.PublicId},
		},
		{
			name:    "valid-with-name",
			ctx:     testCtx,
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: testAuthMethod.PublicId,
					GroupNames:   string(TestEncodedGrpNames(t, testGrpNames...)),
					Name:         "test-name-repo",
				},
			},
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: testAuthMethod.PublicId,
					GroupNames:   string(TestEncodedGrpNames(t, testGrpNames...)),
					Name:         "test-name-repo",
				},
			},
			wantMgmAcctIds: []string{acct1.PublicId, acct2.PublicId},
		},
		{
			name:    "valid-with-description",
			ctx:     testCtx,
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: testAuthMethod.PublicId,
					GroupNames:   string(TestEncodedGrpNames(t, testGrpNames...)),
					Description:  ("test-description-repo"),
					Name:         "myname",
				},
			},
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: testAuthMethod.PublicId,
					GroupNames:   string(TestEncodedGrpNames(t, testGrpNames...)),
					Description:  ("test-description-repo"),
					Name:         "myname",
				},
			},
			wantMgmAcctIds: []string{acct1.PublicId, acct2.PublicId},
		},
		{
			name:    "not-test-grp-name",
			ctx:     testCtx,
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: testAuthMethod.PublicId,
					GroupNames:   string(TestEncodedGrpNames(t, notTestGroupName)),
				},
			},
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: testAuthMethod.PublicId,
					GroupNames:   string(TestEncodedGrpNames(t, notTestGroupName)),
				},
			},
			wantMgmAcctIds: []string{acct3.PublicId},
		},
		{
			name:    "duplicate-name", // must follow "valid-description" test
			ctx:     testCtx,
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: testAuthMethod.PublicId,
					GroupNames:   string(TestEncodedGrpNames(t, testGrpNames...)),
					Description:  ("test-description-repo"),
					Name:         "myname",
				},
			},
			wantErrMatch:    errors.T(errors.NotUnique),
			wantErrContains: `name "myname" already exists`,
		},
		{
			name: "get-oplog-wrapper-err",
			repo: func() *Repository {
				testKms := &mockGetWrapperer{
					getErr: errors.New(testCtx, errors.Encrypt, "test", "get-oplog-wrapper-err"),
				}

				testRepo, err := NewRepository(testCtx, testRw, testRw, testKms)
				assert.NoError(t, err)
				require.NotNil(t, testRepo)
				return testRepo
			}(),
			scopeId: org.GetPublicId(),
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: testAuthMethod.PublicId,
					GroupNames:   string(TestEncodedGrpNames(t, testGrpNames...)),
				},
			},
			wantErrMatch:    errors.T(errors.Encrypt),
			wantErrContains: "unable to get oplog wrapper",
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
			scopeId: org.GetPublicId(),
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: testAuthMethod.PublicId,
					GroupNames:   string(TestEncodedGrpNames(t, testGrpNames...)),
				},
			},
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "write-err",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.repo.CreateManagedGroup(tc.ctx, tc.scopeId, tc.in, tc.opts...)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "Unexpected error %s", err)
				if tc.wantErrContains != "" {
					assert.True(strings.Contains(err.Error(), tc.wantErrContains))
				}
				return
			}
			require.NoError(err)
			assert.Empty(tc.in.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.LdapManagedGroupPrefix, got.PublicId)
			assert.NotSame(tc.in, got)
			assert.Equal(tc.want.Name, got.Name)
			assert.Equal(tc.want.Description, got.Description)
			assert.Equal(got.CreateTime, got.UpdateTime)
			assert.Equal(tc.want.GroupNames, got.GroupNames)
			assert.NoError(db.TestVerifyOplog(t, testRw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))

			if tc.wantMgmAcctIds != nil {
				mgmAccts := auth.TestManagedGroupMemberAccounts(t, testConn, got.PublicId)
				for _, m := range mgmAccts {
					t.Log("ManagedGroupId: ", m.ManagedGroupId)
					t.Log("      MemberId: ", m.MemberId)
				}
				wantAccts := make([]*auth.ManagedGroupMemberAccount, 0, len(tc.wantMgmAcctIds))
				for _, id := range tc.wantMgmAcctIds {
					wantAccts = append(wantAccts, &auth.ManagedGroupMemberAccount{
						ManagedGroupId: got.PublicId,
						MemberId:       id,
					})
				}
				for _, m := range mgmAccts {
					m.CreateTime = nil
				}
				auth.TestSortManagedGroupMemberAccounts(t, wantAccts)
				assert.Equal(wantAccts, mgmAccts)
			}
		})
	}
}

func TestRepository_LookupManagedGroup(t *testing.T) {
	t.Parallel()
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	rootWrapper := db.TestWrapper(t)

	testKms := kms.TestKms(t, testConn, rootWrapper)
	iamRepo := iam.TestRepo(t, testConn, rootWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	testCtx := context.Background()
	orgDbWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	authMethod := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId, []string{"ldaps://ldap1"})
	mg := TestManagedGroup(t, testConn, authMethod, testGrpNames)
	acct1 := TestAccount(t, testConn, authMethod, "alice", WithMemberOfGroups(testCtx, testGrpNames...))
	acct2 := TestAccount(t, testConn, authMethod, "eve", WithMemberOfGroups(testCtx, testGrpNames...))

	newMgId, err := newManagedGroupId(testCtx)
	require.NoError(t, err)

	testRepo, err := NewRepository(testCtx, testRw, testRw, testKms)
	assert.NoError(t, err)
	require.NotNil(t, testRepo)

	tests := []struct {
		name            string
		ctx             context.Context
		repo            *Repository
		in              string
		want            *ManagedGroup
		wantMgmAcct     []*auth.ManagedGroupMemberAccount
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "With no public id",
			ctx:             testCtx,
			repo:            testRepo,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing public id: parameter violation",
		},
		{
			name: "With non existing mg id",
			ctx:  testCtx,
			repo: testRepo,
			in:   newMgId,
		},
		{
			name: "With existing mg id",
			ctx:  testCtx,
			repo: testRepo,
			in:   mg.GetPublicId(),
			want: mg,
			wantMgmAcct: []*auth.ManagedGroupMemberAccount{
				{
					CreateTime:     mg.CreateTime,
					ManagedGroupId: mg.PublicId,
					MemberId:       acct1.PublicId,
				},
				{
					CreateTime:     mg.CreateTime,
					ManagedGroupId: mg.PublicId,
					MemberId:       acct2.PublicId,
				},
			},
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
			in:              mg.GetPublicId(),
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "read-err",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.repo.LookupManagedGroup(tc.ctx, tc.in)
			if tc.wantErrMatch != nil {
				assert.Truef(errors.Match(tc.wantErrMatch, err), "Unexpected error %s", err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.EqualValues(tc.want, got)
			if tc.wantMgmAcct != nil {
				mgmAccts := auth.TestManagedGroupMemberAccounts(t, testConn, tc.want.PublicId)
				for _, m := range mgmAccts {
					t.Log("ManagedGroupId: ", m.ManagedGroupId)
					t.Log("      MemberId: ", m.MemberId)
				}
				auth.TestSortManagedGroupMemberAccounts(t, tc.wantMgmAcct)
				assert.Equal(tc.wantMgmAcct, mgmAccts)
			}
		})
	}
}

func TestRepository_DeleteManagedGroup(t *testing.T) {
	t.Parallel()
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testWrapper := db.TestWrapper(t)

	testCtx := context.Background()
	testKms := kms.TestKms(t, testConn, testWrapper)
	iamRepo := iam.TestRepo(t, testConn, testWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	orgDbWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	authMethod := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId, []string{"ldaps://ldap1"})

	mg := TestManagedGroup(t, testConn, authMethod, testGrpNames)
	newMgId, err := newManagedGroupId(testCtx)
	require.NoError(t, err)

	testRepo, err := NewRepository(testCtx, testRw, testRw, testKms)
	assert.NoError(t, err)
	require.NotNil(t, testRepo)

	tests := []struct {
		name            string
		ctx             context.Context
		repo            *Repository
		scopeId         string
		in              string
		want            int
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "With no scope id",
			ctx:             testCtx,
			repo:            testRepo,
			scopeId:         "",
			in:              mg.GetPublicId(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing scope id: parameter violation: error #100",
		},
		{
			name:            "With no public id",
			ctx:             testCtx,
			repo:            testRepo,
			scopeId:         org.GetPublicId(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing public id: parameter violation: error #100",
		},
		{
			name:            "With non existing managed group id",
			ctx:             testCtx,
			repo:            testRepo,
			scopeId:         org.GetPublicId(),
			in:              newMgId,
			wantErrMatch:    errors.T(errors.RecordNotFound),
			wantErrContains: "managed group not found",
		},
		{
			name: "get-oplog-wrapper-err",
			repo: func() *Repository {
				testKms := &mockGetWrapperer{
					getErr: errors.New(testCtx, errors.Encrypt, "test", "get-oplog-wrapper-err"),
				}

				testRepo, err := NewRepository(testCtx, testRw, testRw, testKms)
				assert.NoError(t, err)
				require.NotNil(t, testRepo)
				return testRepo
			}(),
			scopeId:         org.GetPublicId(),
			in:              mg.GetPublicId(),
			wantErrMatch:    errors.T(errors.Encrypt),
			wantErrContains: "unable to get oplog wrapper",
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
			scopeId:         org.GetPublicId(),
			in:              mg.GetPublicId(),
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
			scopeId:         org.GetPublicId(),
			in:              mg.GetPublicId(),
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "delete-err",
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
			scopeId:         org.GetPublicId(),
			in:              mg.GetPublicId(),
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "unable to generate oplog metadata",
		},
		{
			name:    "With existing managed group id",
			ctx:     testCtx,
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			in:      mg.GetPublicId(),
			want:    1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.repo.DeleteManagedGroup(context.Background(), tc.scopeId, tc.in)
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

func TestRepository_ListManagedGroups(t *testing.T) {
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testRootWrapper := db.TestWrapper(t)

	testCtx := context.Background()
	testKms := kms.TestKms(t, testConn, testRootWrapper)
	iamRepo := iam.TestRepo(t, testConn, testRootWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	orgDbWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	authMethod1 := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId, []string{"ldaps://ldap1"})
	authMethod2 := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId, []string{"ldaps://ldap2"})
	authMethod3 := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId, []string{"ldaps://ldap3"})

	mgs1 := []*ManagedGroup{
		TestManagedGroup(t, testConn, authMethod1, testGrpNames),
		TestManagedGroup(t, testConn, authMethod1, testGrpNames),
		TestManagedGroup(t, testConn, authMethod1, testGrpNames),
	}

	mgs2 := []*ManagedGroup{
		TestManagedGroup(t, testConn, authMethod2, testGrpNames),
		TestManagedGroup(t, testConn, authMethod2, testGrpNames),
		TestManagedGroup(t, testConn, authMethod2, testGrpNames),
	}

	slices.Reverse(mgs1)
	slices.Reverse(mgs2)

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			ManagedGroup{},
			store.ManagedGroup{},
			timestamp.Timestamp{},
			timestamppb.Timestamp{},
		),
	}

	testRepo, err := NewRepository(testCtx, testRw, testRw, testKms)
	assert.NoError(t, err)
	require.NotNil(t, testRepo)

	tests := []struct {
		name            string
		ctx             context.Context
		repo            *Repository
		in              string
		opts            []Option
		want            []*ManagedGroup
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "With no auth method id",
			ctx:             testCtx,
			repo:            testRepo,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method id: parameter violation: error #100",
		},
		{
			name: "With no managed groups",
			ctx:  testCtx,
			repo: testRepo,
			in:   authMethod3.GetPublicId(),
			want: []*ManagedGroup{},
		},
		{
			name: "With first auth method id",
			ctx:  testCtx,
			repo: testRepo,
			in:   authMethod1.GetPublicId(),
			want: mgs1,
		},
		{
			name: "With first auth method id",
			ctx:  testCtx,
			repo: testRepo,
			in:   authMethod2.GetPublicId(),
			want: mgs2,
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
			in:              authMethod1.GetPublicId(),
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "read-err",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, ttime, err := tc.repo.ListManagedGroups(tc.ctx, tc.in, tc.opts...)
			if tc.wantErrMatch != nil {
				require.Error(err)
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
			assert.EqualValues(tc.want, got)
		})
	}
	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing auth method id", func(t *testing.T) {
			t.Parallel()
			_, _, err := testRepo.ListManagedGroups(testCtx, "", WithLimit(testCtx, 1))
			require.ErrorContains(t, err, "missing auth method id")
		})
	})

	t.Run("success-without-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := testRepo.ListManagedGroups(testCtx, authMethod1.PublicId, WithLimit(testCtx, 10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, mgs1, cmpOpts...))
	})
	t.Run("success-with-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := testRepo.ListManagedGroups(testCtx, authMethod1.PublicId, WithStartPageAfterItem(testCtx, mgs1[0]), WithLimit(testCtx, 10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, mgs1[1:], cmpOpts...))
	})
}

func TestRepository_ListManagedGroups_Limits(t *testing.T) {
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testRootWrapper := db.TestWrapper(t)

	testCtx := context.Background()
	testKms := kms.TestKms(t, testConn, testRootWrapper)
	iamRepo := iam.TestRepo(t, testConn, testRootWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	orgDbWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	am := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId, []string{"ldaps://ldap1"})
	mgCount := 10
	for i := 0; i < mgCount; i++ {
		TestManagedGroup(t, testConn, am, testGrpNames)
	}

	tests := []struct {
		name     string
		repoOpts []Option
		listOpts []Option
		wantLen  int
	}{
		{
			name:    "With no limits",
			wantLen: mgCount,
		},
		{
			name:     "With repo limit",
			repoOpts: []Option{WithLimit(testCtx, 3)},
			wantLen:  3,
		},
		{
			name:     "With negative repo limit",
			repoOpts: []Option{WithLimit(testCtx, -1)},
			wantLen:  mgCount,
		},
		{
			name:     "With List limit",
			listOpts: []Option{WithLimit(testCtx, 3)},
			wantLen:  3,
		},
		{
			name:     "With negative List limit",
			listOpts: []Option{WithLimit(testCtx, -1)},
			wantLen:  mgCount,
		},
		{
			name:     "With repo smaller than list limit",
			repoOpts: []Option{WithLimit(testCtx, 2)},
			listOpts: []Option{WithLimit(testCtx, 6)},
			wantLen:  6,
		},
		{
			name:     "With repo larger than list limit",
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
			got, ttime, err := repo.ListManagedGroups(context.Background(), am.GetPublicId(), tc.listOpts...)
			require.NoError(err)
			assert.Len(got, tc.wantLen)
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		})
	}
}

func TestRepository_UpdateManagedGroup(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testRootWrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, testConn, testRootWrapper)
	iamRepo := iam.TestRepo(t, testConn, testRootWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	orgDbWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	am := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId, []string{"ldaps://ldap1"})

	testRepo, err := NewRepository(testCtx, testRw, testRw, testKms)
	assert.NoError(t, err)
	require.NotNil(t, testRepo)

	changeName := func(s string) func(*ManagedGroup) *ManagedGroup {
		return func(mg *ManagedGroup) *ManagedGroup {
			mg.Name = s
			return mg
		}
	}

	changeDescription := func(s string) func(*ManagedGroup) *ManagedGroup {
		return func(mg *ManagedGroup) *ManagedGroup {
			mg.Description = s
			return mg
		}
	}

	changeGrpNames := func(s string) func(*ManagedGroup) *ManagedGroup {
		return func(mg *ManagedGroup) *ManagedGroup {
			mg.GroupNames = s
			return mg
		}
	}

	makeNil := func() func(*ManagedGroup) *ManagedGroup {
		return func(mg *ManagedGroup) *ManagedGroup {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*ManagedGroup) *ManagedGroup {
		return func(mg *ManagedGroup) *ManagedGroup {
			return &ManagedGroup{}
		}
	}

	deletePublicId := func() func(*ManagedGroup) *ManagedGroup {
		return func(mg *ManagedGroup) *ManagedGroup {
			mg.PublicId = ""
			return mg
		}
	}

	nonExistentPublicId := func() func(*ManagedGroup) *ManagedGroup {
		return func(mg *ManagedGroup) *ManagedGroup {
			mg.PublicId = "abcd_OOOOOOOOOO"
			return mg
		}
	}

	combine := func(fns ...func(mg *ManagedGroup) *ManagedGroup) func(*ManagedGroup) *ManagedGroup {
		return func(mg *ManagedGroup) *ManagedGroup {
			for _, fn := range fns {
				mg = fn(mg)
			}
			return mg
		}
	}

	tests := []struct {
		name            string
		repo            *Repository
		scopeId         string
		version         uint32
		orig            *ManagedGroup
		chgFn           func(*ManagedGroup) *ManagedGroup
		masks           []string
		want            *ManagedGroup
		wantCount       int
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:    "nil-ManagedGroup",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{},
			},
			chgFn:           makeNil(),
			masks:           []string{NameField, DescriptionField},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing ManagedGroup: parameter violation: error #100",
		},
		{
			name:    "nil-embedded-ManagedGroup",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{},
			},
			chgFn:           makeEmbeddedNil(),
			masks:           []string{NameField, DescriptionField},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing embedded ManagedGroup: parameter violation: error #100",
		},
		{
			name:    "no-scope-id",
			repo:    testRepo,
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name: "no-scope-id-test-name-repo",
				},
			},
			chgFn:           changeName("no-scope-id-test-update-name-repo"),
			masks:           []string{NameField},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing scope id: parameter violation: error #100",
		},
		{
			name:    "missing-version",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name: "missing-version-test-name-repo",
				},
			},
			chgFn:           changeName("test-update-name-repo"),
			masks:           []string{NameField},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing version: parameter violation: error #100",
		},
		{
			name:    "no-public-id",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{},
			},
			chgFn:           deletePublicId(),
			masks:           []string{NameField, DescriptionField},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing public id: parameter violation: error #100",
		},
		{
			name:    "updating-non-existent-ManagedGroup",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name: "updating-non-existent-ManagedGroup-test-name-repo",
				},
			},
			chgFn:           combine(nonExistentPublicId(), changeName("updating-non-existent-ManagedGroup-test-update-name-repo")),
			masks:           []string{NameField},
			wantErrMatch:    errors.T(errors.RecordNotFound),
			wantErrContains: "record not found, search issue: error #1100",
		},
		{
			name:    "empty-field-mask",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name: "empty-field-mask-test-name-repo",
				},
			},
			chgFn:           changeName("empty-field-mask-test-update-name-repo"),
			wantErrMatch:    errors.T(errors.EmptyFieldMask),
			wantErrContains: "missing field mask: parameter violation: error #104",
		},
		{
			name:    "read-only-fields-in-field-mask",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name: "read-only-fields-in-field-mask-test-name-repo",
				},
			},
			chgFn:           changeName("read-only-fields-in-field-mask-test-update-name-repo"),
			masks:           []string{"PublicId", "CreateTime", "UpdateTime", "AuthMethodId"},
			wantErrMatch:    errors.T(errors.InvalidFieldMask),
			wantErrContains: "PublicId: parameter violation: error #103",
		},
		{
			name:    "unknown-field-in-field-mask",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name: "unknown-field-in-field-mask-test-name-repo",
				},
			},
			chgFn:           changeName("unknown-field-in-field-mask-test-update-name-repo"),
			masks:           []string{"Bilbo"},
			wantErrMatch:    errors.T(errors.InvalidFieldMask),
			wantErrContains: "Bilbo: parameter violation: error #103",
		},
		{
			name:    "change-name",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name: "change-name-test-name-repo",
				},
			},
			chgFn: changeName("change-name-test-update-name-repo"),
			masks: []string{NameField},
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
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
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Description: "test-description-repo",
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{DescriptionField},
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "change-grp-names",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					GroupNames: TestEncodedGrpNames(t, "orig-admin", "orig-users"),
				},
			},
			chgFn: changeGrpNames(TestEncodedGrpNames(t, testGrpNames...)),
			masks: []string{GroupNamesField},
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					GroupNames: TestEncodedGrpNames(t, testGrpNames...),
				},
			},
			wantCount: 1,
		},
		{
			name:    "change-name-and-description",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name:        "change-name-and-description-test-name-repo",
					Description: "test-description-repo",
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("change-name-and-description-test-update-name-repo")),
			masks: []string{NameField, DescriptionField},
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
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
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name:        "delete-name-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{NameField},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
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
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name:        "delete-description-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{DescriptionField},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name: "delete-description-test-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "delete-grp-names",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					GroupNames: TestEncodedGrpNames(t, testGrpNames...),
				},
			},
			masks:           []string{GroupNamesField},
			chgFn:           combine(changeGrpNames("")),
			wantErrMatch:    errors.T(errors.NotNull),
			wantErrContains: "group_names must not be empty: not null constraint violated: integrity violation: error #1001",
		},
		{
			name:    "do-not-delete-name",
			repo:    testRepo,
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name:        "do-not-delete-name-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{DescriptionField},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
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
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name:        "do-not-delete-description-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{NameField},
			chgFn: combine(changeDescription(""), changeName("do-not-delete-description-test-update-name-repo")),
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name:        "do-not-delete-description-test-update-name-repo",
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NotEmpty(tc.repo)

			orig := TestManagedGroup(t, testConn, am, testGrpNames, WithName(testCtx, tc.orig.GetName()), WithDescription(testCtx, tc.orig.GetDescription()))

			tc.orig.AuthMethodId = am.PublicId
			if tc.chgFn != nil {
				orig = tc.chgFn(orig)
			}
			got, gotCount, err := tc.repo.UpdateManagedGroup(testCtx, tc.scopeId, orig, tc.version, tc.masks)
			if tc.wantErrMatch != nil {
				assert.True(errors.Match(tc.wantErrMatch, err), "want err: %q got: %q", tc.wantErrMatch.Code, err)
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
			assertPublicId(t, globals.LdapManagedGroupPrefix, got.PublicId)
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

func TestRepository_ListManagedGroupsRefresh(t *testing.T) {
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testRootWrapper := db.TestWrapper(t)

	ctx := context.Background()
	testKms := kms.TestKms(t, testConn, testRootWrapper)
	iamRepo := iam.TestRepo(t, testConn, testRootWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	orgDbWrapper, err := testKms.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	authMethod1 := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId, []string{"ldaps://ldap1"})
	authMethod2 := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId, []string{"ldaps://ldap2"})

	mgs1 := []*ManagedGroup{
		TestManagedGroup(t, testConn, authMethod1, testGrpNames),
		TestManagedGroup(t, testConn, authMethod1, testGrpNames),
		TestManagedGroup(t, testConn, authMethod1, testGrpNames),
	}

	mgs2 := []*ManagedGroup{
		TestManagedGroup(t, testConn, authMethod2, testGrpNames),
		TestManagedGroup(t, testConn, authMethod2, testGrpNames),
		TestManagedGroup(t, testConn, authMethod2, testGrpNames),
	}

	slices.Reverse(mgs1)
	slices.Reverse(mgs2)

	fiveDaysAgo := time.Now().AddDate(0, 0, -5)

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			ManagedGroup{},
			store.ManagedGroup{},
			timestamp.Timestamp{},
			timestamppb.Timestamp{},
		),
		cmpopts.SortSlices(func(i, j string) bool { return i < j }),
	}

	repo, err := NewRepository(ctx, testRw, testRw, testKms)
	require.NotNil(t, repo)
	assert.NoError(t, err)

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing updated after", func(t *testing.T) {
			t.Parallel()
			_, _, err := repo.ListManagedGroupsRefresh(ctx, authMethod1.PublicId, time.Time{}, WithLimit(ctx, 1))
			require.ErrorContains(t, err, "missing updated after time")
		})
		t.Run("missing auth method id", func(t *testing.T) {
			t.Parallel()
			_, _, err := repo.ListManagedGroupsRefresh(ctx, "", fiveDaysAgo, WithLimit(ctx, 1))
			require.ErrorContains(t, err, "missing auth method id")
		})
	})

	t.Run("success-without-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.ListManagedGroupsRefresh(ctx, authMethod1.PublicId, fiveDaysAgo, WithLimit(ctx, 10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, mgs1, cmpOpts...))
	})
	t.Run("success-with-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.ListManagedGroupsRefresh(ctx, authMethod1.PublicId, fiveDaysAgo, WithStartPageAfterItem(ctx, mgs1[0]), WithLimit(ctx, 10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, mgs1[1:], cmpOpts...))
	})
	t.Run("success-without-after-item-recent-updated-after", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.ListManagedGroupsRefresh(ctx, authMethod1.PublicId, mgs1[len(mgs1)-1].GetUpdateTime().AsTime(), WithLimit(ctx, 10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, mgs1[:len(mgs1)-1], cmpOpts...))
	})
	t.Run("success-with-after-item-recent-updated-after", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.ListManagedGroupsRefresh(ctx, authMethod1.PublicId, mgs1[len(mgs1)-1].GetUpdateTime().AsTime(), WithStartPageAfterItem(ctx, mgs1[0]), WithLimit(ctx, 10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, mgs1[1:len(mgs1)-1], cmpOpts...))
	})
}

func TestRepository_estimatedCountManagedGroups(t *testing.T) {
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
	numItems, err := repo.estimatedManagedGroupCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	// create managed group and check count, expect 1
	authMethod1 := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
	mg := TestManagedGroup(t, conn, authMethod1, testGrpNames)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	numItems, err = repo.estimatedManagedGroupCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, numItems)

	// Delete managed group and check count, expect 0 again
	_, err = repo.DeleteManagedGroup(ctx, org.GetPublicId(), mg.GetPublicId())
	require.NoError(t, err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	numItems, err = repo.estimatedManagedGroupCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)
}

func TestRepository_listDeletedIdsManagedGroups(t *testing.T) {
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
	numItems, err := repo.estimatedManagedGroupCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	// create managed group and check count, expect 1
	authMethod1 := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
	mg := TestManagedGroup(t, conn, authMethod1, testGrpNames)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	deletedIds, ttime, err := repo.listDeletedManagedGroupIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Delete mg and check count, expect 1 entry
	_, err = repo.DeleteManagedGroup(ctx, org.GetPublicId(), mg.GetPublicId())
	require.NoError(t, err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	deletedIds, ttime, err = repo.listDeletedManagedGroupIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	assert.Empty(
		t,
		cmp.Diff(
			[]string{mg.GetPublicId()},
			deletedIds,
			cmpopts.SortSlices(func(i, j string) bool { return i < j }),
		),
	)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = repo.listDeletedManagedGroupIds(ctx, time.Now())
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}
