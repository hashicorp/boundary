// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam_test

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/auth/store"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestRepository_CreateUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := iam.TestRepo(t, conn, wrapper)
	id := testId(t)
	org, _ := iam.TestScopes(t, repo)

	type args struct {
		user *iam.User
		opt  []iam.Option
	}
	tests := []struct {
		name       string
		args       args
		wantDup    bool
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "valid",
			args: args{
				user: func() *iam.User {
					u, err := iam.NewUser(ctx, org.PublicId, iam.WithName("valid"+id), iam.WithDescription(id))
					assert.NoError(t, err)
					return u
				}(),
			},
			wantErr: false,
		},
		{
			name: "bad-scope-id",
			args: args{
				user: func() *iam.User {
					u, err := iam.NewUser(ctx, id)
					assert.NoError(t, err)
					return u
				}(),
			},
			wantErr:    true,
			wantErrMsg: "iam.(Repository).create: error getting metadata: iam.(Repository).stdMetadata: unable to get scope: iam.LookupScope: db.LookupWhere: record not found",
		},
		{
			name: "dup-name",
			args: args{
				user: func() *iam.User {
					u, err := iam.NewUser(ctx, org.PublicId, iam.WithName("dup-name"+id))
					assert.NoError(t, err)
					return u
				}(),
			},
			wantDup:    true,
			wantErr:    true,
			wantErrMsg: "iam.(Repository).CreateUser: user %s already exists in org %s: integrity violation: error #1002",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tt.wantDup {
				dup, err := repo.CreateUser(ctx, tt.args.user, tt.args.opt...)
				require.NoError(err)
				require.NotNil(dup)
			}
			u, err := repo.CreateUser(ctx, tt.args.user, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(u)
				switch tt.name {
				case "dup-name":
					assert.Contains(err.Error(), fmt.Sprintf(tt.wantErrMsg, "dup-name"+id, org.PublicId))
				default:
					assert.Contains(err.Error(), tt.wantErrMsg)
				}
				return
			}
			require.NoError(err)
			assert.NotNil(u.CreateTime)
			assert.NotNil(u.UpdateTime)

			foundUser, _, err := repo.LookupUser(ctx, u.PublicId)
			require.NoError(err)
			assert.True(proto.Equal(foundUser, u))

			err = db.TestVerifyOplog(t, rw, u.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

// TestRepository_LookupUser_WithDifferentPrimaryAuthMethods ensures that the
// when different auth method types are primary, the correct primary account
// info is returned from Repository.LookupUser(...)
func TestRepository_LookupUser_WithDifferentPrimaryAuthMethods(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	repo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, repo)
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	var accountIds []string
	oidcAm := oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.ActivePrivateState, "alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "http://localhost")[0]))
	aa := oidc.TestAccount(t, conn, oidcAm, "alice", oidc.WithFullName("alice eve smith"), oidc.WithEmail("alice@example.com"))
	accountIds = append(accountIds, aa.PublicId)

	pwAms := password.TestAuthMethods(t, conn, org.PublicId, 1)
	require.Equal(t, 1, len(pwAms))
	pwAcct := password.TestAccount(t, conn, pwAms[0].PublicId, "want-login-name")
	accountIds = append(accountIds, pwAcct.PublicId)

	u := iam.TestUser(t, repo, org.PublicId)
	newAccts, err := repo.AddUserAccounts(ctx, u.PublicId, u.Version, accountIds)
	require.NoError(t, err)
	sort.Strings(newAccts)
	require.Equal(t, accountIds, newAccts)

	tests := []struct {
		name                string
		primaryAuthMethodId string
		wantLoginName       string
		wantPrimaryAcctId   string
		wantFullName        string
		wantEmail           string
	}{
		{
			name:                "oidc",
			primaryAuthMethodId: oidcAm.PublicId,
			wantLoginName:       "alice",
			wantPrimaryAcctId:   aa.PublicId,
			wantFullName:        "alice eve smith",
			wantEmail:           "alice@example.com",
		},
		{
			name:                "password",
			primaryAuthMethodId: pwAms[0].PublicId,
			wantLoginName:       "want-login-name",
			wantPrimaryAcctId:   pwAcct.PublicId,
			wantFullName:        "",
			wantEmail:           "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := repo.LookupScope(context.Background(), org.PublicId)
			require.NoError(err)
			iam.TestSetPrimaryAuthMethod(t, repo, s, tt.primaryAuthMethodId)

			got, gotAccts, err := repo.LookupUser(ctx, u.PublicId)
			require.NoError(err)

			sort.Strings(gotAccts)
			assert.Equal(accountIds, gotAccts)

			assert.Equal(tt.wantLoginName, got.LoginName)
			assert.Equal(tt.wantPrimaryAcctId, got.PrimaryAccountId)
			assert.Equal(tt.wantFullName, got.FullName)
			assert.Equal(tt.wantEmail, got.Email)
		})
	}
}

func TestRepository_UpdateUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	repo := iam.TestRepo(t, conn, wrapper)
	id := testId(t)
	org, proj := iam.TestScopes(t, repo)
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	pubId := func(s string) *string { return &s }

	type args struct {
		name           string
		description    string
		fieldMaskPaths []string
		opt            []iam.Option
		ScopeId        string
		PublicId       *string
	}
	tests := []struct {
		name           string
		newUserOpts    []iam.Option
		args           args
		wantRowsUpdate int
		wantErr        bool
		wantErrMsg     string
		wantIsErr      errors.Code
		wantDup        bool
	}{
		{
			name: "valid",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "valid-no-op",
			args: args{
				name:           "valid-no-op" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
			},
			newUserOpts:    []iam.Option{iam.WithName("valid-no-op" + id)},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "not-found",
			args: args{
				name:           "not-found" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
				PublicId:       func() *string { s := "1"; return &s }(),
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "iam.(Repository).UpdateUser: db.Update: record not found, search issue: error #1100",
			wantIsErr:      errors.RecordNotFound,
		},
		{
			name: "null-name",
			args: args{
				name:           "",
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
			},
			newUserOpts:    []iam.Option{iam.WithName("null-name" + id)},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "null-description",
			args: args{
				name:           "",
				fieldMaskPaths: []string{"Description"},
				ScopeId:        org.PublicId,
			},
			newUserOpts:    []iam.Option{iam.WithDescription("null-description" + id)},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "empty-field-mask",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{},
				ScopeId:        org.PublicId,
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "iam.(Repository).UpdateUser: empty field mask, parameter violation: error #104",
		},
		{
			name: "nil-fieldmask",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: nil,
				ScopeId:        org.PublicId,
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "iam.(Repository).UpdateUser: empty field mask, parameter violation: error #104",
		},
		{
			name: "read-only-fields",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"CreateTime"},
				ScopeId:        org.PublicId,
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "iam.(Repository).UpdateUser: invalid field mask: CreateTime: parameter violation: error #103",
		},
		{
			name: "unknown-fields",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"Alice"},
				ScopeId:        org.PublicId,
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "iam.(Repository).UpdateUser: invalid field mask: Alice: parameter violation: error #103",
		},
		{
			name: "no-public-id",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
				PublicId:       pubId(""),
			},
			wantErr:        true,
			wantErrMsg:     "iam.(Repository).UpdateUser: missing public id: parameter violation: error #100",
			wantRowsUpdate: 0,
		},
		{
			name: "proj-scope-id",
			args: args{
				name:           "proj-scope-id" + id,
				fieldMaskPaths: []string{"ScopeId"},
				ScopeId:        proj.PublicId,
			},
			wantErr:    true,
			wantErrMsg: "iam.(Repository).UpdateUser: invalid field mask: ScopeId: parameter violation: error #103",
		},
		{
			name: "empty-scope-id-with-name-mask",
			args: args{
				name:           "empty-scope-id" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        "",
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "dup-name",
			args: args{
				name:           "dup-name" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
			},
			wantErr:    true,
			wantDup:    true,
			wantErrMsg: `iam.(Repository).UpdateUser: user %s already exists in org %s: integrity violation: error #1002`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			// we need to clean out any auth methods
			_, err = rw.Exec(context.Background(), "delete from auth_method", nil)
			require.NoError(err)

			if tt.wantDup {
				u := iam.TestUser(t, repo, org.PublicId, tt.newUserOpts...)
				u.Name = tt.args.name
				_, _, _, err := repo.UpdateUser(context.Background(), u, 1, tt.args.fieldMaskPaths, tt.args.opt...)
				require.NoError(err)
			}

			u := iam.TestUser(t, repo, org.PublicId, tt.newUserOpts...)
			acctCount := 10
			accountIds := make([]string, 0, acctCount)
			var wantEmail, wantFullName, wantPrimaryAccountId string
			var authMethod *oidc.AuthMethod
			for i := 0; i < acctCount; i++ {
				switch i % 2 {
				case 0:
					authMethod = oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.ActivePrivateState, fmt.Sprintf("alice-rp-%d", i), "fido",
						oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice.com")[0]),
						oidc.WithSigningAlgs(oidc.RS256),
						oidc.WithApiUrl(oidc.TestConvertToUrls(t, "http://localhost")[0]))
					wantEmail, wantFullName = fmt.Sprintf("%s-%d@example.com", tt.name, i), fmt.Sprintf("%s-%d", tt.name, i)
					aa := oidc.TestAccount(t, conn, authMethod, fmt.Sprintf(tt.name, i), oidc.WithFullName(wantFullName), oidc.WithEmail(wantEmail))
					wantPrimaryAccountId = aa.PublicId
					accountIds = append(accountIds, aa.PublicId)
				default:
					pwAms := password.TestAuthMethods(t, conn, org.PublicId, 1)
					require.Equal(1, len(pwAms))
					pwAcct := password.TestAccount(t, conn, pwAms[0].PublicId, "name1")
					accountIds = append(accountIds, pwAcct.PublicId)
				}
			}
			require.Equal(acctCount, len(accountIds))
			var s *iam.Scope
			s, err = repo.LookupScope(context.Background(), org.PublicId)
			require.NoError(err)
			// we need a primary auth method, so let's just pick the last oidc
			// one created.
			iam.TestSetPrimaryAuthMethod(t, repo, s, authMethod.PublicId)

			sort.Strings(accountIds)
			if len(accountIds) > 0 {
				newAccts, err := repo.AddUserAccounts(context.Background(), u.PublicId, u.Version, accountIds)
				require.NoError(err)
				sort.Strings(newAccts)
				require.Equal(accountIds, newAccts)
				u.Version++
			}
			// we need to clean out any oplog entries added because we
			// associated accounts to the test user
			_, err = rw.Exec(context.Background(), "delete from oplog_entry", nil)
			require.NoError(err)

			updateUser := iam.AllocUser()
			updateUser.PublicId = u.PublicId
			if tt.args.PublicId != nil {
				updateUser.PublicId = *tt.args.PublicId
			}
			updateUser.ScopeId = tt.args.ScopeId
			updateUser.Name = tt.args.name
			updateUser.Description = tt.args.description

			var userAfterUpdate *iam.User
			var acctIdsAfterUpdate []string
			var updatedRows int
			var err error
			userAfterUpdate, acctIdsAfterUpdate, updatedRows, err = repo.UpdateUser(context.Background(), &updateUser, u.Version, tt.args.fieldMaskPaths, tt.args.opt...)

			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				assert.Nil(userAfterUpdate)
				assert.Equal(0, updatedRows)
				switch tt.name {
				case "dup-name":
					assert.Equal(fmt.Sprintf(tt.wantErrMsg, "dup-name"+id, org.PublicId), err.Error())
				default:
					assert.Containsf(err.Error(), tt.wantErrMsg, "unexpected error: %s", err.Error())
				}
				err = db.TestVerifyOplog(t, rw, u.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(1*time.Second))
				require.Error(err)
				assert.Contains(err.Error(), "record not found")
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			assert.NotEqual(u.UpdateTime, userAfterUpdate.UpdateTime)
			sort.Strings(acctIdsAfterUpdate)
			assert.Equal(accountIds, acctIdsAfterUpdate)
			assert.Equal(wantFullName, userAfterUpdate.FullName)
			assert.Equal(wantEmail, userAfterUpdate.Email)
			assert.Equal(wantPrimaryAccountId, userAfterUpdate.PrimaryAccountId)

			foundUser, foundAccountIds, err := repo.LookupUser(context.Background(), u.PublicId)
			require.NoError(err)
			assert.True(proto.Equal(userAfterUpdate, foundUser))
			sort.Strings(foundAccountIds)
			assert.Equal(accountIds, foundAccountIds)
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
			if tt.args.name == "" {
				dbassert.IsNull(foundUser, "name")
			}
			if tt.args.description == "" {
				dbassert.IsNull(foundUser, "description")
			}

			err = db.TestVerifyOplog(t, rw, u.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_DeleteUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, repo)

	type args struct {
		user *iam.User
		opt  []iam.Option
	}
	tests := []struct {
		name            string
		args            args
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name: "valid",
			args: args{
				user: iam.TestUser(t, repo, org.PublicId),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-public-id",
			args: args{
				user: func() *iam.User {
					u := iam.AllocUser()
					return &u
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "iam.(Repository).DeleteUser: missing public id: parameter violation: error #100",
		},
		{
			name: "not-found",
			args: args{
				user: func() *iam.User {
					u, err := iam.NewUser(ctx, org.PublicId)
					require.NoError(t, err)
					id, err := db.NewPublicId(ctx, globals.UserPrefix)
					require.NoError(t, err)
					u.PublicId = id
					return u
				}(),
			},
			wantRowsDeleted: 1,
			wantErr:         true,
			wantErrMsg:      "db.LookupById: record not found, search issue: error #1100",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deletedRows, err := repo.DeleteUser(ctx, tt.args.user.PublicId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, deletedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, tt.args.user.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				require.Error(err)
				assert.Contains(err.Error(), "record not found")
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundUser, _, err := repo.LookupUser(ctx, tt.args.user.PublicId)
			require.NoError(err)
			assert.Nil(foundUser)

			err = db.TestVerifyOplog(t, rw, tt.args.user.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			require.NoError(err)
		})
	}
}

func TestRepository_ListUsers(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	const testLimit = 10
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	repo := iam.TestRepo(t, conn, wrapper, iam.WithLimit(testLimit))
	org, _ := iam.TestScopes(t, repo)
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	authMethod := oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.ActivePrivateState, "alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "http://localhost")[0]))

	iam.TestSetPrimaryAuthMethod(t, repo, org, authMethod.PublicId)

	type args struct {
		withOrgId string
		opt       []iam.Option
	}
	tests := []struct {
		name      string
		createCnt int
		args      args
		wantCnt   int
		wantErr   bool
	}{
		{
			name:      "negative-limit",
			createCnt: testLimit + 1,
			args: args{
				withOrgId: org.PublicId,
				opt:       []iam.Option{iam.WithLimit(-1)},
			},
			wantErr: true,
		},
		{
			name:      "default-limit",
			createCnt: testLimit + 1,
			args: args{
				withOrgId: org.PublicId,
			},
			wantCnt: testLimit,
			wantErr: false,
		},
		{
			name:      "custom-limit",
			createCnt: testLimit + 1,
			args: args{
				withOrgId: org.PublicId,
				opt:       []iam.Option{iam.WithLimit(3)},
			},
			wantCnt: 3,
			wantErr: false,
		},
		{
			name:      "bad-org",
			createCnt: 1,
			args: args{
				withOrgId: "bad-id",
			},
			wantCnt: 0,
			wantErr: false,
		},
	}
	type userInfo struct {
		email         string
		fullName      string
		primaryAcctId string
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, func() any { u := iam.AllocUser(); return &u }(), "public_id != 'u_anon' and public_id != 'u_auth' and public_id != 'u_recovery'")
			testUsers := []*iam.User{}
			wantUserInfo := map[string]userInfo{}
			for i := 0; i < tt.createCnt; i++ {
				u := iam.TestUser(t, repo, org.PublicId)
				testUsers = append(testUsers, u)
				wantEmail, wantFullName := fmt.Sprintf("%s-%d@example.com", tt.name, i), fmt.Sprintf("%s-%d", tt.name, i)
				a := oidc.TestAccount(t, conn, authMethod, fmt.Sprintf(tt.name, i), oidc.WithFullName(wantFullName), oidc.WithEmail(wantEmail))
				wantUserInfo[u.PublicId] = userInfo{email: wantEmail, fullName: wantFullName, primaryAcctId: a.PublicId}
				_, err := repo.AddUserAccounts(context.Background(), u.PublicId, u.Version, []string{a.PublicId})
				require.NoError(err)

				pwAms := password.TestAuthMethods(t, conn, org.PublicId, 1)
				require.Equal(1, len(pwAms))
				pwAcct := password.TestAccount(t, conn, pwAms[0].PublicId, "name1")
				_, err = repo.AddUserAccounts(context.Background(), u.PublicId, u.Version+1, []string{pwAcct.PublicId})
				require.NoError(err)

			}
			assert.Equal(tt.createCnt, len(testUsers))
			got, _, err := repo.ListUsers(context.Background(), []string{tt.args.withOrgId}, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
			for _, u := range got {
				assert.Equal(wantUserInfo[u.PublicId], userInfo{
					email:         u.Email,
					fullName:      u.FullName,
					primaryAcctId: u.PrimaryAccountId,
				})
			}
		})
	}
}

func TestRepository_ListUsers_Multiple_Scopes(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, repo)

	t.Cleanup(func() {
		db.TestDeleteWhere(t, conn, func() any { i := iam.AllocUser(); return &i }(), "public_id != 'u_anon' and public_id != 'u_auth' and public_id != 'u_recovery'")
	})

	const numPerScope = 10
	total := 3 // anon, auth, recovery
	for i := 0; i < numPerScope; i++ {
		iam.TestUser(t, repo, "global")
		total++
		iam.TestUser(t, repo, org.GetPublicId())
		total++
	}

	got, ttime, err := repo.ListUsers(context.Background(), []string{"global", org.GetPublicId()})
	require.NoError(t, err)
	assert.Equal(t, total, len(got))
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func TestRepository_LookupUserWithLogin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	repo := iam.TestRepo(t, conn, wrapper)

	id := testId(t)
	org, _ := iam.TestScopes(t, repo)
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	authMethod := oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.ActivePrivateState, "alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "http://localhost")[0]))

	iam.TestSetPrimaryAuthMethod(t, repo, org, authMethod.PublicId)

	// an account with no assoc user to test auto-vivify for the primary auth method.
	newAuthAcct := oidc.TestAccount(t, conn, authMethod, "acct-1", oidc.WithFullName("acct-1"), oidc.WithEmail("acct-1@example.com"))

	// a 2nd auth method which will NOT be the primary auth method
	authMethod2 := oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.ActivePrivateState, "alice-rp-2", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "http://localhost")[0]))

	// an account with no assoc user to test non-primary auth methods do not auto-vivify
	newAuthAcctWithoutVivify := oidc.TestAccount(t, conn, authMethod2, "acct-2", oidc.WithFullName("acct-2"), oidc.WithEmail("acct-2@example.com"))

	user := iam.TestUser(t, repo, org.PublicId, iam.WithName("existing-"+id))
	existingUserWithAcctWithVivify := oidc.TestAccount(t, conn, authMethod, "acct-3", oidc.WithFullName("acct-3"), oidc.WithEmail("acct-3@example.com"))
	added, err := repo.AddUserAccounts(context.Background(), user.PublicId, user.Version, []string{existingUserWithAcctWithVivify.PublicId})
	require.NoError(t, err)
	require.Equal(t, 1, len(added))
	foundAcct := allocAuthAccount()
	foundAcct.PublicId = existingUserWithAcctWithVivify.PublicId
	require.NoError(t, rw.LookupById(context.Background(), &foundAcct))
	require.Equal(t, user.PublicId, foundAcct.IamUserId)

	// we need to set these primary acct values on the user, so the test
	// comparisons will work properly.
	user.LoginName = "acct-3"
	user.FullName = "acct-3"
	user.Email = "acct-3@example.com"

	existingUserWithAcctNoVivify := oidc.TestAccount(t, conn, authMethod2, "acct-4", oidc.WithFullName("acct-4"), oidc.WithEmail("acct-4@example.com"))
	user, _, err = repo.LookupUser(context.Background(), user.PublicId)
	require.NoError(t, err)
	added, err = repo.AddUserAccounts(context.Background(), user.PublicId, user.Version, []string{existingUserWithAcctNoVivify.PublicId})
	require.NoError(t, err)
	require.Equal(t, 2, len(added))
	foundAcct.PublicId = existingUserWithAcctNoVivify.PublicId
	require.NoError(t, rw.LookupById(context.Background(), &foundAcct, db.WithWhere("iam_user_id = ?", user.PublicId)))
	require.Equal(t, user.PublicId, foundAcct.IamUserId)

	type args struct {
		withAccountId string
		opt           []iam.Option
	}
	tests := []struct {
		name            string
		args            args
		wantName        string
		wantDescription string
		wantErr         bool
		wantErrIs       errors.Code
		wantUser        *iam.User
	}{
		{
			name: "valid",
			args: args{
				withAccountId: newAuthAcct.PublicId,
				opt: []iam.Option{
					iam.WithName("valid-" + id),
					iam.WithDescription("valid-" + id),
				},
			},
			wantName:        "valid-" + id,
			wantDescription: "valid-" + id,
			wantErr:         false,
		},
		{
			name: "new-acct-without-vivify",
			args: args{
				withAccountId: newAuthAcctWithoutVivify.PublicId,
			},
			wantErr:   true,
			wantErrIs: errors.RecordNotFound,
		},
		{
			name: "missing auth acct id",
			args: args{
				withAccountId: "",
			},
			wantErr:   true,
			wantErrIs: errors.InvalidParameter,
		},
		{
			name: "existing-user-with-account-with-vivify",
			args: args{
				withAccountId: existingUserWithAcctWithVivify.PublicId,
			},
			wantErr:  false,
			wantName: "existing-" + id,
			wantUser: user,
		},
		{
			name: "existing-user-with-account-no-vivify",
			args: args{
				withAccountId: existingUserWithAcctNoVivify.PublicId,
				opt:           []iam.Option{},
			},
			wantErr:  false,
			wantName: "existing-" + id,
			wantUser: user,
		},
		{
			name: "bad-auth-account-id",
			args: args{
				withAccountId: id,
			},
			wantErr:   true,
			wantErrIs: errors.RecordNotFound,
		},
		{
			name: "bad-auth-account-id-with-vivify",
			args: args{
				withAccountId: id,
				opt:           []iam.Option{},
			},
			wantErr:   true,
			wantErrIs: errors.RecordNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
			got, err := repo.LookupUserWithLogin(context.Background(), tt.args.withAccountId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(got)
				assert.Truef(errors.Match(errors.T(tt.wantErrIs), err), "unexpected error %s", err.Error())
				if tt.args.withAccountId != "" && tt.args.withAccountId != id {
					// need to assert that userid in auth_account is still null
					acct := allocAuthAccount()
					acct.PublicId = tt.args.withAccountId
					dbassert.IsNull(&acct, "IamUserId")
				}
				return
			}
			require.NoError(err)
			if tt.wantName != "" {
				assert.Equal(tt.wantName, got.Name)
			}
			if tt.wantDescription != "" {
				assert.Equal(tt.wantDescription, got.Description)
			}
			require.NotEmpty(got.PublicId)
			if tt.wantUser != nil {
				tt.wantUser.Version = got.User.Version
				tt.wantUser.CreateTime = got.User.CreateTime
				tt.wantUser.UpdateTime = got.User.UpdateTime
				assert.Empty(cmp.Diff(got.User, tt.wantUser.User, protocmp.Transform()), "got %q, wanted %q", got.User, tt.wantUser.User)
			}
			acct := allocAuthAccount()
			acct.PublicId = tt.args.withAccountId
			err = rw.LookupByPublicId(context.Background(), &acct)
			require.NoError(err)
			assert.Equal(got.PublicId, acct.IamUserId)
		})
	}
}

func TestRepository_AssociateAccounts(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	repo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, repo)
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	user := iam.TestUser(t, repo, org.PublicId)

	createAccountsFn := func(prefix string) []string {
		db.TestDeleteWhere(t, conn, func() any { i := allocAuthAccount(); return &i }(), "iam_user_id = ?", user.PublicId)
		results := []string{}
		for i := 0; i < 5; i++ {
			authMethod := oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.ActivePrivateState, fmt.Sprintf("%s-alice-rp-%d", prefix, i), "fido",
				oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice.com")[0]),
				oidc.WithSigningAlgs(oidc.RS256),
				oidc.WithApiUrl(oidc.TestConvertToUrls(t, "http://localhost")[0]))

			a := oidc.TestAccount(t, conn, authMethod, fmt.Sprintf("acct-%d", i))
			results = append(results, a.PublicId)
		}
		return results
	}
	type args struct {
		accountIdsFn        func() []string
		userId              string
		userVersionOverride *uint32
		opt                 []iam.Option
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name: "valid",
			args: args{
				userId:       user.PublicId,
				accountIdsFn: func() []string { return createAccountsFn("valid") },
			},
			wantErr: false,
		},
		{
			name: "already-associated",
			args: args{
				userId: user.PublicId,
				accountIdsFn: func() []string {
					ids := createAccountsFn("already-associated")
					authMethod := oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.ActivePrivateState, "already-associated-alice-rp", "fido",
						oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice.com")[0]),
						oidc.WithSigningAlgs(oidc.RS256),
						oidc.WithApiUrl(oidc.TestConvertToUrls(t, "http://localhost")[0]))
					a := oidc.TestAccount(t, conn, authMethod, "already-associated")
					user, _, err := repo.LookupUser(context.Background(), user.PublicId)
					require.NoError(t, err)
					added, err := repo.AddUserAccounts(context.Background(), user.PublicId, user.Version, []string{a.PublicId})
					require.NoError(t, err)
					require.Contains(t, added, a.PublicId)
					ids = append(ids, a.PublicId)
					return ids
				},
			},
			wantErr: false,
		},
		{
			name: "associated-with-diff-user",
			args: args{
				userId: user.PublicId,
				accountIdsFn: func() []string {
					ids := createAccountsFn("associated-with-diff-user")
					authMethod := oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.ActivePrivateState, "associated-with-diff-user-alice-rp", "fido",
						oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice.com")[0]),
						oidc.WithSigningAlgs(oidc.RS256),
						oidc.WithApiUrl(oidc.TestConvertToUrls(t, "http://localhost")[0]))
					u := iam.TestUser(t, repo, org.PublicId)
					a := oidc.TestAccount(t, conn, authMethod, "already-associated")
					added, err := repo.AddUserAccounts(context.Background(), u.PublicId, u.Version, []string{a.PublicId})
					require.NoError(t, err)
					require.Contains(t, added, a.PublicId)
					ids = append(ids, a.PublicId)
					return ids
				},
			},
			wantErr:     true,
			wantErrCode: errors.AccountAlreadyAssociated,
		},
		{
			name: "bad-version",
			args: args{
				userVersionOverride: func() *uint32 {
					i := uint32(22)
					return &i
				}(),
				userId:       user.PublicId,
				accountIdsFn: func() []string { return createAccountsFn("bad-version") },
			},
			wantErr:     true,
			wantErrCode: errors.MultipleRecords,
		},
		{
			name: "zero-version",
			args: args{
				userVersionOverride: func() *uint32 {
					i := uint32(0)
					return &i
				}(),
				userId:       user.PublicId,
				accountIdsFn: func() []string { return createAccountsFn("zero-version") },
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "no-accounts",
			args: args{
				userId:       user.PublicId,
				accountIdsFn: func() []string { return nil },
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			accountIds := tt.args.accountIdsFn()
			sort.Strings(accountIds)

			origUser, _, err := repo.LookupUser(context.Background(), user.PublicId)
			require.NoError(err)

			version := origUser.Version
			if tt.args.userVersionOverride != nil {
				version = *tt.args.userVersionOverride
			}

			got, err := repo.AddUserAccounts(context.Background(), tt.args.userId, version, accountIds, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "unexpected error %s", err)
				return
			}
			require.NoError(err)
			err = db.TestVerifyOplog(t, rw, tt.args.userId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
			for _, id := range got {
				err = db.TestVerifyOplog(t, rw, id, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				assert.NoError(err)
			}

			sort.Strings(got)
			assert.Equal(accountIds, got)

			foundIds, err := repo.ListUserAccounts(context.Background(), tt.args.userId)
			require.NoError(err)
			sort.Strings(foundIds)
			assert.Equal(accountIds, foundIds)

			u, _, err := repo.LookupUser(context.Background(), tt.args.userId)
			require.NoError(err)
			assert.Equal(version+1, u.Version)
		})
	}
}

func TestRepository_DisassociateAccounts(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	repo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, repo)
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	user := iam.TestUser(t, repo, org.PublicId)

	createAccountsFn := func(prefix string) []string {
		db.TestDeleteWhere(t, conn, func() any { a := allocAuthAccount(); return &a }(), "iam_user_id = ?", user.PublicId)
		results := []string{}
		for i := 0; i < 1; i++ {
			authMethod := oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.ActivePrivateState, fmt.Sprintf("%s-alice-rp-%d", prefix, i), "fido",
				oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice.com")[0]),
				oidc.WithSigningAlgs(oidc.RS256),
				oidc.WithApiUrl(oidc.TestConvertToUrls(t, "http://localhost")[0]))
			a := oidc.TestAccount(t, conn, authMethod, fmt.Sprintf("acct-%d", i))
			user, _, err := repo.LookupUser(context.Background(), user.PublicId)
			require.NoError(t, err)
			added, err := repo.AddUserAccounts(context.Background(), user.PublicId, user.Version, []string{a.PublicId})
			require.NoError(t, err)
			require.Contains(t, added, a.PublicId)
			results = append(results, a.PublicId)
		}
		return results
	}
	type args struct {
		accountIdsFn        func() []string
		userId              string
		userVersionOverride *uint32
		opt                 []iam.Option
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name: "valid",
			args: args{
				userId:       user.PublicId,
				accountIdsFn: func() []string { return createAccountsFn("valid") },
			},
			wantErr: false,
		},
		{
			name: "associated-with-diff-user",
			args: args{
				userId: user.PublicId,
				accountIdsFn: func() []string {
					ids := createAccountsFn("associated-with-diff-user")
					authMethod := oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.ActivePrivateState, "associated-with-diff-user-alice-rp", "fido",
						oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice.com")[0]),
						oidc.WithSigningAlgs(oidc.RS256),
						oidc.WithApiUrl(oidc.TestConvertToUrls(t, "http://localhost")[0]))
					u := iam.TestUser(t, repo, org.PublicId)
					a := oidc.TestAccount(t, conn, authMethod, "already-associated")
					added, err := repo.AddUserAccounts(context.Background(), u.PublicId, u.Version, []string{a.PublicId})
					require.NoError(t, err)
					require.Contains(t, added, a.PublicId)
					ids = append(ids, a.PublicId)
					return ids
				},
			},
			wantErr:     true,
			wantErrCode: errors.AccountAlreadyAssociated,
		},
		{
			name: "bad-version",
			args: args{
				userVersionOverride: func() *uint32 {
					i := uint32(22)
					return &i
				}(),
				userId:       user.PublicId,
				accountIdsFn: func() []string { return createAccountsFn("bad-version") },
			},
			wantErr:     true,
			wantErrCode: errors.MultipleRecords,
		},
		{
			name: "zero-version",
			args: args{
				userVersionOverride: func() *uint32 {
					i := uint32(0)
					return &i
				}(),
				userId:       user.PublicId,
				accountIdsFn: func() []string { return createAccountsFn("zero-version") },
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "no-accounts",
			args: args{
				userId:       user.PublicId,
				accountIdsFn: func() []string { return nil },
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			accountIds := tt.args.accountIdsFn()

			origUser, _, err := repo.LookupUser(context.Background(), user.PublicId)
			require.NoError(err)

			version := origUser.Version
			if tt.args.userVersionOverride != nil {
				version = *tt.args.userVersionOverride
			}

			got, err := repo.DeleteUserAccounts(context.Background(), tt.args.userId, version, accountIds, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "unexpected error %s", err)
				return
			}
			require.NoError(err)
			err = db.TestVerifyOplog(t, rw, tt.args.userId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
			for _, id := range got {
				err = db.TestVerifyOplog(t, rw, id, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				assert.NoError(err)
			}
			foundIds, err := repo.ListUserAccounts(context.Background(), tt.args.userId)
			require.NoError(err)
			for _, id := range accountIds {
				assert.True(!strutil.StrListContains(foundIds, id))
			}

			u, _, err := repo.LookupUser(context.Background(), tt.args.userId)
			require.NoError(err)
			assert.Equal(version+1, u.Version)
		})
	}
}

func TestRepository_SetAssociatedAccounts(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	repo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, repo)
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	user := iam.TestUser(t, repo, org.PublicId)

	createAccountsFn := func(prefix string) []string {
		db.TestDeleteWhere(t, conn, func() any { i := allocAuthAccount(); return &i }(), "iam_user_id = ?", user.PublicId)
		results := []string{}
		for i := 0; i < 1; i++ {
			authMethod := oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.ActivePrivateState, fmt.Sprintf("%s-alice-rp-%d", prefix, i), "fido",
				oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice.com")[0]),
				oidc.WithSigningAlgs(oidc.RS256),
				oidc.WithApiUrl(oidc.TestConvertToUrls(t, "http://localhost")[0]))
			a := oidc.TestAccount(t, conn, authMethod, fmt.Sprintf("acct-%d", i))
			results = append(results, a.PublicId)
		}
		return results
	}
	type args struct {
		accountIdsFn        func() ([]string, []string)
		userId              string
		userVersionOverride *uint32
		opt                 []iam.Option
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name: "valid",
			args: args{
				userId: user.PublicId,
				accountIdsFn: func() ([]string, []string) {
					ids := createAccountsFn("valid")
					return ids, ids
				},
			},
			wantErr: false,
		},
		{
			name: "one-already-associated",
			args: args{
				userId: user.PublicId,
				accountIdsFn: func() ([]string, []string) {
					ids := createAccountsFn("one-already-associated")
					changes := append([]string{}, ids...)
					authMethod := oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.ActivePrivateState, "one-already-associated-alice-rp", "fido",
						oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice.com")[0]),
						oidc.WithSigningAlgs(oidc.RS256),
						oidc.WithApiUrl(oidc.TestConvertToUrls(t, "http://localhost")[0]))
					a := oidc.TestAccount(t, conn, authMethod, "acct-one-already-associated")
					user, _, err := repo.LookupUser(context.Background(), user.PublicId)
					require.NoError(t, err)
					added, err := repo.AddUserAccounts(context.Background(), user.PublicId, user.Version, []string{a.PublicId})
					require.NoError(t, err)
					require.Contains(t, added, a.PublicId)
					ids = append(ids, a.PublicId)
					return ids, changes
				},
			},
			wantErr: false,
		},
		{
			name: "no-change",
			args: args{
				userId: user.PublicId,
				accountIdsFn: func() ([]string, []string) {
					ids := createAccountsFn("no-change")
					user, _, err := repo.LookupUser(context.Background(), user.PublicId)
					require.NoError(t, err)
					added, err := repo.AddUserAccounts(context.Background(), user.PublicId, user.Version, ids)
					require.NoError(t, err)
					require.Equal(t, len(ids), len(added))

					// ids := []string{}
					// for i := 0; i < 10; i++ {
					// 	a := testAccount(t, conn, org.PublicId, authMethodId, user.PublicId)
					// 	ids = append(ids, a.PublicId)
					// }
					return ids, nil
				},
			},
			wantErr: false,
		},
		{
			name: "remove-all",
			args: args{
				userId: user.PublicId,
				accountIdsFn: func() ([]string, []string) {
					ids := createAccountsFn("remove-all")
					user, _, err := repo.LookupUser(context.Background(), user.PublicId)
					require.NoError(t, err)
					added, err := repo.AddUserAccounts(context.Background(), user.PublicId, user.Version, ids)
					require.NoError(t, err)
					require.Equal(t, len(ids), len(added))
					return nil, ids
				},
			},
			wantErr: false,
		},
		{
			name: "associated-with-diff-user",
			args: args{
				userId: user.PublicId,
				accountIdsFn: func() ([]string, []string) {
					ids := createAccountsFn("associated-with-diff-user")
					authMethod := oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.ActivePrivateState, "associated-with-diff-user-alice-rp", "fido",
						oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice.com")[0]),
						oidc.WithSigningAlgs(oidc.RS256),
						oidc.WithApiUrl(oidc.TestConvertToUrls(t, "http://localhost")[0]))
					u := iam.TestUser(t, repo, org.PublicId)
					a := oidc.TestAccount(t, conn, authMethod, "already-associated")
					added, err := repo.AddUserAccounts(context.Background(), u.PublicId, u.Version, []string{a.PublicId})
					require.NoError(t, err)
					require.Contains(t, added, a.PublicId)
					ids = append(ids, a.PublicId)
					return ids, ids
				},
			},
			wantErr:     true,
			wantErrCode: errors.AccountAlreadyAssociated,
		},
		{
			name: "bad-version",
			args: args{
				userVersionOverride: func() *uint32 {
					i := uint32(22)
					return &i
				}(),
				userId: user.PublicId,
				accountIdsFn: func() ([]string, []string) {
					ids := createAccountsFn("bad-version")
					return ids, ids
				},
			},
			wantErr:     true,
			wantErrCode: errors.MultipleRecords,
		},
		{
			name: "zero-version",
			args: args{
				userVersionOverride: func() *uint32 {
					i := uint32(0)
					return &i
				}(),
				userId: user.PublicId,
				accountIdsFn: func() ([]string, []string) {
					ids := createAccountsFn("zero-version")
					return ids, ids
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "no-accounts-no-changes",
			args: args{
				userId:       user.PublicId,
				accountIdsFn: func() ([]string, []string) { return nil, nil },
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, func() any { a := allocAuthAccount(); return &a }(), "iam_user_id = ?", user.PublicId)

			accountIds, changes := tt.args.accountIdsFn()
			sort.Strings(accountIds)

			origUser, _, err := repo.LookupUser(context.Background(), user.PublicId)
			require.NoError(err)

			version := origUser.Version
			if tt.args.userVersionOverride != nil {
				version = *tt.args.userVersionOverride
			}

			got, err := repo.SetUserAccounts(context.Background(), tt.args.userId, version, accountIds, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "unexpected error %s", err)
				return
			}
			require.NoError(err)
			if len(changes) != 0 {
				err = db.TestVerifyOplog(t, rw, tt.args.userId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				assert.NoError(err)
				for _, id := range changes {
					err = db.TestVerifyOplog(t, rw, id, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
					assert.NoErrorf(err, "%s missing oplog entry", id)
				}
			}

			sort.Strings(got)
			assert.Equal(accountIds, got)

			foundIds, err := repo.ListUserAccounts(context.Background(), tt.args.userId)
			require.NoError(err)
			sort.Strings(foundIds)
			assert.Equal(accountIds, foundIds)

			u, _, err := repo.LookupUser(context.Background(), tt.args.userId)
			require.NoError(err)
			switch tt.name {
			case "no-accounts-no-changes", "no-change":
				assert.Equalf(version, u.Version, "expected version %d and got: %d", version, u.Version)
			default:
				assert.Equalf(version+1, u.Version, "expected version %d and got: %d", version+1, u.Version)
			}
		})
	}
}

func testId(t *testing.T) string {
	t.Helper()
	id, err := uuid.GenerateUUID()
	require.NoError(t, err)
	return id
}

type testAuthAccount struct {
	*store.Account
	tableName string `gorm:"-"`
}

func allocAuthAccount() testAuthAccount {
	return testAuthAccount{
		Account: &store.Account{},
	}
}

// TableName returns the tablename to override the default gorm table name.
func (a *testAuthAccount) TableName() string {
	if a.tableName != "" {
		return a.tableName
	}
	return "auth_account"
}
