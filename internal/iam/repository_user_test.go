package iam

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRepository_CreateUser(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	id := testId(t)
	org, _ := TestScopes(t, repo)

	type args struct {
		user *User
		opt  []Option
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
				user: func() *User {
					u, err := NewUser(org.PublicId, WithName("valid"+id), WithDescription(id))
					assert.NoError(t, err)
					return u
				}(),
			},
			wantErr: false,
		},
		{
			name: "bad-scope-id",
			args: args{
				user: func() *User {
					u, err := NewUser(id)
					assert.NoError(t, err)
					return u
				}(),
			},
			wantErr:    true,
			wantErrMsg: "create user: error getting metadata for create: unable to get scope for standard metadata: record not found for",
		},
		{
			name: "dup-name",
			args: args{
				user: func() *User {
					u, err := NewUser(org.PublicId, WithName("dup-name"+id))
					assert.NoError(t, err)
					return u
				}(),
			},
			wantDup:    true,
			wantErr:    true,
			wantErrMsg: "create user: user %s already exists in org %s",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tt.wantDup {
				dup, err := repo.CreateUser(context.Background(), tt.args.user, tt.args.opt...)
				require.NoError(err)
				require.NotNil(dup)
			}
			u, err := repo.CreateUser(context.Background(), tt.args.user, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(u)
				switch tt.name {
				case "dup-name":
					assert.Equal(fmt.Sprintf(tt.wantErrMsg, "dup-name"+id, org.PublicId), err.Error())
				default:
					assert.True(strings.HasPrefix(err.Error(), tt.wantErrMsg))
				}
				return
			}
			require.NoError(err)
			assert.NotNil(u.CreateTime)
			assert.NotNil(u.UpdateTime)

			foundUser, err := repo.LookupUser(context.Background(), u.PublicId)
			require.NoError(err)
			assert.True(proto.Equal(foundUser, u))

			err = db.TestVerifyOplog(t, rw, u.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_UpdateUser(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	id := testId(t)
	org, proj := TestScopes(t, repo)
	pubId := func(s string) *string { return &s }

	type args struct {
		name           string
		description    string
		fieldMaskPaths []string
		opt            []Option
		ScopeId        string
		PublicId       *string
	}
	tests := []struct {
		name           string
		newUserOpts    []Option
		args           args
		wantRowsUpdate int
		wantErr        bool
		wantErrMsg     string
		wantIsErr      error
		wantDup        bool
		directUpdate   bool
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
			newUserOpts:    []Option{WithName("valid-no-op" + id)},
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
			wantErrMsg:     "update user: update: lookup after write: record not found for 1",
			wantIsErr:      db.ErrRecordNotFound,
		},
		{
			name: "null-name",
			args: args{
				name:           "",
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
			},
			newUserOpts:    []Option{WithName("null-name" + id)},
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
			newUserOpts:    []Option{WithDescription("null-description" + id)},
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
			wantErrMsg:     "update user: empty field mask",
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
			wantErrMsg:     "update user: empty field mask",
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
			wantErrMsg:     "update user: field: CreateTime: invalid field mask",
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
			wantErrMsg:     "update user: field: Alice: invalid field mask",
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
			wantErrMsg:     "update user: missing user public id invalid parameter",
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
			wantErrMsg: "update user: field: ScopeId: invalid field mask",
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
			wantErrMsg: `update user: user %s already exists in org %s`,
		},
		{
			name: "modified-scope",
			args: args{
				name:           "modified-scope" + id,
				fieldMaskPaths: []string{"ScopeId"},
				ScopeId:        "global",
				opt:            []Option{WithSkipVetForWrite(true)},
			},
			wantErr:      true,
			wantErrMsg:   `update: failed: pq: immutable column: iam_user.scope_id`,
			directUpdate: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tt.wantDup {
				u := TestUser(t, repo, org.PublicId, tt.newUserOpts...)
				u.Name = tt.args.name
				_, _, err := repo.UpdateUser(context.Background(), u, 1, tt.args.fieldMaskPaths, tt.args.opt...)
				require.NoError(err)
			}

			u := TestUser(t, repo, org.PublicId, tt.newUserOpts...)

			updateUser := allocUser()
			updateUser.PublicId = u.PublicId
			if tt.args.PublicId != nil {
				updateUser.PublicId = *tt.args.PublicId
			}
			updateUser.ScopeId = tt.args.ScopeId
			updateUser.Name = tt.args.name
			updateUser.Description = tt.args.description

			var userAfterUpdate *User
			var updatedRows int
			var err error
			if tt.directUpdate {
				u := updateUser.Clone()
				var resource interface{}
				resource, updatedRows, err = repo.update(context.Background(), u.(*User), 1, tt.args.fieldMaskPaths, nil, tt.args.opt...)
				if err == nil {
					userAfterUpdate = resource.(*User)
				}
			} else {
				userAfterUpdate, updatedRows, err = repo.UpdateUser(context.Background(), &updateUser, 1, tt.args.fieldMaskPaths, tt.args.opt...)
			}
			if tt.wantErr {
				require.Error(err)
				if tt.wantIsErr != nil {
					assert.True(errors.Is(err, db.ErrRecordNotFound))
				}
				assert.Nil(userAfterUpdate)
				assert.Equal(0, updatedRows)
				switch tt.name {
				case "dup-name":
					assert.Equal(fmt.Sprintf(tt.wantErrMsg, "dup-name"+id, org.PublicId), err.Error())
				default:
					assert.Containsf(err.Error(), tt.wantErrMsg, "unexpected error: %s", err.Error())
				}
				err = db.TestVerifyOplog(t, rw, u.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				require.Error(err)
				assert.Equal("record not found", err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			assert.NotEqual(u.UpdateTime, userAfterUpdate.UpdateTime)
			foundUser, err := repo.LookupUser(context.Background(), u.PublicId)
			require.NoError(err)
			assert.True(proto.Equal(userAfterUpdate, foundUser))

			dbassert := dbassert.New(t, rw)
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
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)

	type args struct {
		user *User
		opt  []Option
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
				user: TestUser(t, repo, org.PublicId),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-public-id",
			args: args{
				user: func() *User {
					u := allocUser()
					return &u
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "delete user: missing public id invalid parameter",
		},
		{
			name: "not-found",
			args: args{
				user: func() *User {
					u, err := NewUser(org.PublicId)
					require.NoError(t, err)
					id, err := newUserId()
					require.NoError(t, err)
					u.PublicId = id
					return u
				}(),
			},
			wantRowsDeleted: 1,
			wantErr:         true,
			wantErrMsg:      "delete user: failed record not found for",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deletedRows, err := repo.DeleteUser(context.Background(), tt.args.user.PublicId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, deletedRows)
				assert.True(strings.HasPrefix(err.Error(), tt.wantErrMsg))
				err = db.TestVerifyOplog(t, rw, tt.args.user.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				require.Error(err)
				assert.Equal("record not found", err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundUser, err := repo.LookupUser(context.Background(), tt.args.user.PublicId)
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
	repo := TestRepo(t, conn, wrapper, WithLimit(testLimit))
	org, _ := TestScopes(t, repo)

	type args struct {
		withOrgId string
		opt       []Option
	}
	tests := []struct {
		name      string
		createCnt int
		args      args
		wantCnt   int
		wantErr   bool
	}{
		{
			name:      "no-limit",
			createCnt: repo.defaultLimit + 1,
			args: args{
				withOrgId: org.PublicId,
				opt:       []Option{WithLimit(-1)},
			},
			wantCnt: repo.defaultLimit + 1,
			wantErr: false,
		},
		{
			name:      "default-limit",
			createCnt: repo.defaultLimit + 1,
			args: args{
				withOrgId: org.PublicId,
			},
			wantCnt: repo.defaultLimit,
			wantErr: false,
		},
		{
			name:      "custom-limit",
			createCnt: repo.defaultLimit + 1,
			args: args{
				withOrgId: org.PublicId,
				opt:       []Option{WithLimit(3)},
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
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("public_id != 'u_anon' and public_id != 'u_auth' and public_id != 'u_recovery'").Delete(allocUser()).Error)
			testUsers := []*User{}
			for i := 0; i < tt.createCnt; i++ {
				testUsers = append(testUsers, TestUser(t, repo, org.PublicId))
			}
			assert.Equal(tt.createCnt, len(testUsers))
			got, err := repo.ListUsers(context.Background(), tt.args.withOrgId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
		})
	}
}

func TestRepository_LookupUserWithLogin(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)

	id := testId(t)
	org, _ := TestScopes(t, repo)
	authMethodId := testAuthMethod(t, conn, org.PublicId)
	newAuthAcct := testAccount(t, conn, org.PublicId, authMethodId, "")
	newAuthAcctWithoutVivify := testAccount(t, conn, org.PublicId, authMethodId, "")

	user := TestUser(t, repo, org.PublicId, WithName("existing-"+id))
	existingAuthAcct := testAccount(t, conn, org.PublicId, authMethodId, user.PublicId)
	require.Equal(t, user.PublicId, existingAuthAcct.IamUserId)

	type args struct {
		withAccountId string
		opt           []Option
	}
	tests := []struct {
		name            string
		args            args
		wantName        string
		wantDescription string
		wantErr         bool
		wantErrIs       error
		wantUser        *User
	}{
		{
			name: "valid",
			args: args{
				withAccountId: newAuthAcct.PublicId,
				opt: []Option{
					WithAutoVivify(true),
					WithName("valid-" + id),
					WithDescription("valid-" + id),
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
			wantErrIs: db.ErrRecordNotFound,
		},
		{
			name: "missing auth acct id",
			args: args{
				withAccountId: "",
			},
			wantErr:   true,
			wantErrIs: db.ErrInvalidParameter,
		},
		{
			name: "existing-auth-account",
			args: args{
				withAccountId: existingAuthAcct.PublicId,
			},
			wantErr:  false,
			wantName: "existing-" + id,
			wantUser: user,
		},
		{
			name: "existing-auth-account-with-vivify",
			args: args{
				withAccountId: existingAuthAcct.PublicId,
				opt: []Option{
					WithAutoVivify(true),
				},
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
			wantErrIs: db.ErrRecordNotFound,
		},
		{
			name: "bad-auth-account-id-with-vivify",
			args: args{
				withAccountId: id,
				opt: []Option{
					WithAutoVivify(true),
				},
			},
			wantErr:   true,
			wantErrIs: db.ErrRecordNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			dbassert := dbassert.New(t, rw)
			got, err := repo.LookupUserWithLogin(context.Background(), tt.args.withAccountId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(got)
				if tt.wantErrIs != nil {
					assert.Truef(errors.Is(err, tt.wantErrIs), "unexpected error %s", err.Error())
				}
				if tt.args.withAccountId != "" && tt.args.withAccountId != id {
					// need to assert that userid in auth_account is still null
					acct := allocAccount()
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
				assert.True(proto.Equal(tt.wantUser.User, got.User))
			}
			acct := allocAccount()
			acct.PublicId = tt.args.withAccountId
			err = rw.LookupByPublicId(context.Background(), &acct)
			require.NoError(err)
			assert.Equal(got.PublicId, acct.IamUserId)
		})
	}
}

func TestRepository_AssociateUserWithAccount(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)
	authMethodId := testAuthMethod(t, conn, org.PublicId)

	type Ids struct {
		user string
		acct string
	}
	type args struct {
		Ids Ids
		opt []Option
	}
	tests := []struct {
		name      string
		args      args
		want      *User
		want1     *authAccount
		wantErr   bool
		wantErrIs error
		wantAssoc bool
	}{
		{
			name: "simple",
			args: args{
				Ids: func() Ids {
					u := TestUser(t, repo, org.PublicId)
					a := testAccount(t, conn, org.PublicId, authMethodId, "")
					return Ids{user: u.PublicId, acct: a.PublicId}
				}(),
			},
		},
		{
			name: "missing-acctId",
			args: args{
				Ids: func() Ids {
					id := testId(t)

					return Ids{user: id}
				}(),
			},
			wantErr:   true,
			wantErrIs: db.ErrInvalidParameter,
		},
		{
			name: "missing-userId",
			args: args{
				Ids: func() Ids {
					id := testId(t)
					return Ids{acct: id}
				}(),
			},
			wantErr:   true,
			wantErrIs: db.ErrInvalidParameter,
		},
		{
			name: "already-properly-assoc",
			args: args{
				Ids: func() Ids {
					u := TestUser(t, repo, org.PublicId)
					a := testAccount(t, conn, org.PublicId, authMethodId, u.PublicId)
					return Ids{user: u.PublicId, acct: a.PublicId}
				}(),
				opt: []Option{WithDisassociate(true)},
			},
		},
		{
			name: "assoc-with-diff-user",
			args: args{
				Ids: func() Ids {
					u := TestUser(t, repo, org.PublicId)
					diffUser := TestUser(t, repo, org.PublicId)
					a := testAccount(t, conn, org.PublicId, authMethodId, diffUser.PublicId)
					return Ids{user: u.PublicId, acct: a.PublicId}
				}(),
			},
			wantErr:   true,
			wantErrIs: db.ErrInvalidParameter,
		},
		{
			name: "assoc-with-diff-user-withDisassociateOption",
			args: args{
				Ids: func() Ids {
					u := TestUser(t, repo, org.PublicId)
					diffUser := TestUser(t, repo, org.PublicId)
					a := testAccount(t, conn, org.PublicId, authMethodId, diffUser.PublicId)
					return Ids{user: u.PublicId, acct: a.PublicId}
				}(),
			},
			wantErr:   true,
			wantErrIs: db.ErrInvalidParameter,
		},
		{
			name: "bad-acct-id",
			args: args{
				Ids: func() Ids {
					u := TestUser(t, repo, org.PublicId)
					id := testId(t)
					return Ids{user: u.PublicId, acct: id}
				}(),
			},
			wantErr:   true,
			wantErrIs: db.ErrRecordNotFound,
		},
		{
			name: "bad-user-id",
			args: args{
				Ids: func() Ids {
					id := testId(t)
					a := testAccount(t, conn, org.PublicId, authMethodId, "")
					return Ids{user: id, acct: a.PublicId}
				}(),
			},
			wantErr:   true,
			wantErrIs: db.ErrRecordNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			u, err := repo.AssociateUserWithAccount(context.Background(), tt.args.Ids.user, tt.args.Ids.acct, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Empty(u)
				if tt.wantErrIs != nil {
					assert.Truef(errors.Is(err, tt.wantErrIs), "unexpected error %s", err.Error())
				}
				return
			}
			require.NoError(err)
			assert.Equal(tt.args.Ids.user, u.PublicId)
			acct := allocAccount()
			acct.PublicId = tt.args.Ids.acct
			err = rw.LookupByPublicId(context.Background(), &acct)
			require.NoError(err)
			assert.Equal(tt.args.Ids.user, acct.IamUserId)
		})
	}
}

func TestRepository_DissociateUserWithAccount(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)
	authMethodId := testAuthMethod(t, conn, org.PublicId)

	type Ids struct {
		user string
		acct string
	}
	type args struct {
		Ids Ids
		opt []Option
	}
	tests := []struct {
		name      string
		args      args
		want      *User
		want1     *authAccount
		wantErr   bool
		wantErrIs error
	}{
		{
			name: "simple",
			args: args{
				Ids: func() Ids {
					u := TestUser(t, repo, org.PublicId)
					a := testAccount(t, conn, org.PublicId, authMethodId, u.PublicId)
					return Ids{user: u.PublicId, acct: a.PublicId}
				}(),
			},
		},
		{
			name: "missing-acctId",
			args: args{
				Ids: func() Ids {
					id := testId(t)

					return Ids{user: id}
				}(),
			},
			wantErr:   true,
			wantErrIs: db.ErrInvalidParameter,
		},
		{
			name: "missing-userId",
			args: args{
				Ids: func() Ids {
					id := testId(t)
					return Ids{acct: id}
				}(),
			},
			wantErr:   true,
			wantErrIs: db.ErrInvalidParameter,
		},
		{
			name: "already-properly-disassoc",
			args: args{
				Ids: func() Ids {
					u := TestUser(t, repo, org.PublicId)
					a := testAccount(t, conn, org.PublicId, authMethodId, "")
					return Ids{user: u.PublicId, acct: a.PublicId}
				}(),
			},
		},
		{
			name: "assoc-with-diff-user",
			args: args{
				Ids: func() Ids {
					u := TestUser(t, repo, org.PublicId)
					diffUser := TestUser(t, repo, org.PublicId)
					a := testAccount(t, conn, org.PublicId, authMethodId, diffUser.PublicId)
					return Ids{user: u.PublicId, acct: a.PublicId}
				}(),
			},
			wantErr:   true,
			wantErrIs: db.ErrInvalidParameter,
		},
		{
			name: "bad-acct-id",
			args: args{
				Ids: func() Ids {
					u := TestUser(t, repo, org.PublicId)
					id := testId(t)
					return Ids{user: u.PublicId, acct: id}
				}(),
			},
			wantErr:   true,
			wantErrIs: db.ErrRecordNotFound,
		},
		{
			name: "bad-user-id",
			args: args{
				Ids: func() Ids {
					id := testId(t)
					a := testAccount(t, conn, org.PublicId, authMethodId, "")
					return Ids{user: id, acct: a.PublicId}
				}(),
			},
			wantErr:   true,
			wantErrIs: db.ErrRecordNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			dbassert := dbassert.New(t, rw)
			u, err := repo.DissociateUserWithAccount(context.Background(), tt.args.Ids.user, tt.args.Ids.acct, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Empty(u)
				if tt.wantErrIs != nil {
					assert.Truef(errors.Is(err, tt.wantErrIs), "unexpected error %s", err.Error())
				}
				return
			}
			require.NoError(err)
			assert.Equal(tt.args.Ids.user, u.PublicId)

			acct := allocAccount()
			acct.PublicId = tt.args.Ids.acct
			dbassert.IsNull(&acct, "IamUserId")

		})
	}
}
