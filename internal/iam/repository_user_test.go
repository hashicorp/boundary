package iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestRepository_CreateUser(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	a := assert.New(t)
	defer conn.Close()

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	id, err := uuid.GenerateUUID()
	a.NoError(err)

	org, _ := TestScopes(t, conn)

	type args struct {
		orgId string
		opt   []Option
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
				orgId: org.PublicId,
				opt:   []Option{WithName("valid" + id), WithDescription(id)},
			},
			wantErr: false,
		},
		{
			name: "bad-scope-id",
			args: args{
				orgId: id,
			},
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "dup-name",
			args: args{
				orgId: id,
				opt:   []Option{WithName("dup-name" + id)},
			},
			wantDup:    true,
			wantErr:    true,
			wantErrMsg: `failed to create user: error creating: pq: duplicate key value violates unique constraint "iam_user_name_scope_id_key"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			if tt.wantDup {
				dup, err := NewUser(org.PublicId, tt.args.opt...)
				assert.NoError(err)
				dup, err = repo.CreateUser(context.Background(), dup, tt.args.opt...)
				assert.NoError(err)
				assert.NotNil(dup)
			}
			u, err := NewUser(org.PublicId, tt.args.opt...)
			pubId := u.PublicId
			assert.NoError(err)
			u, err = repo.CreateUser(context.Background(), u, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(u)
				assert.Equal(tt.wantErrMsg, err.Error())
				err = db.TestVerifyOplog(rw, pubId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.Equal("record not found", err.Error())
				return
			}
			assert.NoError(err)
			assert.NotNil(u.CreateTime)
			assert.NotNil(u.UpdateTime)

			foundUser, err := repo.LookupUser(context.Background(), u.PublicId)
			assert.NoError(err)
			assert.True(proto.Equal(foundUser, u))

			err = db.TestVerifyOplog(rw, u.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_UpdateUser(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	a := assert.New(t)
	defer conn.Close()

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	id, err := uuid.GenerateUUID()
	a.NoError(err)

	org, proj := TestScopes(t, conn)

	type args struct {
		name           string
		description    string
		fieldMaskPaths []string
		opt            []Option
		ScopeId        string
	}
	tests := []struct {
		name           string
		args           args
		wantRowsUpdate int
		wantErr        bool
		wantErrMsg     string
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
			name: "proj-scope-id-no-mask",
			args: args{
				name:    "proj-scope-id" + id,
				ScopeId: proj.PublicId,
			},
			wantErr:    true,
			wantErrMsg: "failed to update user: error on update not allowed to change a resource's scope",
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
			wantErrMsg: `failed to update user: error updating: pq: duplicate key value violates unique constraint "iam_user_name_scope_id_key"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			if tt.wantDup {
				u := TestUser(t, conn, org.PublicId)
				u.Name = tt.args.name
				_, _, err := repo.UpdateUser(context.Background(), u, tt.args.fieldMaskPaths, tt.args.opt...)
				assert.NoError(err)
			}

			u := TestUser(t, conn, org.PublicId)

			updateUser := allocUser()
			updateUser.PublicId = u.PublicId
			updateUser.ScopeId = tt.args.ScopeId
			updateUser.Name = tt.args.name
			updateUser.Description = tt.args.description

			userAfterUpdate, updatedRows, err := repo.UpdateUser(context.Background(), &updateUser, tt.args.fieldMaskPaths, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(userAfterUpdate)
				assert.Equal(0, updatedRows)
				assert.Equal(tt.wantErrMsg, err.Error())
				err = db.TestVerifyOplog(rw, u.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.Equal("record not found", err.Error())
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			assert.NotEqual(u.UpdateTime, userAfterUpdate.UpdateTime)
			foundUser, err := repo.LookupUser(context.Background(), u.PublicId)
			assert.NoError(err)
			assert.True(proto.Equal(userAfterUpdate, foundUser))

			err = db.TestVerifyOplog(rw, u.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_DeleteUser(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	a := assert.New(t)
	defer conn.Close()

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	a.NoError(err)
	org, _ := TestScopes(t, conn)

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
				user: TestUser(t, conn, org.PublicId),
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
			wantErrMsg:      "you cannot delete a user with an empty public id",
		},
		{
			name: "not-found",
			args: args{
				user: func() *User {
					u, err := NewUser(org.PublicId)
					a.NoError(err)
					return u
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         false,
			wantErrMsg:      "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			deletedRows, err := repo.DeleteUser(context.Background(), tt.args.user.PublicId, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				assert.Equal(tt.wantErrMsg, err.Error())
				err = db.TestVerifyOplog(rw, tt.args.user.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.Equal("record not found", err.Error())
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundUser, err := repo.LookupUser(context.Background(), tt.args.user.PublicId)
			assert.Error(err)
			assert.Nil(foundUser)
			assert.True(errors.Is(err, db.ErrRecordNotFound))

			err = db.TestVerifyOplog(rw, tt.args.user.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)
		})
	}
}
