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

func TestRepository_CreateGroup(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	a := assert.New(t)
	defer conn.Close()

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	a.NoError(err)
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
			wantErrMsg: `failed to create group: create: failed pq: duplicate key value violates unique constraint "iam_group_name_scope_id_key"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			if tt.wantDup {
				dup, err := NewGroup(org.PublicId, tt.args.opt...)
				assert.NoError(err)
				dup, err = repo.CreateGroup(context.Background(), dup, tt.args.opt...)
				assert.NoError(err)
				assert.NotNil(dup)
			}
			grp, err := NewGroup(org.PublicId, tt.args.opt...)
			pubId := grp.PublicId
			assert.NoError(err)
			grp, err = repo.CreateGroup(context.Background(), grp, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(grp)
				assert.Equal(tt.wantErrMsg, err.Error())
				err = db.TestVerifyOplog(t, rw, pubId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.Equal("record not found", err.Error())
				return
			}
			assert.NoError(err)
			assert.NotNil(grp.CreateTime)
			assert.NotNil(grp.UpdateTime)

			foundGrp, err := repo.LookupGroup(context.Background(), grp.PublicId)
			assert.NoError(err)
			assert.True(proto.Equal(foundGrp, grp))

			err = db.TestVerifyOplog(t, rw, grp.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_UpdateGroup(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	a := assert.New(t)
	defer conn.Close()

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	a.NoError(err)
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
			wantErrMsg: "failed to update group: update: both fieldMaskPaths and setToNullPaths are missing",
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
			wantErrMsg: `failed to update group: update: failed pq: duplicate key value violates unique constraint "iam_group_name_scope_id_key"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			if tt.wantDup {
				g := TestGroup(t, conn, org.PublicId)
				g.Name = tt.args.name
				_, _, err := repo.UpdateGroup(context.Background(), g, tt.args.fieldMaskPaths, tt.args.opt...)
				assert.NoError(err)
			}

			u := TestGroup(t, conn, org.PublicId)

			updateGrp := allocGroup()
			updateGrp.PublicId = u.PublicId
			updateGrp.ScopeId = tt.args.ScopeId
			updateGrp.Name = tt.args.name
			updateGrp.Description = tt.args.description

			userAfterUpdate, updatedRows, err := repo.UpdateGroup(context.Background(), &updateGrp, tt.args.fieldMaskPaths, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(userAfterUpdate)
				assert.Equal(0, updatedRows)
				assert.Equal(tt.wantErrMsg, err.Error())
				err = db.TestVerifyOplog(t, rw, u.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.Equal("record not found", err.Error())
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			assert.NotEqual(u.UpdateTime, userAfterUpdate.UpdateTime)
			foundGrp, err := repo.LookupGroup(context.Background(), u.PublicId)
			assert.NoError(err)
			assert.True(proto.Equal(userAfterUpdate, foundGrp))

			err = db.TestVerifyOplog(t, rw, u.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_DeleteGroup(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	a := assert.New(t)
	defer conn.Close()

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	a.NoError(err)
	org, _ := TestScopes(t, conn)

	type args struct {
		group *Group
		opt   []Option
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
				group: TestGroup(t, conn, org.PublicId),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-public-id",
			args: args{
				group: func() *Group {
					g := allocGroup()
					return &g
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "you cannot delete a group with an empty public id",
		},
		{
			name: "not-found",
			args: args{
				group: func() *Group {
					g, err := NewGroup(org.PublicId)
					a.NoError(err)
					return g
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
			deletedRows, err := repo.DeleteGroup(context.Background(), tt.args.group.PublicId, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				assert.Equal(tt.wantErrMsg, err.Error())
				err = db.TestVerifyOplog(t, rw, tt.args.group.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.Equal("record not found", err.Error())
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundGroup, err := repo.LookupGroup(context.Background(), tt.args.group.PublicId)
			assert.Error(err)
			assert.Nil(foundGroup)
			assert.True(errors.Is(err, db.ErrRecordNotFound))

			err = db.TestVerifyOplog(t, rw, tt.args.group.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)
		})
	}
}
