package iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	dbassert "github.com/hashicorp/watchtower/internal/db/assert"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRepository_CreateGroup(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	id := testId(t)

	org, proj := TestScopes(t, conn)

	type args struct {
		group *Group
		opt   []Option
	}
	tests := []struct {
		name        string
		args        args
		wantDup     bool
		wantErr     bool
		wantErrMsg  string
		wantIsError error
	}{
		{
			name: "valid-org",
			args: args{
				group: func() *Group {
					g, err := NewGroup(org.PublicId, WithName("valid-org"+id), WithDescription(id))
					assert.NoError(t, err)
					return g
				}(),
			},
			wantErr: false,
		},
		{
			name: "valid-proj",
			args: args{
				group: func() *Group {
					g, err := NewGroup(proj.PublicId, WithName("valid-proj"+id), WithDescription(id))
					assert.NoError(t, err)
					return g
				}(),
			},
			wantErr: false,
		},
		{
			name: "nil-group",
			args: args{
				group: nil,
			},
			wantErr:     true,
			wantErrMsg:  "create group: missing group nil parameter",
			wantIsError: db.ErrNilParameter,
		},
		{
			name: "nil-store",
			args: args{
				group: func() *Group {
					return &Group{
						Group: nil,
					}
				}(),
			},
			wantErr:     true,
			wantErrMsg:  "create group: missing group store nil parameter",
			wantIsError: db.ErrNilParameter,
		},
		{
			name: "bad-scope-id",
			args: args{
				group: func() *Group {
					g, err := NewGroup(id)
					assert.NoError(t, err)
					return g
				}(),
			},
			wantErr:     true,
			wantErrMsg:  "create group: error getting metadata for create: unable to get scope for standard metadata: record not found for",
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "dup-name",
			args: args{
				group: func() *Group {
					g, err := NewGroup(org.PublicId, WithName("dup-name"+id), WithDescription(id))
					assert.NoError(t, err)
					return g
				}(),
				opt: []Option{WithName("dup-name" + id)},
			},
			wantDup:     true,
			wantErr:     true,
			wantErrMsg:  "already exists in scope ",
			wantIsError: db.ErrNotUnique,
		},
		{
			name: "dup-name-but-diff-scope",
			args: args{
				group: func() *Group {
					g, err := NewGroup(proj.PublicId, WithName("dup-name-but-diff-scope"+id), WithDescription(id))
					assert.NoError(t, err)
					return g
				}(),
				opt: []Option{WithName("dup-name-but-diff-scope" + id)},
			},
			wantDup: true,
			wantErr: false,
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
			grp, err := repo.CreateGroup(context.Background(), tt.args.group, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(grp)
				assert.Contains(err.Error(), tt.wantErrMsg)
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
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	a := assert.New(t)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	a.NoError(err)
	id, err := uuid.GenerateUUID()
	a.NoError(err)

	org, proj := TestScopes(t, conn)
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
		newScopeId     string
		newGrpOpts     []Option
		args           args
		wantRowsUpdate int
		wantErr        bool
		wantErrMsg     string
		wantIsError    error
		wantDup        bool
	}{
		{
			name: "valid",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
			},
			newScopeId:     org.PublicId,
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
			newScopeId:     org.PublicId,
			newGrpOpts:     []Option{WithName("valid-no-op" + id)},
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
			newScopeId:     org.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "update group: update: lookup error lookup after write: failed record not found for 1",
			wantIsError:    db.ErrRecordNotFound,
		},
		{
			name: "null-name",
			args: args{
				name:           "",
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
			},
			newScopeId:     org.PublicId,
			newGrpOpts:     []Option{WithName("null-name" + id)},
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
			newScopeId:     org.PublicId,
			newGrpOpts:     []Option{WithDescription("null-description" + id)},
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
			newScopeId:     org.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "update group: empty field mask",
			wantIsError:    db.ErrEmptyFieldMask,
		},
		{
			name: "nil-fieldmask",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: nil,
				ScopeId:        org.PublicId,
			},
			newScopeId:     org.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "update group: empty field mask",
			wantIsError:    db.ErrEmptyFieldMask,
		},
		{
			name: "read-only-fields",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"CreateTime"},
				ScopeId:        org.PublicId,
			},
			newScopeId:     org.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "update group: field: CreateTime: invalid field mask",
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "unknown-fields",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"Alice"},
				ScopeId:        org.PublicId,
			},
			newScopeId:     org.PublicId,
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "update group: field: Alice: invalid field mask",
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "no-public-id",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
				PublicId:       pubId(""),
			},
			newScopeId:     org.PublicId,
			wantErr:        true,
			wantErrMsg:     "update group: missing group public id invalid parameter",
			wantIsError:    db.ErrInvalidParameter,
			wantRowsUpdate: 0,
		},
		{
			name: "proj-scope-id-no-mask",
			args: args{
				name:    "proj-scope-id" + id,
				ScopeId: proj.PublicId,
			},
			newScopeId:  org.PublicId,
			wantErr:     true,
			wantErrMsg:  "update group: empty field mask",
			wantIsError: db.ErrEmptyFieldMask,
		},
		{
			name: "empty-scope-id-with-name-mask",
			args: args{
				name:           "empty-scope-id" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        "",
			},
			newScopeId:     org.PublicId,
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "dup-name-in-diff-scope",
			args: args{
				name:           "dup-name-in-diff-scope" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        proj.PublicId,
			},
			newScopeId:     proj.PublicId,
			newGrpOpts:     []Option{WithName("dup-name-in-diff-scope-pre-update" + id)},
			wantErr:        false,
			wantRowsUpdate: 1,
			wantDup:        true,
		},
		{
			name: "dup-name",
			args: args{
				name:           "dup-name" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
			},
			newScopeId:  org.PublicId,
			wantErr:     true,
			wantDup:     true,
			wantErrMsg:  " already exists in organization " + org.PublicId,
			wantIsError: db.ErrNotUnique,
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

			u := TestGroup(t, conn, tt.newScopeId, tt.newGrpOpts...)

			updateGrp := allocGroup()
			updateGrp.PublicId = u.PublicId
			if tt.args.PublicId != nil {
				updateGrp.PublicId = *tt.args.PublicId
			}
			updateGrp.ScopeId = tt.args.ScopeId
			updateGrp.Name = tt.args.name
			updateGrp.Description = tt.args.description

			userAfterUpdate, updatedRows, err := repo.UpdateGroup(context.Background(), &updateGrp, tt.args.fieldMaskPaths, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				if tt.wantIsError != nil {
					assert.True(errors.Is(err, tt.wantIsError))
				}
				assert.Nil(userAfterUpdate)
				assert.Equal(0, updatedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, u.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.Is(db.ErrRecordNotFound, err))
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			switch tt.name {
			case "valid-no-op":
				assert.Equal(u.UpdateTime, userAfterUpdate.UpdateTime)
			default:
				assert.NotEqual(u.UpdateTime, userAfterUpdate.UpdateTime)
			}
			foundGrp, err := repo.LookupGroup(context.Background(), u.PublicId)
			assert.NoError(err)
			assert.True(proto.Equal(userAfterUpdate, foundGrp))
			dbassert := dbassert.New(t, rw)
			if tt.args.name == "" {
				dbassert.IsNull(foundGrp, "name")
			}
			if tt.args.description == "" {
				dbassert.IsNull(foundGrp, "description")
			}

			err = db.TestVerifyOplog(t, rw, u.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_DeleteGroup(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	a := assert.New(t)
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
			wantErrMsg:      "delete group: missing public id nil parameter",
		},
		{
			name: "not-found",
			args: args{
				group: func() *Group {
					id, err := newGroupId()
					a.NoError(err)
					g, err := NewGroup(org.PublicId)
					g.PublicId = id
					a.NoError(err)
					return g
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "delete group: failed record not found for ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			deletedRows, err := repo.DeleteGroup(context.Background(), tt.args.group.PublicId, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, tt.args.group.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.Is(db.ErrRecordNotFound, err))
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
