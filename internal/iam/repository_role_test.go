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

func TestRepository_CreateRole(t *testing.T) {
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
		role *Role
		opt  []Option
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
				role: func() *Role {
					r, err := NewRole(org.PublicId, WithName("valid-org"+id), WithDescription(id))
					assert.NoError(t, err)
					return r
				}(),
			},
			wantErr: false,
		},
		{
			name: "valid-proj",
			args: args{
				role: func() *Role {
					r, err := NewRole(proj.PublicId, WithName("valid-proj"+id), WithDescription(id))
					assert.NoError(t, err)
					return r
				}(),
			},
			wantErr: false,
		},
		{
			name: "bad-public-id",
			args: args{
				role: func() *Role {
					r, err := NewRole(proj.PublicId, WithName("valid-proj"+id), WithDescription(id))
					assert.NoError(t, err)
					r.PublicId = id
					return r
				}(),
			},
			wantErrMsg:  "create role: public id not empty: invalid parameter",
			wantIsError: db.ErrInvalidParameter,
			wantErr:     true,
		},
		{
			name: "nil-role",
			args: args{
				role: nil,
			},
			wantErr:     true,
			wantErrMsg:  "create role: missing role nil parameter",
			wantIsError: db.ErrNilParameter,
		},
		{
			name: "nil-store",
			args: args{
				role: func() *Role {
					return &Role{
						Role: nil,
					}
				}(),
			},
			wantErr:     true,
			wantErrMsg:  "create role: missing role store nil parameter",
			wantIsError: db.ErrNilParameter,
		},
		{
			name: "bad-scope-id",
			args: args{
				role: func() *Role {
					r, err := NewRole(id)
					assert.NoError(t, err)
					return r
				}(),
			},
			wantErr:     true,
			wantErrMsg:  "create role: error getting metadata for create: unable to get scope for standard metadata: record not found for",
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "dup-name",
			args: args{
				role: func() *Role {
					r, err := NewRole(org.PublicId, WithName("dup-name"+id), WithDescription(id))
					assert.NoError(t, err)
					return r
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
				role: func() *Role {
					r, err := NewRole(proj.PublicId, WithName("dup-name-but-diff-scope"+id), WithDescription(id))
					assert.NoError(t, err)
					return r
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
				dup, err := NewRole(org.PublicId, tt.args.opt...)
				assert.NoError(err)
				dup, err = repo.CreateRole(context.Background(), dup, tt.args.opt...)
				assert.NoError(err)
				assert.NotNil(dup)
			}
			grp, err := repo.CreateRole(context.Background(), tt.args.role, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(grp)
				assert.Contains(err.Error(), tt.wantErrMsg)
				return
			}
			assert.NoError(err)
			assert.NotNil(grp.CreateTime)
			assert.NotNil(grp.UpdateTime)

			foundGrp, err := repo.LookupRole(context.Background(), grp.PublicId)
			assert.NoError(err)
			assert.True(proto.Equal(foundGrp, grp))

			err = db.TestVerifyOplog(t, rw, grp.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_UpdateRole(t *testing.T) {
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
	id, err := uuid.GenerateUUID()
	require.NoError(t, err)

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
			wantErrMsg:     "update role: update: lookup error lookup after write: failed record not found for 1",
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
			wantErrMsg:     "update role: empty field mask",
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
			wantErrMsg:     "update role: empty field mask",
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
			wantErrMsg:     "update role: field: CreateTime: invalid field mask",
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
			wantErrMsg:     "update role: field: Alice: invalid field mask",
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
			wantErrMsg:     "update role: missing role public id invalid parameter",
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
			wantErrMsg:  "update role: empty field mask",
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
				r := TestRole(t, conn, org.PublicId)
				r.Name = tt.args.name
				_, _, err := repo.UpdateRole(context.Background(), r, tt.args.fieldMaskPaths, tt.args.opt...)
				assert.NoError(err)
			}

			r := TestRole(t, conn, tt.newScopeId, tt.newGrpOpts...)

			updateRole := allocRole()
			updateRole.PublicId = r.PublicId
			if tt.args.PublicId != nil {
				updateRole.PublicId = *tt.args.PublicId
			}
			updateRole.ScopeId = tt.args.ScopeId
			updateRole.Name = tt.args.name
			updateRole.Description = tt.args.description

			roleAfterUpdate, updatedRows, err := repo.UpdateRole(context.Background(), &updateRole, tt.args.fieldMaskPaths, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				if tt.wantIsError != nil {
					assert.True(errors.Is(err, tt.wantIsError))
				}
				assert.Nil(roleAfterUpdate)
				assert.Equal(0, updatedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, r.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.Is(db.ErrRecordNotFound, err))
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			switch tt.name {
			case "valid-no-op":
				assert.Equal(r.UpdateTime, roleAfterUpdate.UpdateTime)
			default:
				assert.NotEqual(r.UpdateTime, roleAfterUpdate.UpdateTime)
			}
			foundRole, err := repo.LookupRole(context.Background(), r.PublicId)
			assert.NoError(err)
			assert.True(proto.Equal(roleAfterUpdate, foundRole))
			dbassert := dbassert.New(t, rw)
			if tt.args.name == "" {
				assert.Equal(foundRole.Name, "")
				dbassert.IsNull(foundRole, "name")
			}
			if tt.args.description == "" {
				assert.Equal(foundRole.Description, "")
				dbassert.IsNull(foundRole, "description")
			}
			err = db.TestVerifyOplog(t, rw, r.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_DeleteRole(t *testing.T) {
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
	org, _ := TestScopes(t, conn)

	type args struct {
		role *Role
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
				role: TestRole(t, conn, org.PublicId),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-public-id",
			args: args{
				role: func() *Role {
					g := allocRole()
					return &g
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "delete role: missing public id nil parameter",
		},
		{
			name: "not-found",
			args: args{
				role: func() *Role {
					id, err := newRoleId()
					require.NoError(t, err)
					r, err := NewRole(org.PublicId)
					r.PublicId = id
					require.NoError(t, err)
					return r
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "delete role: failed record not found for ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			deletedRows, err := repo.DeleteRole(context.Background(), tt.args.role.PublicId, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, tt.args.role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.Is(db.ErrRecordNotFound, err))
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundRole, err := repo.LookupRole(context.Background(), tt.args.role.PublicId)
			assert.Error(err)
			assert.Nil(foundRole)
			assert.True(errors.Is(err, db.ErrRecordNotFound))

			err = db.TestVerifyOplog(t, rw, tt.args.role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}
