// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package iam

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRepository_CreateRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	id := testId(t)

	org, proj := TestScopes(t, repo)

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
		wantIsError errors.Code
	}{
		{
			name: "valid-org",
			args: args{
				role: func() *Role {
					r, err := NewRole(ctx, org.PublicId, WithName("valid-org"+id), WithDescription(id))
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
					r, err := NewRole(ctx, proj.PublicId, WithName("valid-proj"+id), WithDescription(id))
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
					r, err := NewRole(ctx, proj.PublicId, WithName("valid-proj"+id), WithDescription(id))
					assert.NoError(t, err)
					r.PublicId = id
					return r
				}(),
			},
			wantErrMsg:  "am.(Repository).CreateRole: public id not empty: parameter violation: error #100",
			wantIsError: errors.InvalidParameter,
			wantErr:     true,
		},
		{
			name: "nil-role",
			args: args{
				role: nil,
			},
			wantErr:     true,
			wantErrMsg:  "iam.(Repository).CreateRole: missing role: parameter violation: error #100",
			wantIsError: errors.InvalidParameter,
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
			wantErrMsg:  "iam.(Repository).CreateRole: missing role store: parameter violation: error #100",
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "bad-scope-id",
			args: args{
				role: func() *Role {
					r, err := NewRole(ctx, id)
					assert.NoError(t, err)
					return r
				}(),
			},
			wantErr:     true,
			wantErrMsg:  "iam.(Repository).create: error getting metadata: iam.(Repository).stdMetadata: unable to get scope: iam.LookupScope: db.LookupWhere: record not found, search issue: error #1100",
			wantIsError: errors.RecordNotFound,
		},
		{
			name: "dup-name",
			args: args{
				role: func() *Role {
					r, err := NewRole(ctx, org.PublicId, WithName("dup-name"+id), WithDescription(id))
					assert.NoError(t, err)
					return r
				}(),
				opt: []Option{WithName("dup-name" + id)},
			},
			wantDup:     true,
			wantErr:     true,
			wantErrMsg:  "already exists in scope ",
			wantIsError: errors.NotUnique,
		},
		{
			name: "dup-name-but-diff-scope",
			args: args{
				role: func() *Role {
					r, err := NewRole(ctx, proj.PublicId, WithName("dup-name-but-diff-scope"+id), WithDescription(id))
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
				dup, err := NewRole(ctx, org.PublicId, tt.args.opt...)
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
				assert.True(errors.Match(errors.T(tt.wantIsError), err))
				return
			}
			assert.NoError(err)
			assert.NotNil(grp.CreateTime)
			assert.NotNil(grp.UpdateTime)

			foundGrp, _, _, err := repo.LookupRole(context.Background(), grp.PublicId)
			assert.NoError(err)
			assert.True(proto.Equal(foundGrp, grp))

			err = db.TestVerifyOplog(t, rw, grp.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_UpdateRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	id, err := uuid.GenerateUUID()
	require.NoError(t, err)

	org, proj := TestScopes(t, repo)
	u := TestUser(t, repo, org.GetPublicId())

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
		newRoleOpts    []Option
		args           args
		wantRowsUpdate int
		wantErr        bool
		wantErrMsg     string
		wantIsError    errors.Code
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
			newRoleOpts:    []Option{WithName("valid-no-op" + id)},
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
			wantErrMsg:     "error #1100",
			wantIsError:    errors.RecordNotFound,
		},
		{
			name: "null-name",
			args: args{
				name:           "",
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
			},
			newScopeId:     org.PublicId,
			newRoleOpts:    []Option{WithName("null-name" + id)},
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
			newRoleOpts:    []Option{WithDescription("null-description" + id)},
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
			wantErrMsg:     "iam.(Repository).UpdateRole: empty field mask, parameter violation: error #104",
			wantIsError:    errors.EmptyFieldMask,
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
			wantErrMsg:     "iam.(Repository).UpdateRole: empty field mask, parameter violation: error #104",
			wantIsError:    errors.EmptyFieldMask,
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
			wantErrMsg:     "iam.(Repository).UpdateRole: invalid field mask: CreateTime: parameter violation: error #103",
			wantIsError:    errors.InvalidFieldMask,
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
			wantErrMsg:     "iam.(Repository).UpdateRole: invalid field mask: Alice: parameter violation: error #103",
			wantIsError:    errors.InvalidFieldMask,
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
			wantErrMsg:     "iam.(Repository).UpdateRole: missing public id: parameter violation: error #100",
			wantIsError:    errors.InvalidParameter,
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
			wantErrMsg:  "iam.(Repository).UpdateRole: empty field mask, parameter violation: error #104",
			wantIsError: errors.EmptyFieldMask,
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
			newRoleOpts:    []Option{WithName("dup-name-in-diff-scope-pre-update" + id)},
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
			wantErrMsg:  " already exists in org " + org.PublicId,
			wantIsError: errors.NotUnique,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			if tt.wantDup {
				r := TestRole(t, conn, org.PublicId)
				_ = TestUserRole(t, conn, r.GetPublicId(), u.GetPublicId())
				_ = TestRoleGrant(t, conn, r.GetPublicId(), "id=*;type=*;actions=*")
				r.Name = tt.args.name
				_, _, _, _, err := repo.UpdateRole(context.Background(), r, r.Version, tt.args.fieldMaskPaths, tt.args.opt...)
				assert.NoError(err)
			}

			r := TestRole(t, conn, tt.newScopeId, tt.newRoleOpts...)
			ur := TestUserRole(t, conn, r.GetPublicId(), u.GetPublicId())
			princRole := &PrincipalRole{PrincipalRoleView: &store.PrincipalRoleView{
				Type:              UserRoleType.String(),
				CreateTime:        ur.CreateTime,
				RoleId:            ur.RoleId,
				PrincipalId:       ur.PrincipalId,
				PrincipalScopeId:  org.GetPublicId(),
				ScopedPrincipalId: ur.PrincipalId,
				RoleScopeId:       org.GetPublicId(),
			}}
			if tt.newScopeId != org.GetPublicId() {
				// If the project is in a different scope from the created user we need to update the
				// scope specific fields.
				princRole.RoleScopeId = tt.newScopeId
				princRole.ScopedPrincipalId = fmt.Sprintf("%s:%s", org.PublicId, ur.PrincipalId)
			}
			rGrant := TestRoleGrant(t, conn, r.GetPublicId(), "id=*;type=*;actions=*")

			updateRole := allocRole()
			updateRole.PublicId = r.PublicId
			if tt.args.PublicId != nil {
				updateRole.PublicId = *tt.args.PublicId
			}
			updateRole.ScopeId = tt.args.ScopeId
			updateRole.Name = tt.args.name
			updateRole.Description = tt.args.description

			roleAfterUpdate, principals, grants, updatedRows, err := repo.UpdateRole(context.Background(), &updateRole, r.Version, tt.args.fieldMaskPaths, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsError), err))
				assert.Nil(roleAfterUpdate)
				assert.Equal(0, updatedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, r.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.IsNotFoundError(err))
				return
			}
			require.NoError(err)
			require.NotNil(roleAfterUpdate)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			assert.Equal([]*PrincipalRole{princRole}, principals)
			assert.Equal([]*RoleGrant{rGrant}, grants)
			switch tt.name {
			case "valid-no-op":
				assert.Equal(r.UpdateTime, roleAfterUpdate.UpdateTime)
			default:
				assert.NotEqual(r.UpdateTime, roleAfterUpdate.UpdateTime)
			}
			foundRole, _, _, err := repo.LookupRole(context.Background(), r.PublicId)
			assert.NoError(err)
			assert.True(proto.Equal(roleAfterUpdate, foundRole))
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
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
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)

	roleId, err := newRoleId(ctx)
	require.NoError(t, err)

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
					r := allocRole()
					return &r
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "iam.(Repository).DeleteRole: missing public id: parameter violation: error #100",
		},

		{
			name: "not-found",
			args: args{
				role: func() *Role {
					r, err := NewRole(ctx, org.PublicId)
					r.PublicId = roleId
					require.NoError(t, err)
					return r
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "iam.(Repository).DeleteRole: failed for " + roleId + ": db.LookupById: record not found, search issue: error #1100",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			deletedRows, err := repo.DeleteRole(ctx, tt.args.role.PublicId, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, tt.args.role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.IsNotFoundError(err))
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundRole, _, _, err := repo.LookupRole(ctx, tt.args.role.PublicId)
			assert.NoError(err)
			assert.Nil(foundRole)

			err = db.TestVerifyOplog(t, rw, tt.args.role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_ListRoles(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	const testLimit = 10
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper, WithLimit(testLimit))
	org, proj := TestScopes(t, repo)

	type args struct {
		withScopeId string
		opt         []Option
	}
	tests := []struct {
		name          string
		createCnt     int
		createScopeId string
		args          args
		wantCnt       int
		wantErr       bool
	}{
		{
			name:          "no-limit",
			createCnt:     repo.defaultLimit + 1,
			createScopeId: org.PublicId,
			args: args{
				withScopeId: org.PublicId,
				opt:         []Option{WithLimit(-1)},
			},
			wantCnt: repo.defaultLimit + 1,
			wantErr: false,
		},
		{
			name:          "no-limit-proj-role",
			createCnt:     repo.defaultLimit + 1,
			createScopeId: proj.PublicId,
			args: args{
				withScopeId: proj.PublicId,
				opt:         []Option{WithLimit(-1)},
			},
			wantCnt: repo.defaultLimit + 1,
			wantErr: false,
		},
		{
			name:          "default-limit",
			createCnt:     repo.defaultLimit + 1,
			createScopeId: org.PublicId,
			args: args{
				withScopeId: org.PublicId,
			},
			wantCnt: repo.defaultLimit,
			wantErr: false,
		},
		{
			name:          "custom-limit",
			createCnt:     repo.defaultLimit + 1,
			createScopeId: org.PublicId,
			args: args{
				withScopeId: org.PublicId,
				opt:         []Option{WithLimit(3)},
			},
			wantCnt: 3,
			wantErr: false,
		},
		{
			name:          "bad-org",
			createCnt:     1,
			createScopeId: org.PublicId,
			args: args{
				withScopeId: "bad-id",
			},
			wantCnt: 0,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, func() any { r := allocRole(); return &r }(), "1=1")
			testRoles := []*Role{}
			for i := 0; i < tt.createCnt; i++ {
				testRoles = append(testRoles, TestRole(t, conn, tt.createScopeId))
			}
			assert.Equal(tt.createCnt, len(testRoles))
			got, err := repo.ListRoles(context.Background(), []string{tt.args.withScopeId}, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
		})
	}
}

func TestRepository_ListRoles_Multiple_Scopes(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)

	db.TestDeleteWhere(t, conn, func() any { i := allocRole(); return &i }(), "1=1")

	const numPerScope = 10
	var total int
	for i := 0; i < numPerScope; i++ {
		TestRole(t, conn, "global")
		total++
		TestRole(t, conn, org.GetPublicId())
		total++
		TestRole(t, conn, proj.GetPublicId())
		total++
	}

	got, err := repo.ListRoles(context.Background(), []string{"global", org.GetPublicId(), proj.GetPublicId()})
	require.NoError(t, err)
	assert.Equal(t, total, len(got))
}
