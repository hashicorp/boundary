// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRepository_CreateGroup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	id := testId(t)

	org, proj := TestScopes(t, repo)

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
		wantIsError errors.Code
	}{
		{
			name: "valid-org",
			args: args{
				group: func() *Group {
					g, err := NewGroup(ctx, org.PublicId, WithName("valid-org"+id), WithDescription(id))
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
					g, err := NewGroup(ctx, proj.PublicId, WithName("valid-proj"+id), WithDescription(id))
					assert.NoError(t, err)
					return g
				}(),
			},
			wantErr: false,
		},
		{
			name: "bad-public-id",
			args: args{
				group: func() *Group {
					g, err := NewGroup(ctx, proj.PublicId, WithName("valid-proj"+id), WithDescription(id))
					assert.NoError(t, err)
					g.PublicId = id
					return g
				}(),
			},
			wantErrMsg:  "iam.(Repository).CreateGroup: public id not empty: parameter violation: error #100",
			wantIsError: errors.InvalidParameter,
			wantErr:     true,
		},
		{
			name: "nil-group",
			args: args{
				group: nil,
			},
			wantErr:     true,
			wantErrMsg:  "iam.(Repository).CreateGroup: missing group: parameter violation: error #10",
			wantIsError: errors.InvalidParameter,
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
			wantErrMsg:  "iam.(Repository).CreateGroup: missing group store: parameter violation: error #100",
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "bad-scope-id",
			args: args{
				group: func() *Group {
					g, err := NewGroup(ctx, id)
					assert.NoError(t, err)
					return g
				}(),
			},
			wantErr:     true,
			wantErrMsg:  "iam.(Repository).create: error getting metadata: iam.(Repository).stdMetadata: unable to get scope: iam.LookupScope: db.LookupWhere: record not found, search issue: error #1100",
			wantIsError: errors.RecordNotFound,
		},
		{
			name: "dup-name",
			args: args{
				group: func() *Group {
					g, err := NewGroup(ctx, org.PublicId, WithName("dup-name"+id), WithDescription(id))
					assert.NoError(t, err)
					return g
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
				group: func() *Group {
					g, err := NewGroup(ctx, proj.PublicId, WithName("dup-name-but-diff-scope"+id), WithDescription(id))
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
				dup, err := NewGroup(ctx, org.PublicId, tt.args.opt...)
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
				assert.True(errors.Match(errors.T(tt.wantIsError), err))
				return
			}
			assert.NoError(err)
			assert.NotNil(grp.CreateTime)
			assert.NotNil(grp.UpdateTime)

			foundGrp, _, err := repo.LookupGroup(context.Background(), grp.PublicId)
			assert.NoError(err)
			assert.True(proto.Equal(foundGrp, grp))

			err = db.TestVerifyOplog(t, rw, grp.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_UpdateGroup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	a := assert.New(t)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	id, err := uuid.GenerateUUID()
	a.NoError(err)

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
		newScopeId     string
		newGrpOpts     []Option
		args           args
		wantRowsUpdate int
		wantErr        bool
		wantErrMsg     string
		wantIsError    errors.Code
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
			wantErrMsg:     "record not found, search issue: error #1100",
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
			wantErrMsg:     "iam.(Repository).UpdateGroup: empty field mask: parameter violation: error #104",
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
			wantErrMsg:     "iam.(Repository).UpdateGroup: empty field mask: parameter violation: error #104",
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
			wantErrMsg:     "iam.(Repository).UpdateGroup: invalid field mask: CreateTime: parameter violation: error #103",
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
			wantErrMsg:     "iam.(Repository).UpdateGroup: invalid field mask: Alice: parameter violation: error #103",
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
			wantErrMsg:     "iam.(Repository).UpdateGroup: missing public id: parameter violation: error #100",
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
			wantErrMsg:  "iam.(Repository).UpdateGroup: empty field mask: parameter violation: error #104",
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
			wantErrMsg:  " already exists in scope " + org.PublicId,
			wantIsError: errors.NotUnique,
		},
		{
			name: "modified-scope",
			args: args{
				name:           "modified-scope" + id,
				fieldMaskPaths: []string{"ScopeId"},
				ScopeId:        proj.PublicId,
				opt:            []Option{WithSkipVetForWrite(true)},
			},
			newScopeId:   org.PublicId,
			wantErr:      true,
			wantErrMsg:   `iam.(Repository).update: db.DoTx: iam.(Repository).update: db.Update: immutable column: iam_group.scope_id: integrity violation: error #1003`,
			directUpdate: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tt.wantDup {
				g := TestGroup(t, conn, org.PublicId)
				g.Name = tt.args.name
				_, _, _, err := repo.UpdateGroup(context.Background(), g, g.Version, tt.args.fieldMaskPaths, tt.args.opt...)
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
			updateGrp.Version = u.Version

			var groupAfterUpdate *Group
			var updatedRows int
			var err error
			if tt.directUpdate {
				g := updateGrp.Clone()
				var resource any
				resource, updatedRows, err = repo.update(context.Background(), g.(*Group), updateGrp.Version, tt.args.fieldMaskPaths, nil, tt.args.opt...)
				if err == nil {
					groupAfterUpdate = resource.(*Group)
				}
			} else {
				groupAfterUpdate, _, updatedRows, err = repo.UpdateGroup(context.Background(), &updateGrp, updateGrp.Version, tt.args.fieldMaskPaths, tt.args.opt...)
			}
			if tt.wantErr {
				assert.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsError), err))
				assert.Nil(groupAfterUpdate)
				assert.Equal(0, updatedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, u.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.IsNotFoundError(err))
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			switch tt.name {
			case "valid-no-op":
				assert.Equal(u.UpdateTime, groupAfterUpdate.UpdateTime)
			default:
				assert.NotEqual(u.UpdateTime, groupAfterUpdate.UpdateTime)
			}
			foundGrp, _, err := repo.LookupGroup(context.Background(), u.PublicId)
			require.NoError(err)
			assert.True(proto.Equal(groupAfterUpdate, foundGrp))
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
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
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	a := assert.New(t)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)

	grpId, err := newGroupId(ctx)
	a.NoError(err)

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
			wantErrMsg:      "iam.(Repository).DeleteGroup: missing public id: parameter violation: error #100",
		},
		{
			name: "not-found",
			args: args{
				group: func() *Group {
					g, err := NewGroup(ctx, org.PublicId)
					g.PublicId = grpId
					a.NoError(err)
					return g
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "iam.(Repository).DeleteGroup: for group " + grpId + ": db.LookupById: record not found, search issue: error #1100",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			deletedRows, err := repo.DeleteGroup(ctx, tt.args.group.PublicId, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, tt.args.group.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.IsNotFoundError(err))
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundGroup, _, err := repo.LookupGroup(ctx, tt.args.group.PublicId)
			assert.NoError(err)
			assert.Nil(foundGroup)

			err = db.TestVerifyOplog(t, rw, tt.args.group.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_ListGroups(t *testing.T) {
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
			name:          "negative-limit",
			createCnt:     repo.defaultLimit + 1,
			createScopeId: org.PublicId,
			args: args{
				withScopeId: org.PublicId,
				opt:         []Option{WithLimit(-1)},
			},
			wantErr: true,
		},
		{
			name:          "no-limit-proj-group",
			createCnt:     repo.defaultLimit + 1,
			createScopeId: proj.PublicId,
			args: args{
				withScopeId: proj.PublicId,
				opt:         []Option{WithLimit(-1)},
			},
			wantErr: true,
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
			db.TestDeleteWhere(t, conn, func() any {
				i := allocGroup()
				return &i
			}(), "1=1")
			testGroups := []*Group{}
			for i := 0; i < tt.createCnt; i++ {
				testGroups = append(testGroups, TestGroup(t, conn, tt.createScopeId))
			}
			assert.Equal(tt.createCnt, len(testGroups))
			got, _, err := repo.listGroups(context.Background(), []string{tt.args.withScopeId}, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
		})
	}
}

func TestRepository_ListGroups_Multiple_Scopes(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)

	db.TestDeleteWhere(t, conn, func() any { g := allocGroup(); return &g }(), "1=1")

	const numPerScope = 10
	var total int
	for i := 0; i < numPerScope; i++ {
		TestGroup(t, conn, "global")
		total++
		TestGroup(t, conn, org.GetPublicId())
		total++
		TestGroup(t, conn, proj.GetPublicId())
		total++
	}

	got, ttime, err := repo.listGroups(context.Background(), []string{"global", org.GetPublicId(), proj.GetPublicId()})
	require.NoError(t, err)
	assert.Equal(t, total, len(got))

	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func TestRepository_ListMembers(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	const testLimit = 10
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper, WithLimit(testLimit))
	org, proj := TestScopes(t, repo)
	pg := TestGroup(t, conn, proj.PublicId)
	og := TestGroup(t, conn, org.PublicId)

	type args struct {
		withGroupId string
		opt         []Option
	}
	tests := []struct {
		name      string
		createCnt int
		args      args
		wantCnt   int
		wantErr   bool
	}{
		{
			name:      "no-limit-pg-group",
			createCnt: repo.defaultLimit + 1,
			args: args{
				withGroupId: pg.PublicId,
				opt:         []Option{WithLimit(-1)},
			},
			wantCnt: repo.defaultLimit + 1,
			wantErr: false,
		},
		{
			name:      "no-limit-org-group",
			createCnt: repo.defaultLimit + 1,
			args: args{
				withGroupId: og.PublicId,
				opt:         []Option{WithLimit(-1)},
			},
			wantCnt: repo.defaultLimit + 1,
			wantErr: false,
		},
		{
			name:      "default-limit",
			createCnt: repo.defaultLimit + 1,
			args: args{
				withGroupId: pg.PublicId,
			},
			wantCnt: repo.defaultLimit,
			wantErr: false,
		},
		{
			name:      "custom-limit",
			createCnt: repo.defaultLimit + 1,
			args: args{
				withGroupId: pg.PublicId,
				opt:         []Option{WithLimit(3)},
			},
			wantCnt: 3,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, func() any {
				i := allocGroupMember()
				return &i
			}(), "1=1")
			gm := []*GroupMemberUser{}
			for i := 0; i < tt.createCnt; i++ {
				u := TestUser(t, repo, org.PublicId)
				gm = append(gm, TestGroupMember(t, conn, tt.args.withGroupId, u.PublicId))
			}
			assert.Equal(tt.createCnt, len(gm))

			got, err := repo.ListGroupMembers(context.Background(), tt.args.withGroupId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
		})
	}
	t.Run("missing-id", func(t *testing.T) {
		require := require.New(t)
		got, err := repo.ListGroupMembers(context.Background(), "")
		require.Error(err)
		require.Nil(got)
		require.Truef(errors.Match(errors.T(errors.InvalidParameter), err), "unexpected error %s", err.Error())
	})
}

func TestRepository_AddGroupMembers(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	group := TestGroup(t, conn, proj.PublicId)
	createUsersFn := func() []string {
		results := []string{}
		for i := 0; i < 5; i++ {
			u := TestUser(t, repo, org.PublicId)
			results = append(results, u.PublicId)
		}
		return results
	}
	groupVersion := uint32(0)
	type args struct {
		groupId      string
		groupVersion *uint32
		userIds      []string
		opt          []Option
	}
	tests := []struct {
		name      string
		args      args
		wantErr   bool
		wantErrIs error
	}{
		{
			name: "valid-members",
			args: args{
				groupId: group.PublicId,
				userIds: createUsersFn(),
			},
			wantErr: false,
		},
		{
			name: "valid-next-version",
			args: args{
				groupId: group.PublicId,
				userIds: createUsersFn(),
			},
			wantErr: false,
		},
		{
			name: "bad-version",
			args: args{
				groupId:      group.PublicId,
				groupVersion: func() *uint32 { v := uint32(1000); return &v }(),
				userIds:      createUsersFn(),
			},
			wantErr: true,
		},
		{
			name: "zero-version",
			args: args{
				groupId:      group.PublicId,
				groupVersion: func() *uint32 { v := uint32(0); return &v }(),
				userIds:      createUsersFn(),
			},
			wantErr: true,
		},
		{
			name: "no-members",
			args: args{
				groupId: group.PublicId,
				userIds: nil,
			},
			wantErr: true,
		},
		{
			name: "recovery-user",
			args: args{
				groupId: group.PublicId,
				userIds: []string{globals.RecoveryUserId},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			var version uint32
			switch {
			case tt.args.groupVersion != nil:
				version = *tt.args.groupVersion
			default:
				groupVersion += 1
				version = groupVersion
			}
			gm := allocGroupMember()
			db.TestDeleteWhere(t, conn, &gm, "1=1")

			got, err := repo.AddGroupMembers(context.Background(), tt.args.groupId, version, tt.args.userIds, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrIs != nil {
					assert.Truef(errors.Is(err, tt.wantErrIs), "unexpected error %s", err.Error())
				}
				return
			}
			require.NoError(err)
			gotMembers := map[string]*GroupMember{}
			for _, m := range got {
				gotMembers[m.MemberId] = m
			}
			for _, id := range tt.args.userIds {
				assert.NotEmpty(gotMembers[id])
				u, _, err := repo.LookupUser(context.Background(), id)
				assert.NoError(err)
				assert.Equal(id, u.PublicId)
			}
			err = db.TestVerifyOplog(t, rw, group.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)

			foundMembers, err := repo.ListGroupMembers(context.Background(), group.PublicId)
			require.NoError(err)
			for _, m := range foundMembers {
				assert.NotEmpty(gotMembers[m.MemberId])
				assert.Equal(gotMembers[m.MemberId].GetGroupId(), m.GroupId)
			}
		})
	}
}

func TestRepository_DeleteGroupMembers(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)

	type args struct {
		group           *Group
		groupIdOverride *string
		groupVersion    uint32
		createUserCnt   int
		deleteUserCnt   int
		opt             []Option
	}
	tests := []struct {
		name            string
		args            args
		wantRowsDeleted int
		wantErr         bool
		wantIsErr       errors.Code
	}{
		{
			name: "valid",
			args: args{
				group:         TestGroup(t, conn, org.PublicId),
				createUserCnt: 5,
				deleteUserCnt: 5,
				groupVersion:  2,
			},
			wantRowsDeleted: 5,
			wantErr:         false,
		},
		{
			name: "valid-keeping-some",
			args: args{
				group:         TestGroup(t, conn, org.PublicId),
				createUserCnt: 5,
				deleteUserCnt: 2,
				groupVersion:  2,
			},
			wantRowsDeleted: 2,
			wantErr:         false,
		},
		{
			name: "not-found",
			args: args{
				group:           TestGroup(t, conn, org.PublicId),
				groupVersion:    2,
				groupIdOverride: func() *string { id := testId(t); return &id }(),
				createUserCnt:   5,
				deleteUserCnt:   5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
		},
		{
			name: "missing-group-id",
			args: args{
				group:           TestGroup(t, conn, org.PublicId),
				groupVersion:    2,
				groupIdOverride: func() *string { id := ""; return &id }(),
				createUserCnt:   5,
				deleteUserCnt:   5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsErr:       errors.InvalidParameter,
		},
		{
			name: "bad-version",
			args: args{
				group:         TestGroup(t, conn, org.PublicId),
				createUserCnt: 5,
				deleteUserCnt: 5,
				groupVersion:  10000,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
		},
		{
			name: "zero-version",
			args: args{
				group:         TestGroup(t, conn, org.PublicId),
				createUserCnt: 5,
				deleteUserCnt: 5,
				groupVersion:  0,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsErr:       errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			userIds := make([]string, 0, tt.args.createUserCnt)
			for i := 0; i < tt.args.createUserCnt; i++ {
				u := TestUser(t, repo, org.PublicId)
				userIds = append(userIds, u.PublicId)
			}
			members, err := repo.AddGroupMembers(context.Background(), tt.args.group.PublicId, 1, userIds, tt.args.opt...)
			require.NoError(err)
			assert.Equal(tt.args.createUserCnt, len(members))

			deleteUserIds := make([]string, 0, tt.args.deleteUserCnt)
			for i := 0; i < tt.args.deleteUserCnt; i++ {
				deleteUserIds = append(deleteUserIds, userIds[i])
			}
			var groupId string
			switch {
			case tt.args.groupIdOverride != nil:
				groupId = *tt.args.groupIdOverride
			default:
				groupId = tt.args.group.PublicId
			}
			deletedRows, err := repo.DeleteGroupMembers(context.Background(), groupId, tt.args.groupVersion, deleteUserIds, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "unexpected error %s", err.Error())
				err = db.TestVerifyOplog(t, rw, tt.args.group.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.Match(errors.T(errors.RecordNotFound), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)

			err = db.TestVerifyOplog(t, rw, tt.args.group.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_SetGroupMembers(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)

	org, proj := TestScopes(t, repo)
	testUser := TestUser(t, repo, org.PublicId)

	createUsersFn := func() []string {
		results := []string{}
		for i := 0; i < 5; i++ {
			u := TestUser(t, repo, org.PublicId)
			results = append(results, u.PublicId)
		}
		return results
	}
	setupFn := func(groupId string) []string {
		users := createUsersFn()
		_, err := repo.AddGroupMembers(context.Background(), groupId, 1, users)
		require.NoError(t, err)
		return users
	}
	type args struct {
		group          *Group
		groupVersion   uint32
		userIds        []string
		addToOrigUsers bool
		opt            []Option
	}
	tests := []struct {
		name             string
		setup            func(string) []string
		args             args
		wantAffectedRows int
		wantErr          bool
	}{
		{
			name:  "clear",
			setup: setupFn,
			args: args{
				group:        TestGroup(t, conn, proj.PublicId),
				groupVersion: 2, // yep, since setupFn will increment it to 2
				userIds:      []string{},
			},
			wantErr:          false,
			wantAffectedRows: 5,
		},
		{
			name:  "no change",
			setup: setupFn,
			args: args{
				group:          TestGroup(t, conn, proj.PublicId),
				groupVersion:   2, // yep, since setupFn will increment it to 2
				userIds:        []string{},
				addToOrigUsers: true,
			},
			wantErr:          false,
			wantAffectedRows: 0,
		},
		{
			name:  "add users",
			setup: setupFn,
			args: args{
				group:          TestGroup(t, conn, proj.PublicId),
				groupVersion:   2, // yep, since setupFn will increment it to 2
				userIds:        []string{testUser.PublicId},
				addToOrigUsers: true,
			},
			wantErr:          false,
			wantAffectedRows: 1,
		},
		{
			name:  "remove existing and add users",
			setup: setupFn,
			args: args{
				group:          TestGroup(t, conn, proj.PublicId),
				groupVersion:   2, // yep, since setupFn will increment it to 2
				userIds:        []string{testUser.PublicId},
				addToOrigUsers: false,
			},
			wantErr:          false,
			wantAffectedRows: 6,
		},
		{
			name:  "bad version",
			setup: setupFn,
			args: args{
				group:          TestGroup(t, conn, proj.PublicId),
				groupVersion:   1000,
				userIds:        []string{testUser.PublicId},
				addToOrigUsers: true,
			},
			wantErr:          true,
			wantAffectedRows: 0,
		},
		{
			name:  "zero version",
			setup: setupFn,
			args: args{
				group:          TestGroup(t, conn, proj.PublicId),
				groupVersion:   0,
				userIds:        []string{testUser.PublicId},
				addToOrigUsers: true,
			},
			wantErr:          true,
			wantAffectedRows: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var origUsers []string
			if tt.setup != nil {
				origUsers = tt.setup(tt.args.group.PublicId)
			}
			setUsers := tt.args.userIds
			if tt.args.addToOrigUsers {
				setUsers = append(setUsers, origUsers...)
			}

			got, affectedRows, err := repo.SetGroupMembers(context.Background(), tt.args.group.PublicId, tt.args.groupVersion, setUsers, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantAffectedRows, affectedRows)
			var gotIds []string
			for _, r := range got {
				gotIds = append(gotIds, r.GetMemberId())
			}
			var wantIds []string
			wantIds = append(wantIds, tt.args.userIds...)
			sort.Strings(wantIds)
			sort.Strings(gotIds)
			assert.Equal(wantIds, wantIds)
		})
	}
}

func Test_listGroupDeletedIds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)
	r := TestGroup(t, conn, org.GetPublicId())

	// Expect no entries at the start
	deletedIds, ttime, err := repo.listGroupDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Delete a group
	_, err = repo.DeleteGroup(ctx, r.GetPublicId())
	require.NoError(t, err)

	// Expect a single entry
	deletedIds, ttime, err = repo.listGroupDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Equal(t, []string{r.GetPublicId()}, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = repo.listGroupDeletedIds(ctx, time.Now())
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func Test_estimatedGroupCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	// Check total entries at start, expect 0
	numItems, err := repo.estimatedGroupCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	iamRepo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, iamRepo)
	// Create a group, expect 1 entry
	u := TestGroup(t, conn, org.GetPublicId())

	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems, err = repo.estimatedGroupCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, numItems)

	// Delete the group, expect 3 again
	_, err = repo.DeleteGroup(ctx, u.GetPublicId())
	require.NoError(t, err)

	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	numItems, err = repo.estimatedGroupCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)
}
