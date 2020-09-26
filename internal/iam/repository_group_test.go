package iam

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRepository_CreateGroup(t *testing.T) {
	t.Parallel()
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
			name: "bad-public-id",
			args: args{
				group: func() *Group {
					g, err := NewGroup(proj.PublicId, WithName("valid-proj"+id), WithDescription(id))
					assert.NoError(t, err)
					g.PublicId = id
					return g
				}(),
			},
			wantErrMsg:  "create group: public id not empty: invalid parameter",
			wantIsError: db.ErrInvalidParameter,
			wantErr:     true,
		},
		{
			name: "nil-group",
			args: args{
				group: nil,
			},
			wantErr:     true,
			wantErrMsg:  "create group: missing group invalid parameter",
			wantIsError: db.ErrInvalidParameter,
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
			wantErrMsg:  "create group: missing group store invalid parameter",
			wantIsError: db.ErrInvalidParameter,
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
		wantIsError    error
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
			wantErrMsg:     "update group: update: lookup after write: record not found for 1",
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
			wantErrMsg:  " already exists in org " + org.PublicId,
			wantIsError: db.ErrNotUnique,
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
			wantErrMsg:   `update: failed: pq: immutable column: iam_group.scope_id`,
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
				var resource interface{}
				resource, updatedRows, err = repo.update(context.Background(), g.(*Group), updateGrp.Version, tt.args.fieldMaskPaths, nil, tt.args.opt...)
				if err == nil {
					groupAfterUpdate = resource.(*Group)
				}
			} else {
				groupAfterUpdate, _, updatedRows, err = repo.UpdateGroup(context.Background(), &updateGrp, updateGrp.Version, tt.args.fieldMaskPaths, tt.args.opt...)
			}
			if tt.wantErr {
				assert.Error(err)
				if tt.wantIsError != nil {
					assert.True(errors.Is(err, tt.wantIsError))
				}
				assert.Nil(groupAfterUpdate)
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
				assert.Equal(u.UpdateTime, groupAfterUpdate.UpdateTime)
			default:
				assert.NotEqual(u.UpdateTime, groupAfterUpdate.UpdateTime)
			}
			foundGrp, _, err := repo.LookupGroup(context.Background(), u.PublicId)
			require.NoError(err)
			assert.True(proto.Equal(groupAfterUpdate, foundGrp))
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
	conn, _ := db.TestSetup(t, "postgres")
	a := assert.New(t)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)

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
			wantErrMsg:      "delete group: missing public id invalid parameter",
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
			foundGroup, _, err := repo.LookupGroup(context.Background(), tt.args.group.PublicId)
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
			name:          "no-limit-proj-group",
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
			require.NoError(conn.Where("1=1").Delete(allocGroup()).Error)
			testGroups := []*Group{}
			for i := 0; i < tt.createCnt; i++ {
				testGroups = append(testGroups, TestGroup(t, conn, tt.createScopeId))
			}
			assert.Equal(tt.createCnt, len(testGroups))
			got, err := repo.ListGroups(context.Background(), tt.args.withScopeId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
		})
	}
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
			require.NoError(conn.Where("1=1").Delete(allocGroupMember()).Error)
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
		require.Truef(errors.Is(err, db.ErrInvalidParameter), "unexpected error %s", err.Error())

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
				userIds: []string{"u_recovery"},
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
			require.NoError(conn.Where("1=1").Delete(allocGroupMember()).Error)
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
		wantIsErr       error
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
			wantIsErr:       db.ErrInvalidParameter,
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
			wantIsErr:       db.ErrInvalidParameter,
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
				if tt.wantIsErr != nil {
					assert.Truef(errors.Is(err, tt.wantIsErr), "unexpected error %s", err.Error())
				}
				err = db.TestVerifyOplog(t, rw, tt.args.group.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.Is(db.ErrRecordNotFound, err))
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
