// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func Test_NewGroupMember(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	org2, _ := TestScopes(t, repo)

	orgGroup := TestGroup(t, conn, org.PublicId)
	projGroup := TestGroup(t, conn, proj.PublicId)
	user := TestUser(t, repo, org.PublicId)
	user2 := TestUser(t, repo, org2.PublicId)

	type args struct {
		groupId string
		userId  string
		opt     []Option
	}
	tests := []struct {
		name      string
		args      args
		want      *GroupMemberUser
		wantErr   bool
		wantIsErr errors.Code
	}{
		{
			name: "valid-org",
			args: args{
				groupId: orgGroup.PublicId,
				userId:  user.PublicId,
			},
			want: func() *GroupMemberUser {
				gm := allocGroupMember()
				gm.GroupId = orgGroup.PublicId
				gm.MemberId = user.PublicId
				return &gm
			}(),
		},
		{
			name: "valid-proj",
			args: args{
				groupId: projGroup.PublicId,
				userId:  user.PublicId,
			},
			want: func() *GroupMemberUser {
				gm := allocGroupMember()
				gm.GroupId = projGroup.PublicId
				gm.MemberId = user.PublicId
				return &gm
			}(),
		},
		{
			name: "cross-org",
			args: args{
				groupId: orgGroup.PublicId,
				userId:  user2.PublicId,
			},
			want: func() *GroupMemberUser {
				gm := allocGroupMember()
				gm.GroupId = orgGroup.PublicId
				gm.MemberId = user2.PublicId
				return &gm
			}(),
		},
		{
			name: "missing-group",
			args: args{
				userId: user.PublicId,
			},
			want:      nil,
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "missing-user",
			args: args{
				groupId: projGroup.PublicId,
			},
			want:      nil,
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := NewGroupMemberUser(ctx, tt.args.groupId, tt.args.userId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
		})
	}
}

func Test_GroupMemberCreate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	type args struct {
		gm *GroupMemberUser
	}
	tests := []struct {
		name       string
		args       args
		wantDup    bool
		wantErr    bool
		wantErrMsg string
		wantIsErr  errors.Code
	}{
		{
			name: "valid-with-org",
			args: args{
				gm: func() *GroupMemberUser {
					g := TestGroup(t, conn, org.PublicId)
					u := TestUser(t, repo, org.PublicId)
					gm, err := NewGroupMemberUser(ctx, g.PublicId, u.PublicId)
					require.NoError(t, err)
					return gm
				}(),
			},
			wantErr: false,
		},
		{
			name: "valid-with-proj",
			args: args{
				gm: func() *GroupMemberUser {
					g := TestGroup(t, conn, proj.PublicId)
					u := TestUser(t, repo, org.PublicId)
					gm, err := NewGroupMemberUser(ctx, g.PublicId, u.PublicId)
					require.NoError(t, err)
					return gm
				}(),
			},
			wantErr: false,
		},
		{
			name: "bad-group-id",
			args: args{
				gm: func() *GroupMemberUser {
					id := testId(t)
					u := TestUser(t, repo, org.PublicId)
					gm, err := NewGroupMemberUser(ctx, id, u.PublicId)
					require.NoError(t, err)
					return gm
				}(),
			},
			wantErr:    true,
			wantErrMsg: `db.Create: insert or update on table "iam_group_member_user" violates foreign key constraint`,
		},
		{
			name: "bad-user-id",
			args: args{
				gm: func() *GroupMemberUser {
					id := testId(t)
					g := TestGroup(t, conn, proj.PublicId)
					gm, err := NewGroupMemberUser(ctx, g.PublicId, id)
					require.NoError(t, err)
					return gm
				}(),
			},
			wantErr:    true,
			wantErrMsg: `integrity violation: error #1003`,
		},
		{
			name: "missing-group-id",
			args: args{
				gm: func() *GroupMemberUser {
					u := TestUser(t, repo, org.PublicId)
					return &GroupMemberUser{
						GroupMemberUser: &store.GroupMemberUser{
							GroupId:  "",
							MemberId: u.PublicId,
						},
					}
				}(),
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "missing-user-id",
			args: args{
				gm: func() *GroupMemberUser {
					g := TestGroup(t, conn, org.PublicId)
					return &GroupMemberUser{
						GroupMemberUser: &store.GroupMemberUser{
							GroupId:  g.PublicId,
							MemberId: "",
						},
					}
				}(),
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "dup-at-org",
			args: args{
				gm: func() *GroupMemberUser {
					g := TestGroup(t, conn, org.PublicId)
					u := TestUser(t, repo, org.PublicId)
					gm, err := NewGroupMemberUser(ctx, g.PublicId, u.PublicId)
					require.NoError(t, err)
					return gm
				}(),
			},
			wantDup:    true,
			wantErr:    true,
			wantErrMsg: `db.Create: duplicate key value violates unique constraint "iam_group_member_user_pkey"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			w := db.New(conn)
			if tt.wantDup {
				gm := tt.args.gm.Clone().(*GroupMemberUser)
				err := w.Create(context.Background(), gm)
				require.NoError(err)
			}
			gm := tt.args.gm.Clone().(*GroupMemberUser)
			err := w.Create(context.Background(), gm)
			if tt.wantErr {
				require.Error(err)
				assert.Contains(err.Error(), tt.wantErrMsg)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			assert.NoError(err)

			found := allocGroupMember()
			err = w.LookupWhere(context.Background(), &found, "group_id = ? and member_id = ?", []any{gm.GroupId, gm.MemberId})
			require.NoError(err)
			assert.Empty(cmp.Diff(gm, &found, protocmp.Transform()))
		})
	}
}

func Test_GroupMemberUpdate(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)
	rw := db.New(conn)

	t.Run("updates not allowed", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		g := TestGroup(t, conn, org.PublicId)
		u := TestUser(t, repo, org.PublicId)
		u2 := TestUser(t, repo, org.PublicId)
		gm := TestGroupMember(t, conn, g.PublicId, u.PublicId)
		updateGrpMember := gm.Clone().(*GroupMemberUser)
		updateGrpMember.MemberId = u2.PublicId
		updatedRows, err := rw.Update(context.Background(), updateGrpMember, []string{"MemberId"}, nil)
		require.Error(err)
		assert.Equal(0, updatedRows)
	})
}

func Test_GroupMemberDelete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	rw := db.New(conn)
	id := testId(t)
	org, _ := TestScopes(t, repo)
	u := TestUser(t, repo, org.PublicId)
	g := TestGroup(t, conn, org.PublicId)

	tests := []struct {
		name            string
		gm              *GroupMemberUser
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			gm:              TestGroupMember(t, conn, g.PublicId, u.PublicId),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:            "bad-id",
			gm:              func() *GroupMemberUser { gm := allocGroupMember(); gm.MemberId = id; gm.GroupId = id; return &gm }(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deleteGroup := allocGroupMember()
			deleteGroup.GroupId = tt.gm.GetGroupId()
			deleteGroup.MemberId = tt.gm.GetMemberId()
			deletedRows, err := rw.Delete(context.Background(), &deleteGroup)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			if tt.wantRowsDeleted == 0 {
				assert.Equal(tt.wantRowsDeleted, deletedRows)
				return
			}
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			found := allocGroupMember()
			err = rw.LookupWhere(context.Background(), &found, "group_id = ? and member_id = ?", []any{tt.gm.GetGroupId(), tt.gm.GetMemberId()})
			require.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestGroupMember_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	user := TestUser(t, repo, org.PublicId)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		group := TestGroup(t, conn, org.PublicId)
		gm := TestGroupMember(t, conn, group.PublicId, user.PublicId)
		cp := gm.Clone()
		assert.True(proto.Equal(cp.(*GroupMemberUser).GroupMemberUser, gm.GroupMemberUser))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		g := TestGroup(t, conn, org.PublicId)
		g2 := TestGroup(t, conn, proj.PublicId)
		gm := TestGroupMember(t, conn, g.PublicId, user.PublicId)
		gm2 := TestGroupMember(t, conn, g2.PublicId, user.PublicId)
		cp := gm.Clone()
		assert.True(!proto.Equal(cp.(*GroupMemberUser).GroupMemberUser, gm2.GroupMemberUser))
	})
}

func TestGroupMember_SetTableName(t *testing.T) {
	defaultTableName := groupMemberViewDefaultTableName
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-name",
			initialName: "",
			setNameTo:   "new-name",
			want:        "new-name",
		},
		{
			name:        "reset to default",
			initialName: "initial",
			setNameTo:   "",
			want:        defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := &GroupMember{
				GroupMemberView: &store.GroupMemberView{},
			}
			require.Equal(defaultTableName, def.TableName())
			s := &GroupMember{
				GroupMemberView: &store.GroupMemberView{},
				tableName:       tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}

func TestGroupMemberUser_SetTableName(t *testing.T) {
	defaultTableName := groupMemberUserDefaultTable
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-name",
			initialName: "",
			setNameTo:   "new-name",
			want:        "new-name",
		},
		{
			name:        "reset to default",
			initialName: "initial",
			setNameTo:   "",
			want:        defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := allocGroupMember()
			require.Equal(defaultTableName, def.TableName())
			s := &GroupMemberUser{
				GroupMemberUser: &store.GroupMemberUser{},
				tableName:       tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
