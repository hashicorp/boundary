package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func Test_NewGroupMember(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	org, proj := TestScopes(t, conn)
	orgGroup := TestGroup(t, conn, org.PublicId)
	projGroup := TestGroup(t, conn, proj.PublicId)
	user := TestUser(t, conn, org.PublicId)

	type args struct {
		groupId string
		userId  string
		opt     []Option
	}
	tests := []struct {
		name      string
		args      args
		want      *GroupMember
		wantErr   bool
		wantIsErr error
	}{
		{
			name: "valid-org",
			args: args{
				groupId: orgGroup.PublicId,
				userId:  user.PublicId,
			},
			want: func() *GroupMember {
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
			want: func() *GroupMember {
				gm := allocGroupMember()
				gm.GroupId = projGroup.PublicId
				gm.MemberId = user.PublicId
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
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "missing-user",
			args: args{
				groupId: projGroup.PublicId,
			},
			want:      nil,
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := NewGroupMember(tt.args.groupId, tt.args.userId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Is(err, tt.wantIsErr))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
		})
	}
}

func Test_GroupMemberCreate(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	org, proj := TestScopes(t, conn)
	type args struct {
		gm *GroupMember
	}
	tests := []struct {
		name       string
		args       args
		wantDup    bool
		wantErr    bool
		wantErrMsg string
		wantIsErr  error
	}{
		{
			name: "valid-with-org",
			args: args{
				gm: func() *GroupMember {
					g := TestGroup(t, conn, org.PublicId)
					u := TestUser(t, conn, org.PublicId)
					gm, err := NewGroupMember(g.PublicId, u.PublicId)
					require.NoError(t, err)
					return gm
				}(),
			},
			wantErr: false,
		},
		{
			name: "valid-with-proj",
			args: args{
				gm: func() *GroupMember {
					g := TestGroup(t, conn, proj.PublicId)
					u := TestUser(t, conn, org.PublicId)
					gm, err := NewGroupMember(g.PublicId, u.PublicId)
					require.NoError(t, err)
					return gm
				}(),
			},
			wantErr: false,
		},
		{
			name: "bad-group-id",
			args: args{
				gm: func() *GroupMember {
					id := testId(t)
					u := TestUser(t, conn, org.PublicId)
					gm, err := NewGroupMember(id, u.PublicId)
					require.NoError(t, err)
					return gm
				}(),
			},
			wantErr:    true,
			wantErrMsg: `create: failed pq: insert or update on table "iam_group_member" violates foreign key constraint`,
		},
		{
			name: "bad-user-id",
			args: args{
				gm: func() *GroupMember {
					id := testId(t)
					g := TestGroup(t, conn, proj.PublicId)
					gm, err := NewGroupMember(g.PublicId, id)
					require.NoError(t, err)
					return gm
				}(),
			},
			wantErr:    true,
			wantErrMsg: `create: failed pq: insert or update on table "iam_group_member" violates foreign key constraint`,
		},
		{
			name: "missing-group-id",
			args: args{
				gm: func() *GroupMember {
					u := TestUser(t, conn, org.PublicId)
					return &GroupMember{
						GroupMember: &store.GroupMember{
							GroupId:  "",
							MemberId: u.PublicId,
						},
					}
				}(),
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "missing-user-id",
			args: args{
				gm: func() *GroupMember {
					g := TestGroup(t, conn, org.PublicId)
					return &GroupMember{
						GroupMember: &store.GroupMember{
							GroupId:  g.PublicId,
							MemberId: "",
						},
					}
				}(),
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "dup-at-org",
			args: args{
				gm: func() *GroupMember {
					g := TestGroup(t, conn, org.PublicId)
					u := TestUser(t, conn, org.PublicId)
					gm, err := NewGroupMember(g.PublicId, u.PublicId)
					require.NoError(t, err)
					return gm
				}(),
			},
			wantDup:    true,
			wantErr:    true,
			wantErrMsg: `create: failed pq: duplicate key value violates unique constraint "iam_group_member_pkey"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			w := db.New(conn)
			if tt.wantDup {
				gm := tt.args.gm.Clone().(*GroupMember)
				err := w.Create(context.Background(), gm)
				require.NoError(err)
			}
			gm := tt.args.gm.Clone().(*GroupMember)
			err := w.Create(context.Background(), gm)
			if tt.wantErr {
				require.Error(err)
				assert.Contains(err.Error(), tt.wantErrMsg)
				if tt.wantIsErr != nil {
					assert.True(errors.Is(err, tt.wantIsErr))
				}
				return
			}
			assert.NoError(err)

			found := allocGroupMember()
			err = w.LookupWhere(context.Background(), &found, "group_id = ? and member_id = ?", gm.GroupId, gm.MemberId)
			require.NoError(err)
			assert.Equal(gm, &found)
		})
	}
}

func Test_GroupMemberUpdate(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	org, _ := TestScopes(t, conn)
	rw := db.New(conn)

	t.Run("updates not allowed", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		g := TestGroup(t, conn, org.PublicId)
		u := TestUser(t, conn, org.PublicId)
		u2 := TestUser(t, conn, org.PublicId)
		gm := TestGroupMember(t, conn, g.PublicId, u.PublicId)
		updateGrpMember := gm.Clone().(*GroupMember)
		updateGrpMember.MemberId = u2.PublicId
		updatedRows, err := rw.Update(context.Background(), updateGrpMember, []string{"MemberId"}, nil)
		require.Error(err)
		assert.Equal(0, updatedRows)
	})
}

func Test_GroupMemberDelete(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	rw := db.New(conn)
	id := testId(t)
	org, _ := TestScopes(t, conn)
	u := TestUser(t, conn, org.PublicId)
	g := TestRole(t, conn, org.PublicId)

	tests := []struct {
		name            string
		gm              *GroupMember
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
			gm:              func() *GroupMember { gm := allocGroupMember(); gm.MemberId = id; gm.GroupId = id; return &gm }(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deleteRole := allocUserRole()
			deleteRole.RoleId = tt.gm.GetGroupId()
			deleteRole.PrincipalId = tt.gm.GetMemberId()
			deletedRows, err := rw.Delete(context.Background(), &deleteRole)
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
			found := allocUserRole()
			err = rw.LookupWhere(context.Background(), &found, "role_id = ? and principal_id = ?", tt.gm.GetGroupId(), tt.gm.GetMemberId())
			require.Error(err)
			assert.True(errors.Is(db.ErrRecordNotFound, err))
		})
	}
}

func TestGroupMember_Clone(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	org, proj := TestScopes(t, conn)
	user := TestUser(t, conn, org.PublicId)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		group := TestGroup(t, conn, org.PublicId)
		gm := TestGroupMember(t, conn, group.PublicId, user.PublicId)
		cp := gm.Clone()
		assert.True(proto.Equal(cp.(*GroupMember).GroupMember, gm.GroupMember))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		g := TestGroup(t, conn, org.PublicId)
		g2 := TestGroup(t, conn, proj.PublicId)
		gm := TestGroupMember(t, conn, g.PublicId, user.PublicId)
		gm2 := TestGroupMember(t, conn, g2.PublicId, user.PublicId)
		cp := gm.Clone()
		assert.True(!proto.Equal(cp.(*GroupMember).GroupMember, gm2.GroupMember))
	})
}
