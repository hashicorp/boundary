package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
