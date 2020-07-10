package iam

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/hashicorp/watchtower/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRoleGrant_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	_, proj := TestScopes(t, conn)
	projRole := TestRole(t, conn, proj.PublicId)

	type args struct {
		roleId string
		grant  string
		opt    []Option
	}
	tests := []struct {
		name      string
		args      args
		want      *RoleGrant
		wantErr   bool
		wantIsErr error
		create    bool
	}{
		{
			name: "nil-role",
			args: args{
				roleId: "",
				grant:  "id=*;actions=*",
			},
			wantErr:   true,
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "nil-grant",
			args: args{
				roleId: projRole.PublicId,
				grant:  "",
			},
			wantErr:   true,
			wantIsErr: db.ErrNilParameter,
			create:    true,
		},
		{
			name: "valid",
			args: args{
				roleId: projRole.PublicId,
				grant:  "id=*;actions=*",
			},
			want: func() *RoleGrant {
				g := allocRoleGrant()
				g.RoleId = projRole.PublicId
				g.RawGrant = "id=*;actions=*"
				g.CanonicalGrant = "id=*;actions=*"
				return &g
			}(),
			create: true,
		},
		{
			name: "valid-reversed-grant",
			args: args{
				roleId: projRole.PublicId,
				grant:  "actions=*;id=*",
			},
			want: func() *RoleGrant {
				g := allocRoleGrant()
				g.RoleId = projRole.PublicId
				g.RawGrant = "actions=*;id=*"
				g.CanonicalGrant = "id=*;actions=*"
				return &g
			}(),
			create: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("1=1").Delete(allocRoleGrant()).Error)
			got, err := NewRoleGrant(tt.args.roleId, tt.args.grant, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Is(err, tt.wantIsErr))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				err = db.New(conn).Create(context.Background(), got)
				if tt.wantErr {
					assert.Error(err)
					return
				} else {
					assert.NoError(err)
				}
				assert.Equal(tt.want.CanonicalGrant, got.CanonicalGrant)

				// also ensure duplicate grants aren't allowed
				g2 := got.Clone().(*RoleGrant)
				assert.Error(db.New(conn).Create(context.Background(), g2))
			}
		})
	}
}

func TestRoleGrant_Update(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, _ := TestScopes(t, conn)
	rw := db.New(conn)

	t.Run("updates not allowed", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		r := TestRole(t, conn, org.PublicId)
		roleGrant := TestRoleGrant(t, conn, r.PublicId, "id=*;actions=*")
		updateRoleGrant := roleGrant.Clone().(*RoleGrant)
		updateRoleGrant.RawGrant = "actions=*;id=*"
		updatedRows, err := rw.Update(context.Background(), updateRoleGrant, []string{"RawGrant"}, nil)
		require.Error(err)
		assert.Equal(0, updatedRows)
	})
}

func TestRoleGrant_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	_, proj := TestScopes(t, conn)
	projRole := TestRole(t, conn, proj.PublicId)

	type args struct {
		roleId string
		grant  string
	}
	tests := []struct {
		name        string
		args        args
		want        *RoleGrant
		wantErr     bool
		wantsErrStr string
		deletedRows int
	}{
		{
			name: "nil-role",
			args: args{
				roleId: "",
				grant:  "id=*;actions=*",
			},
			wantErr:     true,
			wantsErrStr: "primary key is not set",
		},
		{
			name: "nil-grant",
			args: args{
				roleId: projRole.PublicId,
				grant:  "",
			},
			// Note: Gorm's primary key checking is only for what it considers
			// the main primary key field, hence this doesn't error as the above
			// case does
		},
		{
			name: "invalid",
			args: args{
				roleId: projRole.PublicId,
				grant:  "id=a_edcb;actions=create,update",
			},
		},
		{
			name: "valid",
			args: args{
				roleId: projRole.PublicId,
				grant:  "id=a_bcde;actions=create,update",
			},
			deletedRows: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("1=1").Delete(allocRoleGrant()).Error)
			rg, err := NewRoleGrant(projRole.PublicId, "id=a_bcde;actions=create,update")
			require.NoError(err)
			require.NoError(rw.Create(context.Background(), rg))
			rg, err = NewRoleGrant(projRole.PublicId, "id=a_cdef;actions=create,update")
			require.NoError(err)
			require.NoError(rw.Create(context.Background(), rg))

			rg = &RoleGrant{
				RoleGrant: &store.RoleGrant{
					RoleId:         tt.args.roleId,
					RawGrant:       tt.args.grant,
					CanonicalGrant: tt.args.grant,
				},
			}
			deleted, err := rw.Delete(context.Background(), rg)
			if tt.wantErr {
				require.Error(err)
				assert.True(strings.Contains(err.Error(), tt.wantsErrStr))
				return
			}
			require.NoError(err)
			assert.Equal(tt.deletedRows, deleted)
		})
	}
}

func TestRoleGrant_ResourceType(t *testing.T) {
	assert := assert.New(t)
	r := &RoleGrant{}
	ty := r.ResourceType()
	assert.Equal(ty, resource.RoleGrant)
}

func TestRoleGrant_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		s := testOrg(t, conn, "", "")
		role := TestRole(t, conn, s.PublicId)

		g, err := NewRoleGrant(role.PublicId, "id=*;actions=*")
		assert.NoError(err)
		assert.NotNil(g)
		assert.Equal(g.RoleId, role.PublicId)
		assert.Equal(g.RawGrant, "id=*;actions=*")

		cp := g.Clone()
		assert.True(proto.Equal(cp.(*RoleGrant).RoleGrant, g.RoleGrant))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		s := testOrg(t, conn, "", "")
		role := TestRole(t, conn, s.PublicId)

		g, err := NewRoleGrant(role.PublicId, "id=*;actions=*")
		assert.NoError(err)
		assert.NotNil(g)
		assert.Equal(g.RoleId, role.PublicId)
		assert.Equal(g.RawGrant, "id=*;actions=*")

		g2, err := NewRoleGrant(role.PublicId, "id=foo;actions=read")
		assert.NoError(err)
		assert.NotNil(g2)
		assert.Equal(g2.RoleId, role.PublicId)
		assert.Equal(g2.RawGrant, "id=foo;actions=read")

		cp := g.Clone()
		assert.True(!proto.Equal(cp.(*RoleGrant).RoleGrant, g2.RoleGrant))
	})
}
