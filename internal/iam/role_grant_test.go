package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewRoleGrant(t *testing.T) {
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
		},
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
			name: "create",
			args: args{
				roleId: projRole.PublicId,
				grant:  "actions=*;id=*",
			},
			want: func() *RoleGrant {
				g := allocRoleGrant()
				g.RoleId = projRole.PublicId
				g.RawGrant = "actions=*;id=*"
				g.CanonicalGrant = "actions=*;id=*"
				return &g
			}(),
			create: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRoleGrant(tt.args.roleId, tt.args.grant, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Is(err, tt.wantIsErr))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				assert.NoError(db.New(conn).Create(context.Background(), got))
				assert.Equal("id=*;actions=*", got.CanonicalGrant)

				// also ensure duplicate grants aren't allowed
				g2 := got.Clone().(*RoleGrant)
				assert.Error(db.New(conn).Create(context.Background(), g2))
			}
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
