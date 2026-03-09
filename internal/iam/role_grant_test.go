// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRoleGrant_Create(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	_, proj := TestScopes(t, repo)
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
		wantIsErr errors.Code
		create    bool
	}{
		{
			name: "nil-role",
			args: args{
				roleId: "",
				grant:  "ids=*;type=*;actions=*",
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-grant",
			args: args{
				roleId: projRole.PublicId,
				grant:  "",
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
			create:    true,
		},
		{
			name: "valid",
			args: args{
				roleId: projRole.PublicId,
				grant:  "ids=*;type=*;actions=*",
			},
			want: func() *RoleGrant {
				g := allocRoleGrant()
				g.RoleId = projRole.PublicId
				g.RawGrant = "ids=*;type=*;actions=*"
				g.CanonicalGrant = "ids=*;type=*;actions=*"
				return &g
			}(),
			create: true,
		},
		{
			name: "valid-reversed-grant",
			args: args{
				roleId: projRole.PublicId,
				grant:  "type=*;actions=*;ids=*",
			},
			want: func() *RoleGrant {
				g := allocRoleGrant()
				g.RoleId = projRole.PublicId
				g.RawGrant = "type=*;actions=*;ids=*"
				g.CanonicalGrant = "ids=*;type=*;actions=*"
				return &g
			}(),
			create: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, func() any { a := allocRoleGrant(); return &a }(), "1=1")
			got, err := NewRoleGrant(ctx, tt.args.roleId, tt.args.grant, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
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
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)
	rw := db.New(conn)

	t.Run("updates not allowed", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		r := TestRole(t, conn, org.PublicId)
		roleGrant := TestRoleGrant(t, conn, r.PublicId, "ids=*;type=*;actions=*")
		updateRoleGrant := roleGrant.Clone().(*RoleGrant)
		updateRoleGrant.RawGrant = "type=*;actions=*;ids=*"
		updatedRows, err := rw.Update(context.Background(), updateRoleGrant, []string{"RawGrant"}, nil)
		require.Error(err)
		assert.Equal(0, updatedRows)
	})
}

func TestRoleGrant_Delete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	_, proj := TestScopes(t, repo)
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
				grant:  "ids=*;type=*;actions=*",
			},
			wantErr:     true,
			wantsErrStr: "is not set",
		},
		{
			name: "nil-grant",
			args: args{
				roleId: projRole.PublicId,
				grant:  "",
			},
			wantErr:     true,
			wantsErrStr: "is not set",
		},
		{
			name: "invalid",
			args: args{
				roleId: projRole.PublicId,
				grant:  "ids=u_edcb;actions=read,update",
			},
		},
		{
			name: "valid",
			args: args{
				roleId: projRole.PublicId,
				grant:  "ids=u_bcde;actions=read,update",
			},
			deletedRows: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			r := allocRoleGrant()
			db.TestDeleteWhere(t, conn, &r, "1=1")
			rg, err := NewRoleGrant(ctx, projRole.PublicId, "ids=u_bcde;actions=read,update")
			require.NoError(err)
			require.NoError(rw.Create(context.Background(), rg))
			rg, err = NewRoleGrant(ctx, projRole.PublicId, "ids=u_cdef;actions=read,update")
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
				assert.Contains(err.Error(), tt.wantsErrStr)
				return
			}
			require.NoError(err)
			assert.Equal(tt.deletedRows, deleted)
		})
	}
}

func TestRoleGrant_Clone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		s := testOrg(t, repo, "", "")
		role := TestRole(t, conn, s.PublicId)

		g, err := NewRoleGrant(ctx, role.PublicId, "ids=*;type=*;actions=*")
		assert.NoError(err)
		assert.NotNil(g)
		assert.Equal(g.RoleId, role.PublicId)
		assert.Equal(g.RawGrant, "ids=*;type=*;actions=*")

		cp := g.Clone()
		assert.True(proto.Equal(cp.(*RoleGrant).RoleGrant, g.RoleGrant))
	})
	t.Run("not-equal", func(t *testing.T) {
		require, assert := require.New(t), assert.New(t)
		s := testOrg(t, repo, "", "")
		role := TestRole(t, conn, s.PublicId)

		g, err := NewRoleGrant(ctx, role.PublicId, "ids=*;type=*;actions=*")
		assert.NoError(err)
		require.NotNil(g)
		assert.Equal(g.RoleId, role.PublicId)
		assert.Equal(g.RawGrant, "ids=*;type=*;actions=*")

		g2, err := NewRoleGrant(ctx, role.PublicId, "ids=u_foo;actions=read")
		assert.NoError(err)
		require.NotNil(g2)
		assert.Equal(g2.RoleId, role.PublicId)
		assert.Equal(g2.RawGrant, "ids=u_foo;actions=read")

		cp := g.Clone()
		assert.True(!proto.Equal(cp.(*RoleGrant).RoleGrant, g2.RoleGrant))
	})
}

func TestRoleGrant_SetTableName(t *testing.T) {
	defaultTableName := defaultRoleGrantTable
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
			def := allocRoleGrant()
			require.Equal(defaultTableName, def.TableName())
			s := &RoleGrant{
				RoleGrant: &store.RoleGrant{},
				tableName: tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
