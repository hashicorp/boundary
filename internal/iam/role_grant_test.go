package iam

import (
	"context"
	"strings"
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
				grant:  "id=*;type=*;actions=*",
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
				grant:  "id=*;type=*;actions=*",
			},
			want: func() *RoleGrant {
				g := allocRoleGrant()
				g.RoleId = projRole.PublicId
				g.RawGrant = "id=*;type=*;actions=*"
				g.CanonicalGrant = "id=*;type=*;actions=*"
				return &g
			}(),
			create: true,
		},
		{
			name: "valid-reversed-grant",
			args: args{
				roleId: projRole.PublicId,
				grant:  "type=*;actions=*;id=*",
			},
			want: func() *RoleGrant {
				g := allocRoleGrant()
				g.RoleId = projRole.PublicId
				g.RawGrant = "type=*;actions=*;id=*"
				g.CanonicalGrant = "id=*;type=*;actions=*"
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
		roleGrant := TestRoleGrant(t, conn, r.PublicId, "id=*;type=*;actions=*")
		updateRoleGrant := roleGrant.Clone().(*RoleGrant)
		updateRoleGrant.RawGrant = "type=*;actions=*;id=*"
		updatedRows, err := rw.Update(context.Background(), updateRoleGrant, []string{"RawGrant"}, nil)
		require.Error(err)
		assert.Equal(0, updatedRows)
	})
}

func TestRoleGrant_Delete(t *testing.T) {
	t.Parallel()
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
				grant:  "id=*;type=*;actions=*",
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
				grant:  "id=a_edcb;actions=read,update",
			},
		},
		{
			name: "valid",
			args: args{
				roleId: projRole.PublicId,
				grant:  "id=a_bcde;actions=read,update",
			},
			deletedRows: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("1=1").Delete(allocRoleGrant()).Error)
			rg, err := NewRoleGrant(projRole.PublicId, "id=a_bcde;actions=read,update")
			require.NoError(err)
			require.NoError(rw.Create(context.Background(), rg))
			rg, err = NewRoleGrant(projRole.PublicId, "id=a_cdef;actions=read,update")
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

func TestRoleGrant_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		s := testOrg(t, repo, "", "")
		role := TestRole(t, conn, s.PublicId)

		g, err := NewRoleGrant(role.PublicId, "id=*;type=*;actions=*")
		assert.NoError(err)
		assert.NotNil(g)
		assert.Equal(g.RoleId, role.PublicId)
		assert.Equal(g.RawGrant, "id=*;type=*;actions=*")

		cp := g.Clone()
		assert.True(proto.Equal(cp.(*RoleGrant).RoleGrant, g.RoleGrant))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		s := testOrg(t, repo, "", "")
		role := TestRole(t, conn, s.PublicId)

		g, err := NewRoleGrant(role.PublicId, "id=*;type=*;actions=*")
		assert.NoError(err)
		assert.NotNil(g)
		assert.Equal(g.RoleId, role.PublicId)
		assert.Equal(g.RawGrant, "id=*;type=*;actions=*")

		g2, err := NewRoleGrant(role.PublicId, "id=foo;actions=read")
		assert.NoError(err)
		assert.NotNil(g2)
		assert.Equal(g2.RoleId, role.PublicId)
		assert.Equal(g2.RawGrant, "id=foo;actions=read")

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
