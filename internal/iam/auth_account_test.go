package iam

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/watchtower/internal/db"
	dbassert "github.com/hashicorp/watchtower/internal/db/assert"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func Test_AuthAccountUpdate(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	id := testId(t)
	org, proj := TestScopes(t, conn)
	rw := db.New(conn)
	type args struct {
		name           string
		description    string
		fieldMaskPaths []string
		nullPaths      []string
		ScopeId        string
	}
	tests := []struct {
		name           string
		args           args
		wantRowsUpdate int
		wantErr        bool
		wantErrMsg     string
		wantDup        bool
	}{
		{
			name: "valid",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "proj-scope-id",
			args: args{
				name:           "proj-scope-id" + id,
				fieldMaskPaths: []string{"ScopeId"},
				ScopeId:        proj.PublicId,
			},
			wantErr:    true,
			wantErrMsg: "update: vet for write failed not allowed to change a resource's scope",
		},
		{
			name: "proj-scope-id-not-in-mask",
			args: args{
				name:           "proj-scope-id" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        proj.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "empty-scope-id",
			args: args{
				name:           "empty-scope-id" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        "",
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "dup-name",
			args: args{
				name:           "dup-name" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
			},
			wantErr:    true,
			wantDup:    true,
			wantErrMsg: `update: failed pq: duplicate key value violates unique constraint "iam_role_name_scope_id_key"`,
		},
		{
			name: "set description null",
			args: args{
				name:           "set description null" + id,
				fieldMaskPaths: []string{"Name"},
				nullPaths:      []string{"Description"},
				ScopeId:        org.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "set name null",
			args: args{
				description:    "set description null" + id,
				fieldMaskPaths: []string{"Description"},
				nullPaths:      []string{"Name"},
				ScopeId:        org.PublicId,
			},
			wantDup:        true,
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "set description null",
			args: args{
				name:           "set name null" + id,
				fieldMaskPaths: []string{"Name"},
				nullPaths:      []string{"Description"},
				ScopeId:        org.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tt.wantDup {
				r := TestRole(t, conn, org.PublicId, WithName(tt.args.name))
				_, err := rw.Update(context.Background(), r, tt.args.fieldMaskPaths, tt.args.nullPaths)
				require.NoError(err)
			}

			id := testId(t)
			role := TestRole(t, conn, org.PublicId, WithDescription(id), WithName(id))

			updateRole := allocRole()
			updateRole.PublicId = role.PublicId
			updateRole.ScopeId = tt.args.ScopeId
			updateRole.Name = tt.args.name
			updateRole.Description = tt.args.description

			updatedRows, err := rw.Update(context.Background(), &updateRole, tt.args.fieldMaskPaths, tt.args.nullPaths)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, updatedRows)
				assert.Equal(tt.wantErrMsg, err.Error())
				err = db.TestVerifyOplog(t, rw, role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				require.Error(err)
				assert.Equal("record not found", err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			assert.NotEqual(role.UpdateTime, updateRole.UpdateTime)
			foundRole := allocRole()
			foundRole.PublicId = role.GetPublicId()
			err = rw.LookupByPublicId(context.Background(), &foundRole)
			require.NoError(err)
			assert.True(proto.Equal(updateRole, foundRole))
			if len(tt.args.nullPaths) != 0 {
				dbassert := dbassert.New(t, rw)
				for _, f := range tt.args.nullPaths {
					dbassert.IsNull(&foundRole, f)
				}
			}
		})
	}
	t.Run("update dup names in diff scopes", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		id := testId(t)
		_ = TestRole(t, conn, org.PublicId, WithDescription(id), WithName(id))
		projRole := TestRole(t, conn, proj.PublicId, WithName(id))
		updatedRows, err := rw.Update(context.Background(), projRole, []string{"Name"}, nil)
		require.NoError(err)
		assert.Equal(1, updatedRows)

		foundRole := allocRole()
		foundRole.PublicId = projRole.GetPublicId()
		err = rw.LookupByPublicId(context.Background(), &foundRole)
		require.NoError(err)
		assert.Equal(id, projRole.Name)
	})
}

func TestAuthAccount_GetScope(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	org, proj := TestScopes(t, conn)

	t.Run("valid-org", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		role := TestRole(t, conn, org.PublicId)
		scope, err := role.GetScope(context.Background(), w)
		require.NoError(err)
		assert.True(proto.Equal(org, scope))
	})
	t.Run("valid-proj", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		role := TestRole(t, conn, proj.PublicId)
		scope, err := role.GetScope(context.Background(), w)
		require.NoError(err)
		assert.True(proto.Equal(proj, scope))
	})
}

func TestAuthAccount_Clone(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	org, _ := TestScopes(t, conn)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		u := TestUser(t, conn, org.PublicId)
		authMethodPublicId := testAuthMethod(t, conn, org.PublicId)
		acct := testAuthAccount(t, conn, org.PublicId, authMethodPublicId, u.PublicId)
		cp := acct.Clone()
		assert.True(proto.Equal(cp.(*AuthAccount).AuthAccount, acct.AuthAccount))
	})
	// t.Run("not-equal", func(t *testing.T) {
	// 	assert := assert.New(t)
	// 	role := TestRole(t, conn, org.PublicId)
	// 	role2 := TestRole(t, conn, org.PublicId)
	// 	cp := role.Clone()
	// 	assert.True(!proto.Equal(cp.(*Role).Role, role2.Role))
	// })
}
