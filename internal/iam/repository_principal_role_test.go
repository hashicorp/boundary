package iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_AddPrincipalRoles(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	org, proj := TestScopes(t, conn)
	role := TestRole(t, conn, proj.PublicId)

	createUsersFn := func() []string {
		results := []string{}
		for i := 0; i < 5; i++ {
			u := TestUser(t, conn, org.PublicId)
			results = append(results, u.PublicId)
		}
		return results
	}
	createGrpsFn := func() []string {
		results := []string{}
		for i := 0; i < 5; i++ {
			g := TestGroup(t, conn, proj.PublicId)
			results = append(results, g.PublicId)
		}
		return results
	}
	type args struct {
		roleId      string
		roleVersion int
		userIds     []string
		groupIds    []string
		opt         []Option
	}
	tests := []struct {
		name      string
		args      args
		wantErr   bool
		wantErrIs error
	}{
		{
			name: "valid-both-users-and-groups",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 0,
				userIds:     createUsersFn(),
				groupIds:    createGrpsFn(),
			},
			wantErr: false,
		},
		{
			name: "valid-just-groups",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 1,
				userIds:     nil,
				groupIds:    createGrpsFn(),
			},
			wantErr: false,
		},
		{
			name: "valid-just-users",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 2,
				userIds:     createUsersFn(),
				groupIds:    nil,
			},
			wantErr: false,
		},
		{
			name: "bad-version",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 1000,
				userIds:     createUsersFn(),
				groupIds:    createGrpsFn(),
			},
			wantErr: true,
		},
		{
			name: "no-principals",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 1,
				userIds:     nil,
				groupIds:    nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn.LogMode(true)
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("1=1").Delete(allocUserRole()).Error)
			require.NoError(conn.Where("1=1").Delete(allocGroupRole()).Error)
			got, err := repo.AddPrincipalRoles(context.Background(), tt.args.roleId, tt.args.roleVersion, tt.args.userIds, tt.args.groupIds, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrIs != nil {
					assert.Truef(errors.Is(err, tt.wantErrIs), "unexpected error %s", err.Error())
				}
				return
			}
			require.NoError(err)
			gotPrincipal := map[string]PrincipalRole{}
			for _, r := range got {
				gotPrincipal[r.GetPrincipalId()] = r
			}
			for _, id := range tt.args.userIds {
				assert.NotEmpty(gotPrincipal[id])
				u, err := repo.LookupUser(context.Background(), id)
				assert.NoError(err)
				assert.Equal(id, u.PublicId)
			}
			for _, id := range tt.args.groupIds {
				assert.NotEmpty(gotPrincipal[id])
				g, err := repo.LookupGroup(context.Background(), id)
				assert.NoError(err)
				assert.Equal(id, g.PublicId)
			}
			err = db.TestVerifyOplog(t, rw, role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)

			foundRoles, err := repo.ListPrincipalRoles(context.Background(), role.PublicId)
			require.NoError(err)
			for _, r := range foundRoles {
				assert.NotEmpty(gotPrincipal[r.GetPrincipalId()])
				assert.Equal(gotPrincipal[r.GetPrincipalId()].GetRoleId(), r.GetRoleId())
				assert.Equal(gotPrincipal[r.GetPrincipalId()].GetScopeId(), r.GetScopeId())
				assert.Equal(gotPrincipal[r.GetPrincipalId()].GetType(), r.GetType())
			}

		})
	}
}
