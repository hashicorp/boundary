// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

// This is in an iam_test package because managed groups are an abstract type so
// we need to reach into an implementation for testing, which itself reaches
// into IAM. So this avoids a dependency loop.

func TestNewManagedGroupRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, repo)
	orgRole := iam.TestRole(t, conn, org.PublicId)
	const managedGroupId = "mgoidc_1234567890"

	type args struct {
		roleId         string
		ManagedGroupId string
		opt            []iam.Option
	}
	tests := []struct {
		name      string
		args      args
		want      *iam.ManagedGroupRole
		wantErr   bool
		wantIsErr errors.Code
	}{
		{
			name: "valid-org",
			args: args{
				roleId:         orgRole.PublicId,
				ManagedGroupId: managedGroupId,
			},
			want: func() *iam.ManagedGroupRole {
				r := iam.AllocManagedGroupRole()
				r.RoleId = orgRole.PublicId
				r.PrincipalId = managedGroupId
				return &r
			}(),
		},
		{
			name: "empty-role-id",
			args: args{
				roleId:         "",
				ManagedGroupId: managedGroupId,
			},
			want:      nil,
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-ManagedGroup-id",
			args: args{
				roleId:         orgRole.PublicId,
				ManagedGroupId: "",
			},
			want:      nil,
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := iam.NewManagedGroupRole(ctx, tt.args.roleId, tt.args.ManagedGroupId, tt.args.opt...)
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

func TestManagedGroupRole_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")

	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)

	repo := iam.TestRepo(t, conn, wrap)
	org, _ := iam.TestScopes(t, repo)
	org2, _ := iam.TestScopes(t, repo)

	ctx := context.Background()
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	authMethod := oidc.TestAuthMethod(
		t, conn, databaseWrapper, org.GetPublicId(), oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	mg := oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter)

	type args struct {
		role *iam.ManagedGroupRole
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
				role: func() *iam.ManagedGroupRole {
					role := iam.TestRole(t, conn, org.PublicId)
					principalRole, err := iam.NewManagedGroupRole(ctx, role.PublicId, mg.PublicId)
					require.NoError(t, err)
					return principalRole
				}(),
			},
			wantErr: false,
		},
		{
			name: "cross-org",
			args: args{
				role: func() *iam.ManagedGroupRole {
					role := iam.TestRole(t, conn, org2.PublicId)
					principalRole, err := iam.NewManagedGroupRole(ctx, role.PublicId, mg.PublicId)
					require.NoError(t, err)
					return principalRole
				}(),
			},
		},
		{
			name: "bad-role-id",
			args: args{
				role: func() *iam.ManagedGroupRole {
					id := testId(t)
					principalRole, err := iam.NewManagedGroupRole(ctx, id, mg.PublicId)
					require.NoError(t, err)
					return principalRole
				}(),
			},
			wantErr:    true,
			wantErrMsg: "integrity violation: error #1003",
		},
		{
			name: "bad-principal-id",
			args: args{
				role: func() *iam.ManagedGroupRole {
					id := testId(t)
					role := iam.TestRole(t, conn, org.PublicId)
					principalRole, err := iam.NewManagedGroupRole(ctx, role.PublicId, id)
					require.NoError(t, err)
					return principalRole
				}(),
			},
			wantErr:    true,
			wantErrMsg: "integrity violation: error #1003",
		},
		{
			name: "missing-role-id",
			args: args{
				role: func() *iam.ManagedGroupRole {
					return &iam.ManagedGroupRole{
						ManagedGroupRole: &store.ManagedGroupRole{
							RoleId:      "",
							PrincipalId: mg.PublicId,
						},
					}
				}(),
			},
			wantErr:    true,
			wantErrMsg: "iam.(ManagedGroupRole).VetForWrite: missing role id: parameter violation: error #100",
			wantIsErr:  errors.InvalidParameter,
		},
		{
			name: "missing-principal-id",
			args: args{
				role: func() *iam.ManagedGroupRole {
					role := iam.TestRole(t, conn, org.PublicId)
					return &iam.ManagedGroupRole{
						ManagedGroupRole: &store.ManagedGroupRole{
							RoleId:      role.PublicId,
							PrincipalId: "",
						},
					}
				}(),
			},
			wantErr:    true,
			wantErrMsg: "iam.(ManagedGroupRole).VetForWrite: missing managed group id: parameter violation: error #100",
			wantIsErr:  errors.InvalidParameter,
		},
		{
			name: "dup-at-org",
			args: args{
				role: func() *iam.ManagedGroupRole {
					role := iam.TestRole(t, conn, org.PublicId)
					principalRole, err := iam.NewManagedGroupRole(ctx, role.PublicId, mg.PublicId)
					require.NoError(t, err)
					return principalRole
				}(),
			},
			wantDup:    true,
			wantErr:    true,
			wantErrMsg: `db.Create: duplicate key value violates unique constraint "iam_managed_group_role_pkey": unique constraint violation`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			w := db.New(conn)
			if tt.wantDup {
				r := tt.args.role.Clone().(*iam.ManagedGroupRole)
				err := w.Create(context.Background(), r)
				require.NoError(err)
			}
			r := tt.args.role.Clone().(*iam.ManagedGroupRole)
			err := w.Create(context.Background(), r)
			if tt.wantErr {
				require.Error(err)
				assert.Contains(err.Error(), tt.wantErrMsg)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			assert.NoError(err)

			found := iam.AllocManagedGroupRole()
			err = w.LookupWhere(context.Background(), &found, "role_id = ? and principal_id = ?", []any{r.RoleId, r.PrincipalId})
			require.NoError(err)
			assert.Empty(cmp.Diff(r, &found, protocmp.Transform()))
		})
	}
}

func TestManagedGroupRole_Update(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)

	repo := iam.TestRepo(t, conn, wrap)
	org, _ := iam.TestScopes(t, repo)

	ctx := context.Background()
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	authMethod := oidc.TestAuthMethod(
		t, conn, databaseWrapper, org.GetPublicId(), oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	t.Run("updates not allowed", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		r := iam.TestRole(t, conn, org.PublicId)
		mg := oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter)
		mg2 := oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter)
		mgr := iam.TestManagedGroupRole(t, conn, r.PublicId, mg.PublicId)
		updateRole := mgr.Clone().(*iam.ManagedGroupRole)
		updateRole.PrincipalId = mg2.PublicId
		updatedRows, err := rw.Update(context.Background(), updateRole, []string{"PrincipalId"}, nil)
		require.Error(err)
		assert.Equal(0, updatedRows)
	})
}

func TestManagedGroupRole_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)

	repo := iam.TestRepo(t, conn, wrap)
	org, _ := iam.TestScopes(t, repo)

	ctx := context.Background()
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	authMethod := oidc.TestAuthMethod(
		t, conn, databaseWrapper, org.GetPublicId(), oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	id := testId(t)
	mg := oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter)
	r := iam.TestRole(t, conn, org.PublicId)

	tests := []struct {
		name            string
		role            *iam.ManagedGroupRole
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			role:            iam.TestManagedGroupRole(t, conn, r.PublicId, mg.PublicId),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "bad-id",
			role: func() *iam.ManagedGroupRole {
				r := iam.AllocManagedGroupRole()
				r.PrincipalId = id
				r.RoleId = id
				return &r
			}(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deleteRole := iam.AllocManagedGroupRole()
			deleteRole.RoleId = tt.role.GetRoleId()
			deleteRole.PrincipalId = tt.role.GetPrincipalId()
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
			found := iam.AllocManagedGroupRole()
			err = rw.LookupWhere(context.Background(), &found, "role_id = ? and principal_id = ?", []any{tt.role.GetRoleId(), tt.role.GetPrincipalId()})
			require.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestManagedGroupRole_Clone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		mgr, err := iam.NewManagedGroupRole(ctx, "r_abc", "mgoidc_abc")
		require.NoError(err)
		cp := mgr.Clone()
		assert.True(proto.Equal(cp.(*iam.ManagedGroupRole).ManagedGroupRole, mgr.ManagedGroupRole))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		mgr, err := iam.NewManagedGroupRole(ctx, "r_abc", "mgoidc_abc")
		require.NoError(err)
		mgr2, err := iam.NewManagedGroupRole(ctx, "r_xyz", "mgoidc_xyz")
		require.NoError(err)
		cp := mgr.Clone()

		assert.True(!proto.Equal(cp.(*iam.ManagedGroupRole).ManagedGroupRole, mgr2.ManagedGroupRole))
	})
}
