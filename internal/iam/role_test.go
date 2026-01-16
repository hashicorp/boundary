// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestNewRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	id := testId(t)

	type args struct {
		scopePublicId string
		opt           []Option
	}
	tests := []struct {
		name            string
		args            args
		wantErr         bool
		wantErrMsg      string
		wantIsErr       errors.Code
		wantName        string
		wantDescription string
	}{
		{
			name: "valid",
			args: args{
				scopePublicId: org.PublicId,
				opt:           []Option{WithName(id), WithDescription("description-" + id)},
			},
			wantErr:         false,
			wantName:        id,
			wantDescription: "description-" + id,
		},
		{
			name: "valid-proj",
			args: args{
				scopePublicId: proj.PublicId,
				opt:           []Option{WithName(id), WithDescription("description-" + id)},
			},
			wantErr:         false,
			wantName:        id,
			wantDescription: "description-" + id,
		},
		{
			name: "valid-with-no-options" + id,
			args: args{
				scopePublicId: org.PublicId,
			},
			wantErr: false,
		},
		{
			name: "no-scope",
			args: args{
				opt: []Option{WithName(id)},
			},
			wantErr:    true,
			wantErrMsg: "iam.NewRole: missing scope id: parameter violation: error #100",
			wantIsErr:  errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRole(ctx, tt.args.scopePublicId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Contains(err.Error(), tt.wantErrMsg)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantName, got.Name)
			assert.Equal(tt.wantDescription, got.Description)
			assert.Empty(got.PublicId)
		})
	}
}

func TestRole_Actions(t *testing.T) {
	assert := assert.New(t)
	r := &Role{}
	a := r.Actions()
	assert.Equal(a[action.Create.String()], action.Create)
	assert.Equal(a[action.Update.String()], action.Update)
	assert.Equal(a[action.Read.String()], action.Read)
	assert.Equal(a[action.Delete.String()], action.Delete)
	assert.Equal(a[action.AddGrants.String()], action.AddGrants)
	assert.Equal(a[action.RemoveGrants.String()], action.RemoveGrants)
	assert.Equal(a[action.SetGrants.String()], action.SetGrants)
	assert.Equal(a[action.AddPrincipals.String()], action.AddPrincipals)
	assert.Equal(a[action.RemovePrincipals.String()], action.RemovePrincipals)
	assert.Equal(a[action.SetPrincipals.String()], action.SetPrincipals)
}

func TestRole_ResourceType(t *testing.T) {
	assert := assert.New(t)
	r := &Role{}
	ty := r.GetResourceType()
	assert.Equal(ty, resource.Role)
}

func TestRole_GetScope(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)

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

func Test_globalRole_Create(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	type args struct {
		role *globalRole
	}
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	rw := db.New(conn)
	tests := []struct {
		name       string
		args       args
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "can create valid role in global grants scope individual",
			args: args{
				role: func() *globalRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					r := &globalRole{
						GlobalRole: &store.GlobalRole{
							PublicId:           grpId,
							ScopeId:            globals.GlobalPrefix,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
							GrantThisRoleScope: false,
							GrantScope:         globals.GrantScopeIndividual,
						},
					}
					return r
				}(),
			},
			wantErr: false,
		},
		{
			name: "can create valid role in global grants scope descendants",
			args: args{
				role: func() *globalRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					r := &globalRole{
						GlobalRole: &store.GlobalRole{
							PublicId:           grpId,
							ScopeId:            globals.GlobalPrefix,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
							GrantThisRoleScope: true,
							GrantScope:         globals.GrantScopeDescendants,
						},
					}
					return r
				}(),
			},
			wantErr: false,
		},
		{
			name: "can create valid role in global grants scope children",
			args: args{
				role: func() *globalRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					r := &globalRole{
						GlobalRole: &store.GlobalRole{
							PublicId:           grpId,
							ScopeId:            globals.GlobalPrefix,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
							GrantThisRoleScope: true,
							GrantScope:         globals.GrantScopeChildren,
						},
					}
					return r
				}(),
			},
			wantErr: false,
		},
		{
			name: "cannot create role in org",
			args: args{
				role: func() *globalRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					r := &globalRole{
						GlobalRole: &store.GlobalRole{
							PublicId:           grpId,
							ScopeId:            org.PublicId,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
							GrantThisRoleScope: true,
							GrantScope:         globals.GrantScopeDescendants,
						},
					}
					return r
				}(),
			},
			wantErr:    true,
			wantErrMsg: `db.Create: insert or update on table "iam_role_global" violates foreign key constraint "iam_scope_global_fkey": integrity violation: error #1003`,
		},
		{
			name: "cannot create role in project",
			args: args{
				role: func() *globalRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					r := &globalRole{
						GlobalRole: &store.GlobalRole{
							PublicId:           grpId,
							ScopeId:            proj.PublicId,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
							GrantThisRoleScope: true,
							GrantScope:         globals.GrantScopeDescendants,
						},
					}
					return r
				}(),
			},
			wantErr:    true,
			wantErrMsg: `db.Create: insert or update on table "iam_role_global" violates foreign key constraint "iam_scope_global_fkey": integrity violation: error #1003`,
		},
		{
			name: "invalid grants scope",
			args: args{
				role: func() *globalRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					r := &globalRole{
						GlobalRole: &store.GlobalRole{
							PublicId:           grpId,
							ScopeId:            globals.GlobalPrefix,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
							GrantThisRoleScope: true,
							GrantScope:         "invalid-scope",
						},
					}
					return r
				}(),
			},
			wantErr:    true,
			wantErrMsg: `db.Create: insert or update on table "iam_role_global" violates foreign key constraint "iam_role_global_grant_scope_enm_fkey": integrity violation: error #1003`,
		},
		{
			name: "duplicate name not allowed",
			args: args{
				role: func() *globalRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					// create a role then return the cloned role with different name
					r := &globalRole{
						GlobalRole: &store.GlobalRole{
							PublicId:           grpId,
							ScopeId:            globals.GlobalPrefix,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
							GrantThisRoleScope: true,
							GrantScope:         globals.GrantScopeDescendants,
						},
					}

					require.NoError(t, rw.Create(ctx, r))
					newId, err := newRoleId(ctx)
					require.NoError(t, err)
					dupeName := r.Clone().(*globalRole)
					dupeName.PublicId = newId
					dupeName.GrantThisRoleScope = false
					dupeName.GrantScope = globals.GrantScopeChildren
					return dupeName
				}(),
			},
			wantErr:    true,
			wantErrMsg: `db.Create: duplicate key value violates unique constraint "iam_role_global_name_scope_id_uq": unique constraint violation: integrity violation: error #1002`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.args.role.Clone().(*globalRole)
			err := rw.Create(ctx, r)
			if tt.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.wantErrMsg)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, tt.args.role.PublicId)

			foundGrp := allocGlobalRole()
			foundGrp.PublicId = tt.args.role.PublicId
			err = rw.LookupByPublicId(ctx, &foundGrp)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(r, &foundGrp, protocmp.Transform()))

			require.NotEmpty(t, foundGrp.GrantScopeUpdateTime)
			require.NotEmpty(t, foundGrp.GrantThisRoleScopeUpdateTime)
			require.NotZero(t, foundGrp.CreateTime.AsTime())
			require.NotZero(t, foundGrp.UpdateTime.AsTime())

			baseRole := &testBaseRole{PublicId: tt.args.role.PublicId}
			err = rw.LookupByPublicId(ctx, baseRole)
			require.NoError(t, err)
			require.Equal(t, foundGrp.CreateTime.AsTime(), baseRole.CreateTime.AsTime())
			require.Equal(t, foundGrp.UpdateTime.AsTime(), baseRole.UpdateTime.AsTime())
		})
	}
}

func Test_globalRole_Update(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	type arg struct {
		updateRole *globalRole
		fieldMask  []string
		nullPath   []string
		opts       []db.Option
	}
	tests := []struct {
		name           string
		setupOriginal  func(t *testing.T) *globalRole
		createInput    func(t *testing.T, original *globalRole) arg
		wantErr        bool
		wantRowsUpdate int
		wantErrMsg     string
	}{
		{
			name: "can update name and description",
			setupOriginal: func(t *testing.T) *globalRole {
				roleId, err := newRoleId(ctx)
				require.NoError(t, err)
				original := &globalRole{
					GlobalRole: &store.GlobalRole{
						PublicId:           roleId,
						ScopeId:            globals.GlobalPrefix,
						Name:               testId(t),
						Description:        testId(t),
						GrantThisRoleScope: false,
						GrantScope:         globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, original))
				return original
			},
			createInput: func(t *testing.T, original *globalRole) arg {
				updated := original.Clone().(*globalRole)
				updated.Name = testId(t)
				updated.Description = testId(t)
				return arg{
					updateRole: updated,
					fieldMask:  []string{"name", "description"},
					nullPath:   []string{},
					opts:       []db.Option{},
				}
			},
			wantRowsUpdate: 1,
			wantErr:        false,
		},
		{
			name: "can update grant_scope",
			setupOriginal: func(t *testing.T) *globalRole {
				roleId, err := newRoleId(ctx)
				require.NoError(t, err)
				original := &globalRole{
					GlobalRole: &store.GlobalRole{
						PublicId:           roleId,
						ScopeId:            globals.GlobalPrefix,
						Name:               testId(t),
						Description:        "desc",
						GrantThisRoleScope: false,
						GrantScope:         globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, original))
				return original
			},
			createInput: func(t *testing.T, original *globalRole) arg {
				updated := original.Clone().(*globalRole)
				updated.GrantScope = globals.GrantScopeChildren
				return arg{
					updateRole: updated,
					fieldMask:  []string{"GrantScope"},
					nullPath:   []string{},
					opts:       []db.Option{},
				}
			},
			wantRowsUpdate: 1,
			wantErr:        false,
		},
		{
			name: "can set name and description null",
			setupOriginal: func(t *testing.T) *globalRole {
				roleId, err := newRoleId(ctx)
				require.NoError(t, err)
				original := &globalRole{
					GlobalRole: &store.GlobalRole{
						PublicId:           roleId,
						ScopeId:            globals.GlobalPrefix,
						Name:               testId(t),
						Description:        "desc",
						GrantThisRoleScope: false,
						GrantScope:         globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, original))
				return original
			},
			createInput: func(t *testing.T, original *globalRole) arg {
				updated := original.Clone().(*globalRole)
				updated.Name = ""
				updated.Description = ""
				return arg{
					updateRole: updated,
					fieldMask:  []string{},
					nullPath:   []string{"name", "description"},
					opts:       []db.Option{},
				}
			},
			wantRowsUpdate: 1,
			wantErr:        false,
		},
		{
			name: "can update grant_this_role_scope",
			setupOriginal: func(t *testing.T) *globalRole {
				roleId, err := newRoleId(ctx)
				require.NoError(t, err)
				original := &globalRole{
					GlobalRole: &store.GlobalRole{
						PublicId:           roleId,
						ScopeId:            globals.GlobalPrefix,
						Name:               testId(t),
						Description:        "desc",
						GrantThisRoleScope: true,
						GrantScope:         globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, original))
				return original
			},
			createInput: func(t *testing.T, original *globalRole) arg {
				updated := original.Clone().(*globalRole)
				updated.GrantThisRoleScope = false
				return arg{
					updateRole: updated,
					fieldMask:  []string{"GrantThisRoleScope"},
					nullPath:   []string{},
					opts:       []db.Option{},
				}
			},
			wantRowsUpdate: 1,
			wantErr:        false,
		},
		{
			name: "can update version",
			setupOriginal: func(t *testing.T) *globalRole {
				roleId, err := newRoleId(ctx)
				require.NoError(t, err)
				original := &globalRole{
					GlobalRole: &store.GlobalRole{
						PublicId:           roleId,
						ScopeId:            globals.GlobalPrefix,
						Name:               testId(t),
						Description:        "desc",
						GrantThisRoleScope: true,
						GrantScope:         globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, original))
				return original
			},
			createInput: func(t *testing.T, original *globalRole) arg {
				updated := original.Clone().(*globalRole)
				// version will be overridden by trigger
				updated.Version = 123456
				return arg{
					updateRole: updated,
					fieldMask:  []string{"version"},
					nullPath:   []string{},
					opts:       []db.Option{},
				}
			},
			wantRowsUpdate: 1,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := tt.setupOriginal(t)
			args := tt.createInput(t, original)
			updatedRows, err := rw.Update(context.Background(), args.updateRole, args.fieldMask, args.nullPath, args.opts...)
			if tt.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.wantErrMsg)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, args.updateRole.PublicId)
			if tt.wantRowsUpdate == 0 {
				require.Zero(t, updatedRows)
				return
			}
			require.Equal(t, tt.wantRowsUpdate, updatedRows)
			foundGrp := allocGlobalRole()
			foundGrp.PublicId = original.PublicId
			err = rw.LookupByPublicId(ctx, &foundGrp)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(args.updateRole, &foundGrp, protocmp.Transform()))
			baseRole := &testBaseRole{PublicId: original.PublicId}
			err = rw.LookupByPublicId(ctx, baseRole)
			require.NoError(t, err)
			require.Equal(t, original.Version+1, foundGrp.Version)
			require.Equal(t, foundGrp.UpdateTime.AsTime(), baseRole.UpdateTime.AsTime())
			// assert other update time as necessary
			if original.GrantThisRoleScope != args.updateRole.GrantThisRoleScope {
				require.Greater(t, foundGrp.GrantThisRoleScopeUpdateTime.AsTime(), original.GrantThisRoleScopeUpdateTime.AsTime())
			}
			if original.GrantScope != args.updateRole.GrantScope {
				require.Greater(t, foundGrp.GrantScopeUpdateTime.AsTime(), original.GrantScopeUpdateTime.AsTime())
			}
		})
	}
}

func Test_globalRole_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	tests := []struct {
		name            string
		setupRole       func(ctx context.Context, t *testing.T) *globalRole
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name: "valid",
			setupRole: func(ctx context.Context, t *testing.T) *globalRole {
				role := &globalRole{
					GlobalRole: &store.GlobalRole{
						ScopeId:            globals.GlobalPrefix,
						Name:               "test-role",
						Description:        "description",
						GrantThisRoleScope: false,
						GrantScope:         globals.GrantScopeIndividual,
					},
				}
				id, err := newRoleId(ctx)
				require.NoError(t, err)
				role.PublicId = id
				require.NoError(t, rw.Create(ctx, role))
				require.NotEmpty(t, role.PublicId)
				return role
			},
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "role-does-not-exist",
			setupRole: func(ctx context.Context, t *testing.T) *globalRole {
				id, err := newRoleId(ctx)
				require.NoError(t, err)
				role := &globalRole{
					GlobalRole: &store.GlobalRole{
						PublicId:           id,
						ScopeId:            globals.GlobalPrefix,
						Name:               "test-role",
						Description:        "description",
						GrantThisRoleScope: false,
						GrantScope:         globals.GrantScopeIndividual,
					},
				}
				return role
			},
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			createdRole := tc.setupRole(context.Background(), t)
			deletedRows, err := rw.Delete(context.Background(), &globalRole{
				GlobalRole: &store.GlobalRole{
					PublicId: createdRole.PublicId,
				},
			})
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tc.wantRowsDeleted == 0 {
				require.Equal(t, tc.wantRowsDeleted, deletedRows)
				return
			}
			require.Equal(t, tc.wantRowsDeleted, deletedRows)
			foundRole := &globalRole{GlobalRole: &store.GlobalRole{PublicId: createdRole.PublicId}}
			err = rw.LookupByPublicId(context.Background(), foundRole)
			require.Error(t, err)
			require.True(t, errors.IsNotFoundError(err))

			// also check that base table was deleted
			baseRole := &testBaseRole{PublicId: createdRole.PublicId}
			err = rw.LookupByPublicId(context.Background(), baseRole)
			require.Error(t, err)
			require.True(t, errors.IsNotFoundError(err))
		})
	}
}

func Test_globalRole_Actions(t *testing.T) {
	r := allocGlobalRole()
	a := r.Actions()
	assert.Equal(t, a[action.Create.String()], action.Create)
	assert.Equal(t, a[action.Update.String()], action.Update)
	assert.Equal(t, a[action.Read.String()], action.Read)
	assert.Equal(t, a[action.Delete.String()], action.Delete)
	assert.Equal(t, a[action.AddGrants.String()], action.AddGrants)
	assert.Equal(t, a[action.RemoveGrants.String()], action.RemoveGrants)
	assert.Equal(t, a[action.SetGrants.String()], action.SetGrants)
	assert.Equal(t, a[action.AddPrincipals.String()], action.AddPrincipals)
	assert.Equal(t, a[action.RemovePrincipals.String()], action.RemovePrincipals)
	assert.Equal(t, a[action.SetPrincipals.String()], action.SetPrincipals)
}

func Test_globalRole_ResourceType(t *testing.T) {
	t.Parallel()
	role := allocGlobalRole()
	result := role.GetResourceType()
	assert.Equal(t, result, resource.Role)
}

func Test_globalRole_GetScope(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	ctx := context.Background()
	rw := db.New(conn)
	role := globalRole{
		GlobalRole: &store.GlobalRole{
			ScopeId:            globals.GlobalPrefix,
			Name:               "test-role",
			Description:        "description",
			GrantThisRoleScope: false,
			GrantScope:         globals.GrantScopeIndividual,
		},
	}
	id, err := newRoleId(ctx)
	require.NoError(t, err)
	role.PublicId = id
	require.NoError(t, rw.Create(ctx, role))
	require.NotEmpty(t, role.PublicId)
	scope, err := role.GetScope(context.Background(), rw)
	require.NoError(t, err)
	require.Equal(t, scope.GetPublicId(), role.GetScopeId())
}

func Test_globalRole_Clone(t *testing.T) {
	t.Parallel()
	role1 := &globalRole{
		GlobalRole: &store.GlobalRole{
			PublicId:                     "r_123456",
			ScopeId:                      "global",
			Name:                         "test-role",
			Description:                  "description",
			GrantThisRoleScope:           true,
			GrantScope:                   globals.GrantScopeChildren,
			GrantThisRoleScopeUpdateTime: timestamp.New(time.Date(2025, 2, 12, 3, 15, 15, 30, time.UTC)),
			GrantScopeUpdateTime:         timestamp.New(time.Date(2025, 3, 12, 3, 15, 15, 30, time.UTC)),
			CreateTime:                   timestamp.New(time.Date(2025, 4, 12, 3, 15, 15, 30, time.UTC)),
			UpdateTime:                   timestamp.New(time.Date(2025, 5, 12, 3, 15, 15, 30, time.UTC)),
			Version:                      1,
		},
		GrantScopes: []*RoleGrantScope{
			{
				CreateTime:       timestamp.New(time.Date(2025, 3, 12, 3, 15, 15, 30, time.UTC)),
				RoleId:           "r_123456",
				ScopeIdOrSpecial: "children",
			},
			{
				CreateTime:       timestamp.New(time.Date(2025, 1, 14, 3, 15, 15, 30, time.UTC)),
				RoleId:           "r_123456",
				ScopeIdOrSpecial: "p_123456",
			},
		},
	}
	role2 := &globalRole{
		GlobalRole: &store.GlobalRole{
			PublicId:                     "r_abcdef",
			ScopeId:                      "o_123456",
			Name:                         "another-role",
			Description:                  "different description",
			GrantThisRoleScope:           true,
			GrantScope:                   globals.GrantScopeChildren,
			GrantThisRoleScopeUpdateTime: timestamp.New(time.Date(2024, 2, 12, 3, 15, 15, 30, time.UTC)),
			GrantScopeUpdateTime:         timestamp.New(time.Date(2024, 3, 12, 3, 15, 15, 30, time.UTC)),
			CreateTime:                   timestamp.New(time.Date(2024, 4, 12, 3, 15, 15, 30, time.UTC)),
			UpdateTime:                   timestamp.New(time.Date(2024, 5, 12, 3, 15, 15, 30, time.UTC)),
			Version:                      1,
		},
		GrantScopes: []*RoleGrantScope{
			{
				CreateTime:       timestamp.New(time.Date(2024, 3, 12, 3, 15, 15, 30, time.UTC)),
				RoleId:           "r_abcdef",
				ScopeIdOrSpecial: "children",
			},
			{
				CreateTime:       timestamp.New(time.Date(2024, 1, 14, 3, 15, 15, 30, time.UTC)),
				RoleId:           "r_abcdef",
				ScopeIdOrSpecial: "p_abcdef",
			},
		},
	}
	require.NotEqual(t, role1, role2)

	t.Run("valid", func(t *testing.T) {
		clone := role1.Clone()
		assert.True(t, proto.Equal(clone.(*globalRole).GlobalRole, role1.GlobalRole))
		assert.Equal(t, clone.(*globalRole).GrantScopes, role1.GrantScopes)
	})
	t.Run("not-equal", func(t *testing.T) {
		role1Clone := role1.Clone()
		assert.True(t, !proto.Equal(role1Clone.(*globalRole).GlobalRole, role2.GlobalRole))
		assert.NotEqual(t, role1Clone.(*globalRole).GrantScopes, role2.GrantScopes)
	})
}

func Test_globalRole_SetTableName(t *testing.T) {
	defaultTableName := defaultGlobalRoleTableName
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
			def := allocGlobalRole()
			require.Equal(t, defaultTableName, def.TableName())
			s := &globalRole{
				GlobalRole: &store.GlobalRole{},
				tableName:  tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(t, tt.want, s.TableName())
		})
	}
}

func Test_orgRole_Create(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	type args struct {
		role *orgRole
	}
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	org2 := TestOrg(t, repo)
	rw := db.New(conn)
	tests := []struct {
		name       string
		args       args
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "can create valid role in org grants scope individual",
			args: args{
				role: func() *orgRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					r := &orgRole{
						OrgRole: &store.OrgRole{
							PublicId:           grpId,
							ScopeId:            org.PublicId,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
							GrantThisRoleScope: false,
							GrantScope:         globals.GrantScopeIndividual,
						},
					}
					return r
				}(),
			},
			wantErr: false,
		},
		{
			name: "can create valid role in org grants scope children",
			args: args{
				role: func() *orgRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					r := &orgRole{
						OrgRole: &store.OrgRole{
							PublicId:           grpId,
							ScopeId:            org.PublicId,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
							GrantThisRoleScope: true,
							GrantScope:         globals.GrantScopeChildren,
						},
					}
					return r
				}(),
			},
			wantErr: false,
		},
		{
			name: "duplicate name different scope allowed",
			args: args{
				role: func() *orgRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					// create a role then return the cloned role with different name
					r := &orgRole{
						OrgRole: &store.OrgRole{
							PublicId:           grpId,
							ScopeId:            org.PublicId,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
							GrantThisRoleScope: true,
							GrantScope:         globals.GrantScopeChildren,
						},
					}

					require.NoError(t, rw.Create(ctx, r))
					newId, err := newRoleId(ctx)
					require.NoError(t, err)
					dupeName := r.Clone().(*orgRole)
					dupeName.PublicId = newId
					dupeName.ScopeId = org2.PublicId
					dupeName.GrantThisRoleScope = false
					dupeName.GrantScope = globals.GrantScopeChildren
					return dupeName
				}(),
			},
			wantErr: false,
		},
		{
			name: "cannot create valid role in org grants scope descendants",
			args: args{
				role: func() *orgRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					r := &orgRole{
						OrgRole: &store.OrgRole{
							PublicId:           grpId,
							ScopeId:            org.PublicId,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
							GrantThisRoleScope: true,
							GrantScope:         globals.GrantScopeDescendants,
						},
					}
					return r
				}(),
			},
			wantErr:    true,
			wantErrMsg: `db.Create: insert or update on table "iam_role_org" violates foreign key constraint "iam_role_org_grant_scope_enm_fkey": integrity violation: error #1003`,
		},
		{
			name: "cannot create role in org with descendants grants",
			args: args{
				role: func() *orgRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					r := &orgRole{
						OrgRole: &store.OrgRole{
							PublicId:           grpId,
							ScopeId:            org.PublicId,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
							GrantThisRoleScope: true,
							GrantScope:         globals.GrantScopeDescendants,
						},
					}
					return r
				}(),
			},
			wantErr:    true,
			wantErrMsg: `db.Create: insert or update on table "iam_role_org" violates foreign key constraint "iam_role_org_grant_scope_enm_fkey": integrity violation: error #1003`,
		},
		{
			name: "cannot create role in global",
			args: args{
				role: func() *orgRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					r := &orgRole{
						OrgRole: &store.OrgRole{
							PublicId:           grpId,
							ScopeId:            globals.GlobalPrefix,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
							GrantThisRoleScope: true,
							GrantScope:         globals.GrantScopeChildren,
						},
					}
					return r
				}(),
			},
			wantErr:    true,
			wantErrMsg: `db.Create: insert or update on table "iam_role_org" violates foreign key constraint "iam_scope_org_fkey": integrity violation: error #1003`,
		},
		{
			name: "cannot create role in project",
			args: args{
				role: func() *orgRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					r := &orgRole{
						OrgRole: &store.OrgRole{
							PublicId:           grpId,
							ScopeId:            proj.PublicId,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
							GrantThisRoleScope: true,
							GrantScope:         globals.GrantScopeDescendants,
						},
					}
					return r
				}(),
			},
			wantErr:    true,
			wantErrMsg: `db.Create: insert or update on table "iam_role_org" violates foreign key constraint "iam_scope_org_fkey": integrity violation: error #1003`,
		},
		{
			name: "invalid grants scope",
			args: args{
				role: func() *orgRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					r := &orgRole{
						OrgRole: &store.OrgRole{
							PublicId:           grpId,
							ScopeId:            org.PublicId,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
							GrantThisRoleScope: true,
							GrantScope:         "invalid-scope",
						},
					}
					return r
				}(),
			},
			wantErr:    true,
			wantErrMsg: `db.Create: insert or update on table "iam_role_org" violates foreign key constraint "iam_role_org_grant_scope_enm_fkey": integrity violation: error #1003`,
		},
		{
			name: "duplicate name not allowed",
			args: args{
				role: func() *orgRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					// create a role then return the cloned role with different name
					r := &orgRole{
						OrgRole: &store.OrgRole{
							PublicId:           grpId,
							ScopeId:            org.PublicId,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
							GrantThisRoleScope: true,
							GrantScope:         globals.GrantScopeChildren,
						},
					}

					require.NoError(t, rw.Create(ctx, r))
					newId, err := newRoleId(ctx)
					require.NoError(t, err)
					dupeName := r.Clone().(*orgRole)
					dupeName.PublicId = newId
					dupeName.GrantThisRoleScope = false
					dupeName.GrantScope = globals.GrantScopeChildren
					return dupeName
				}(),
			},
			wantErr:    true,
			wantErrMsg: `db.Create: duplicate key value violates unique constraint "iam_role_org_name_scope_id_uq": unique constraint violation: integrity violation: error #1002`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.args.role.Clone().(*orgRole)
			err := rw.Create(ctx, r)
			if tt.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.wantErrMsg)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, tt.args.role.PublicId)

			foundGrp := allocOrgRole()
			foundGrp.PublicId = tt.args.role.PublicId
			err = rw.LookupByPublicId(ctx, &foundGrp)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(r, &foundGrp, protocmp.Transform()))

			require.NotEmpty(t, foundGrp.GrantScopeUpdateTime)
			require.NotEmpty(t, foundGrp.GrantThisRoleScopeUpdateTime)
			require.NotZero(t, foundGrp.CreateTime.AsTime())
			require.NotZero(t, foundGrp.UpdateTime.AsTime())

			baseRole := testBaseRole{PublicId: tt.args.role.PublicId}
			err = rw.LookupByPublicId(ctx, &baseRole)
			require.NoError(t, err)
			require.Equal(t, foundGrp.CreateTime.AsTime(), baseRole.CreateTime.AsTime())
			require.Equal(t, foundGrp.UpdateTime.AsTime(), baseRole.UpdateTime.AsTime())
		})
	}
}

func Test_orgRole_Update(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org := TestOrg(t, repo)
	type arg struct {
		updateRole *orgRole
		fieldMask  []string
		nullPath   []string
		opts       []db.Option
	}
	tests := []struct {
		name           string
		setupOriginal  func(t *testing.T) *orgRole
		createInput    func(t *testing.T, original *orgRole) arg
		wantErr        bool
		wantRowsUpdate int
		wantErrMsg     string
	}{
		{
			name: "can update name and description",
			setupOriginal: func(t *testing.T) *orgRole {
				roleId, err := newRoleId(ctx)
				require.NoError(t, err)
				original := &orgRole{
					OrgRole: &store.OrgRole{
						PublicId:           roleId,
						ScopeId:            org.PublicId,
						Name:               testId(t),
						Description:        testId(t),
						GrantThisRoleScope: false,
						GrantScope:         globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, original))
				return original
			},
			createInput: func(t *testing.T, original *orgRole) arg {
				updated := original.Clone().(*orgRole)
				updated.Name = testId(t)
				updated.Description = testId(t)
				return arg{
					updateRole: updated,
					fieldMask:  []string{"name", "description"},
					nullPath:   []string{},
					opts:       []db.Option{},
				}
			},
			wantRowsUpdate: 1,
			wantErr:        false,
		},
		{
			name: "can update grant_scope",
			setupOriginal: func(t *testing.T) *orgRole {
				roleId, err := newRoleId(ctx)
				require.NoError(t, err)
				original := &orgRole{
					OrgRole: &store.OrgRole{
						PublicId:           roleId,
						ScopeId:            org.PublicId,
						Name:               testId(t),
						Description:        "desc",
						GrantThisRoleScope: false,
						GrantScope:         globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, original))
				return original
			},
			createInput: func(t *testing.T, original *orgRole) arg {
				updated := original.Clone().(*orgRole)
				updated.GrantScope = globals.GrantScopeChildren
				return arg{
					updateRole: updated,
					fieldMask:  []string{"GrantScope"},
					nullPath:   []string{},
					opts:       []db.Option{},
				}
			},
			wantRowsUpdate: 1,
			wantErr:        false,
		},
		{
			name: "can set name and description null",
			setupOriginal: func(t *testing.T) *orgRole {
				roleId, err := newRoleId(ctx)
				require.NoError(t, err)
				original := &orgRole{
					OrgRole: &store.OrgRole{
						PublicId:           roleId,
						ScopeId:            org.PublicId,
						Name:               testId(t),
						Description:        "desc",
						GrantThisRoleScope: false,
						GrantScope:         globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, original))
				return original
			},
			createInput: func(t *testing.T, original *orgRole) arg {
				updated := original.Clone().(*orgRole)
				updated.Name = ""
				updated.Description = ""
				return arg{
					updateRole: updated,
					fieldMask:  []string{},
					nullPath:   []string{"name", "description"},
					opts:       []db.Option{},
				}
			},
			wantRowsUpdate: 1,
			wantErr:        false,
		},
		{
			name: "can update grant_this_role_scope",
			setupOriginal: func(t *testing.T) *orgRole {
				roleId, err := newRoleId(ctx)
				require.NoError(t, err)
				original := &orgRole{
					OrgRole: &store.OrgRole{
						PublicId:           roleId,
						ScopeId:            org.PublicId,
						Name:               testId(t),
						Description:        "desc",
						GrantThisRoleScope: true,
						GrantScope:         globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, original))
				return original
			},
			createInput: func(t *testing.T, original *orgRole) arg {
				updated := original.Clone().(*orgRole)
				updated.GrantThisRoleScope = false
				return arg{
					updateRole: updated,
					fieldMask:  []string{"GrantThisRoleScope"},
					nullPath:   []string{},
					opts:       []db.Option{},
				}
			},
			wantRowsUpdate: 1,
			wantErr:        false,
		},
		{
			name: "can update version",
			setupOriginal: func(t *testing.T) *orgRole {
				roleId, err := newRoleId(ctx)
				require.NoError(t, err)
				original := &orgRole{
					OrgRole: &store.OrgRole{
						PublicId:           roleId,
						ScopeId:            org.PublicId,
						Name:               testId(t),
						Description:        "desc",
						GrantThisRoleScope: true,
						GrantScope:         globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, original))
				return original
			},
			createInput: func(t *testing.T, original *orgRole) arg {
				updated := original.Clone().(*orgRole)
				updated.Version = uint32(15)
				return arg{
					updateRole: updated,
					fieldMask:  []string{"version"},
					nullPath:   []string{},
					opts:       []db.Option{},
				}
			},
			wantRowsUpdate: 1,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := tt.setupOriginal(t)
			args := tt.createInput(t, original)
			updatedRows, err := rw.Update(context.Background(), args.updateRole, args.fieldMask, args.nullPath, args.opts...)
			if tt.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.wantErrMsg)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, args.updateRole.PublicId)
			if tt.wantRowsUpdate == 0 {
				require.Zero(t, updatedRows)
				return
			}
			require.Equal(t, tt.wantRowsUpdate, updatedRows)

			foundGrp := allocOrgRole()
			foundGrp.PublicId = original.PublicId
			err = rw.LookupByPublicId(ctx, &foundGrp)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(args.updateRole, &foundGrp, protocmp.Transform()))
			// also check that base table was deleted
			baseRole := &testBaseRole{PublicId: original.PublicId}
			err = rw.LookupByPublicId(ctx, baseRole)
			require.NoError(t, err)
			require.Equal(t, foundGrp.UpdateTime.AsTime(), baseRole.UpdateTime.AsTime())
			require.Equal(t, original.Version+1, foundGrp.Version)
			require.Equal(t, foundGrp.UpdateTime.AsTime(), baseRole.UpdateTime.AsTime())
			// assert other update time as necessary
			if original.GrantThisRoleScope != args.updateRole.GrantThisRoleScope {
				require.Greater(t, foundGrp.GrantThisRoleScopeUpdateTime.AsTime(), original.GrantThisRoleScopeUpdateTime.AsTime())
			}
			if original.GrantScope != args.updateRole.GrantScope {
				require.Greater(t, foundGrp.GrantScopeUpdateTime.AsTime(), original.GrantScopeUpdateTime.AsTime())
			}
		})
	}
}

func Test_orgRole_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org := TestOrg(t, repo)
	tests := []struct {
		name            string
		setupRole       func(ctx context.Context, t *testing.T) *orgRole
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name: "valid",
			setupRole: func(ctx context.Context, t *testing.T) *orgRole {
				role := &orgRole{
					OrgRole: &store.OrgRole{
						ScopeId:            org.PublicId,
						Name:               "test-role",
						Description:        "description",
						GrantThisRoleScope: false,
						GrantScope:         globals.GrantScopeIndividual,
					},
				}
				id, err := newRoleId(ctx)
				require.NoError(t, err)
				role.PublicId = id
				require.NoError(t, rw.Create(ctx, role))
				require.NotEmpty(t, role.PublicId)
				return role
			},
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "role-does-not-exist",
			setupRole: func(ctx context.Context, t *testing.T) *orgRole {
				id, err := newRoleId(ctx)
				require.NoError(t, err)
				role := &orgRole{
					OrgRole: &store.OrgRole{
						PublicId:           id,
						ScopeId:            org.PublicId,
						Name:               "test-role",
						Description:        "description",
						GrantThisRoleScope: false,
						GrantScope:         globals.GrantScopeIndividual,
					},
				}
				return role
			},
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			createdRole := tc.setupRole(context.Background(), t)
			deletedRows, err := rw.Delete(context.Background(), &orgRole{
				OrgRole: &store.OrgRole{
					PublicId: createdRole.PublicId,
				},
			})
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tc.wantRowsDeleted == 0 {
				require.Equal(t, tc.wantRowsDeleted, deletedRows)
				return
			}
			require.Equal(t, tc.wantRowsDeleted, deletedRows)
			foundRole := &orgRole{OrgRole: &store.OrgRole{PublicId: createdRole.PublicId}}
			err = rw.LookupByPublicId(context.Background(), foundRole)
			require.Error(t, err)
			require.True(t, errors.IsNotFoundError(err))

			// also check that base table was deleted
			baseRole := &testBaseRole{PublicId: createdRole.PublicId}
			err = rw.LookupByPublicId(context.Background(), baseRole)
			require.Error(t, err)
			require.True(t, errors.IsNotFoundError(err))
		})
	}
}

func Test_orgRole_Actions(t *testing.T) {
	r := &orgRole{}
	a := r.Actions()
	assert.Equal(t, a[action.Create.String()], action.Create)
	assert.Equal(t, a[action.Update.String()], action.Update)
	assert.Equal(t, a[action.Read.String()], action.Read)
	assert.Equal(t, a[action.Delete.String()], action.Delete)
	assert.Equal(t, a[action.AddGrants.String()], action.AddGrants)
	assert.Equal(t, a[action.RemoveGrants.String()], action.RemoveGrants)
	assert.Equal(t, a[action.SetGrants.String()], action.SetGrants)
	assert.Equal(t, a[action.AddPrincipals.String()], action.AddPrincipals)
	assert.Equal(t, a[action.RemovePrincipals.String()], action.RemovePrincipals)
	assert.Equal(t, a[action.SetPrincipals.String()], action.SetPrincipals)
}

func Test_orgRole_ResourceType(t *testing.T) {
	t.Parallel()
	role := orgRole{}
	result := role.GetResourceType()
	assert.Equal(t, result, resource.Role)
}

func Test_orgRole_GetScope(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	ctx := context.Background()
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org := TestOrg(t, repo)
	role := orgRole{
		OrgRole: &store.OrgRole{
			ScopeId:            org.PublicId,
			Name:               "test-role",
			Description:        "description",
			GrantThisRoleScope: false,
			GrantScope:         globals.GrantScopeIndividual,
		},
	}
	id, err := newRoleId(ctx)
	require.NoError(t, err)
	role.PublicId = id
	require.NoError(t, rw.Create(ctx, role))
	require.NotEmpty(t, role.PublicId)
	scope, err := role.GetScope(context.Background(), rw)
	require.NoError(t, err)
	require.True(t, proto.Equal(org, scope))
}

func Test_orgRole_Clone(t *testing.T) {
	t.Parallel()
	role1 := &orgRole{
		OrgRole: &store.OrgRole{
			PublicId:                     "r_123456",
			ScopeId:                      "o_123456",
			Name:                         "test-role",
			Description:                  "description",
			GrantThisRoleScope:           true,
			GrantScope:                   globals.GrantScopeChildren,
			GrantThisRoleScopeUpdateTime: timestamp.New(time.Date(2025, 2, 12, 3, 15, 15, 30, time.UTC)),
			GrantScopeUpdateTime:         timestamp.New(time.Date(2025, 3, 12, 3, 15, 15, 30, time.UTC)),
			CreateTime:                   timestamp.New(time.Date(2025, 4, 12, 3, 15, 15, 30, time.UTC)),
			UpdateTime:                   timestamp.New(time.Date(2025, 5, 12, 3, 15, 15, 30, time.UTC)),
			Version:                      1,
		},
		GrantScopes: []*RoleGrantScope{
			{
				CreateTime:       timestamp.New(time.Date(2025, 3, 12, 3, 15, 15, 30, time.UTC)),
				RoleId:           "r_123456",
				ScopeIdOrSpecial: "children",
			},
			{
				CreateTime:       timestamp.New(time.Date(2025, 1, 14, 3, 15, 15, 30, time.UTC)),
				RoleId:           "r_123456",
				ScopeIdOrSpecial: "p_123456",
			},
		},
	}
	role2 := &orgRole{
		OrgRole: &store.OrgRole{
			PublicId:                     "r_abcdef",
			ScopeId:                      "o_abcdef",
			Name:                         "another-role",
			Description:                  "different description",
			GrantThisRoleScope:           true,
			GrantScope:                   globals.GrantScopeChildren,
			GrantThisRoleScopeUpdateTime: timestamp.New(time.Date(2024, 2, 12, 3, 15, 15, 30, time.UTC)),
			GrantScopeUpdateTime:         timestamp.New(time.Date(2024, 3, 12, 3, 15, 15, 30, time.UTC)),
			CreateTime:                   timestamp.New(time.Date(2024, 4, 12, 3, 15, 15, 30, time.UTC)),
			UpdateTime:                   timestamp.New(time.Date(2024, 5, 12, 3, 15, 15, 30, time.UTC)),
			Version:                      1,
		},
		GrantScopes: []*RoleGrantScope{
			{
				CreateTime:       timestamp.New(time.Date(2024, 3, 12, 3, 15, 15, 30, time.UTC)),
				RoleId:           "r_abcdef",
				ScopeIdOrSpecial: "children",
			},
			{
				CreateTime:       timestamp.New(time.Date(2024, 1, 14, 3, 15, 15, 30, time.UTC)),
				RoleId:           "r_abcdef",
				ScopeIdOrSpecial: "p_abcdef",
			},
		},
	}
	require.NotEqual(t, role1, role2)

	t.Run("valid", func(t *testing.T) {
		clone := role1.Clone()
		assert.True(t, proto.Equal(clone.(*orgRole).OrgRole, role1.OrgRole))
		assert.Equal(t, clone.(*orgRole).GrantScopes, role1.GrantScopes)
	})
	t.Run("not-equal", func(t *testing.T) {
		role1Clone := role1.Clone()
		assert.True(t, !proto.Equal(role1Clone.(*orgRole).OrgRole, role2.OrgRole))
		assert.NotEqual(t, role1Clone.(*orgRole).GrantScopes, role2.GrantScopes)
	})
}

func Test_orgRole_SetTableName(t *testing.T) {
	defaultTableName := defaultOrgRoleTableName
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
			def := orgRole{}
			require.Equal(t, defaultTableName, def.TableName())
			s := &orgRole{
				OrgRole:   &store.OrgRole{},
				tableName: tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(t, tt.want, s.TableName())
		})
	}
}

func Test_projectRole_Create(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	type args struct {
		role *projectRole
	}
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	proj2 := TestProject(t, repo, org.PublicId)
	rw := db.New(conn)
	tests := []struct {
		name       string
		args       args
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "can create valid role in project",
			args: args{
				role: func() *projectRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					r := &projectRole{
						ProjectRole: &store.ProjectRole{
							PublicId:           grpId,
							ScopeId:            proj.PublicId,
							GrantThisRoleScope: false,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
						},
					}
					return r
				}(),
			},
			wantErr: false,
		},
		{
			name: "duplicate name different scope allowed",
			args: args{
				role: func() *projectRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					// create a role then return the cloned role with different name
					r := &projectRole{
						ProjectRole: &store.ProjectRole{
							PublicId:           grpId,
							ScopeId:            proj.PublicId,
							GrantThisRoleScope: true,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
						},
					}

					require.NoError(t, rw.Create(ctx, r))
					newId, err := newRoleId(ctx)
					require.NoError(t, err)
					dupeName := r.Clone().(*projectRole)
					dupeName.PublicId = newId
					dupeName.ScopeId = proj2.PublicId
					return dupeName
				}(),
			},
			wantErr: false,
		},
		{
			name: "cannot create role in global",
			args: args{
				role: func() *projectRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					r := &projectRole{
						ProjectRole: &store.ProjectRole{
							PublicId:           grpId,
							GrantThisRoleScope: true,
							ScopeId:            globals.GlobalPrefix,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
						},
					}
					return r
				}(),
			},
			wantErr:    true,
			wantErrMsg: `db.Create: insert or update on table "iam_role_project" violates foreign key constraint "iam_scope_project_fkey": integrity violation: error #1003`,
		},
		{
			name: "cannot create role in org",
			args: args{
				role: func() *projectRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					r := &projectRole{
						ProjectRole: &store.ProjectRole{
							PublicId:    grpId,
							ScopeId:     org.PublicId,
							Name:        "name" + randomUuid,
							Description: "desc" + randomUuid,
						},
					}
					return r
				}(),
			},
			wantErr:    true,
			wantErrMsg: `db.Create: insert or update on table "iam_role_project" violates foreign key constraint "iam_scope_project_fkey": integrity violation: error #1003`,
		},
		{
			name: "duplicate name same scope not allowed",
			args: args{
				role: func() *projectRole {
					randomUuid := testId(t)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					// create a role then return the cloned role with different name
					r := &projectRole{
						ProjectRole: &store.ProjectRole{
							PublicId:           grpId,
							GrantThisRoleScope: true,
							ScopeId:            proj.PublicId,
							Name:               "name" + randomUuid,
							Description:        "desc" + randomUuid,
						},
					}

					require.NoError(t, rw.Create(ctx, r))
					newId, err := newRoleId(ctx)
					require.NoError(t, err)
					dupeName := r.Clone().(*projectRole)
					dupeName.PublicId = newId
					return dupeName
				}(),
			},
			wantErr:    true,
			wantErrMsg: `db.Create: duplicate key value violates unique constraint "iam_role_project_name_scope_id_uq": unique constraint violation: integrity violation: error #1002`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.args.role.Clone().(*projectRole)
			err := rw.Create(ctx, r)
			if tt.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.wantErrMsg)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, tt.args.role.PublicId)

			foundGrp := allocProjectRole()
			foundGrp.PublicId = tt.args.role.PublicId
			err = rw.LookupByPublicId(ctx, &foundGrp)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(r, &foundGrp, protocmp.Transform()))
			require.NotZero(t, foundGrp.CreateTime.AsTime())
			require.NotZero(t, foundGrp.UpdateTime.AsTime())
			baseRole := &testBaseRole{PublicId: tt.args.role.PublicId}
			err = rw.LookupByPublicId(ctx, baseRole)
			require.NoError(t, err)
			require.Equal(t, foundGrp.CreateTime.AsTime(), baseRole.CreateTime.AsTime())
			require.Equal(t, foundGrp.UpdateTime.AsTime(), baseRole.UpdateTime.AsTime())
		})
	}
}

func Test_projectRole_Update(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	_, proj := TestScopes(t, repo)
	type arg struct {
		updateRole *projectRole
		fieldMask  []string
		nullPath   []string
		opts       []db.Option
	}
	tests := []struct {
		name           string
		setupOriginal  func(t *testing.T) *projectRole
		createInput    func(t *testing.T, original *projectRole) arg
		wantErr        bool
		wantRowsUpdate int
		wantErrMsg     string
	}{
		{
			name: "can update name and description",
			setupOriginal: func(t *testing.T) *projectRole {
				roleId, err := newRoleId(ctx)
				require.NoError(t, err)
				original := &projectRole{
					ProjectRole: &store.ProjectRole{
						PublicId:    roleId,
						ScopeId:     proj.PublicId,
						Name:        testId(t),
						Description: testId(t),
					},
				}
				require.NoError(t, rw.Create(ctx, original))
				return original
			},
			createInput: func(t *testing.T, original *projectRole) arg {
				updated := original.Clone().(*projectRole)
				updated.Name = testId(t)
				updated.Description = testId(t)
				return arg{
					updateRole: updated,
					fieldMask:  []string{"name", "description"},
					nullPath:   []string{},
					opts:       []db.Option{},
				}
			},
			wantRowsUpdate: 1,
			wantErr:        false,
		},
		{
			name: "can set name and description null",
			setupOriginal: func(t *testing.T) *projectRole {
				roleId, err := newRoleId(ctx)
				require.NoError(t, err)
				original := &projectRole{
					ProjectRole: &store.ProjectRole{
						PublicId:    roleId,
						ScopeId:     proj.PublicId,
						Name:        testId(t),
						Description: "desc",
					},
				}
				require.NoError(t, rw.Create(ctx, original))
				return original
			},
			createInput: func(t *testing.T, original *projectRole) arg {
				updated := original.Clone().(*projectRole)
				updated.Name = ""
				updated.Description = ""
				return arg{
					updateRole: updated,
					fieldMask:  []string{},
					nullPath:   []string{"name", "description"},
					opts:       []db.Option{},
				}
			},
			wantRowsUpdate: 1,
			wantErr:        false,
		},
		{
			name: "can update grant_this_role_scope",
			setupOriginal: func(t *testing.T) *projectRole {
				roleId, err := newRoleId(ctx)
				require.NoError(t, err)
				original := &projectRole{
					ProjectRole: &store.ProjectRole{
						PublicId:           roleId,
						ScopeId:            proj.PublicId,
						Name:               testId(t),
						Description:        "desc",
						GrantThisRoleScope: true,
					},
				}
				require.NoError(t, rw.Create(ctx, original))
				return original
			},
			createInput: func(t *testing.T, original *projectRole) arg {
				updated := original.Clone().(*projectRole)
				updated.GrantThisRoleScope = false
				return arg{
					updateRole: updated,
					fieldMask:  []string{"GrantThisRoleScope"},
					nullPath:   []string{},
					opts:       []db.Option{},
				}
			},
			wantRowsUpdate: 1,
			wantErr:        false,
		},
		{
			name: "can update version",
			setupOriginal: func(t *testing.T) *projectRole {
				roleId, err := newRoleId(ctx)
				require.NoError(t, err)
				original := &projectRole{
					ProjectRole: &store.ProjectRole{
						PublicId:    roleId,
						ScopeId:     proj.PublicId,
						Name:        testId(t),
						Description: "desc",
					},
				}
				require.NoError(t, rw.Create(ctx, original))
				return original
			},
			createInput: func(t *testing.T, original *projectRole) arg {
				updated := original.Clone().(*projectRole)
				updated.Version = uint32(15)
				return arg{
					updateRole: updated,
					fieldMask:  []string{"version"},
					nullPath:   []string{},
					opts:       []db.Option{},
				}
			},
			wantRowsUpdate: 1,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := tt.setupOriginal(t)
			args := tt.createInput(t, original)
			updatedRows, err := rw.Update(context.Background(), args.updateRole, args.fieldMask, args.nullPath, args.opts...)
			if tt.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.wantErrMsg)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, args.updateRole.PublicId)
			if tt.wantRowsUpdate == 0 {
				require.Zero(t, updatedRows)
				return
			}
			require.Equal(t, tt.wantRowsUpdate, updatedRows)

			foundGrp := allocProjectRole()
			foundGrp.PublicId = original.PublicId
			err = rw.LookupByPublicId(ctx, &foundGrp)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(args.updateRole, &foundGrp, protocmp.Transform()))
			baseRole := &testBaseRole{PublicId: original.PublicId}
			err = rw.LookupByPublicId(ctx, baseRole)
			require.NoError(t, err)
			require.Equal(t, foundGrp.UpdateTime.AsTime(), baseRole.UpdateTime.AsTime())
			require.Equal(t, original.Version+1, foundGrp.Version)
			require.Equal(t, foundGrp.UpdateTime.AsTime(), baseRole.UpdateTime.AsTime())
		})
	}
}

func Test_projectRole_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	_, proj := TestScopes(t, repo)
	tests := []struct {
		name            string
		setupRole       func(ctx context.Context, t *testing.T) *projectRole
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name: "valid",
			setupRole: func(ctx context.Context, t *testing.T) *projectRole {
				role := &projectRole{
					ProjectRole: &store.ProjectRole{
						ScopeId:     proj.PublicId,
						Name:        "test-role",
						Description: "description",
					},
				}
				id, err := newRoleId(ctx)
				require.NoError(t, err)
				role.PublicId = id
				require.NoError(t, rw.Create(ctx, role))
				require.NotEmpty(t, role.PublicId)
				return role
			},
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "role-does-not-exist",
			setupRole: func(ctx context.Context, t *testing.T) *projectRole {
				id, err := newRoleId(ctx)
				require.NoError(t, err)
				role := &projectRole{
					ProjectRole: &store.ProjectRole{
						PublicId:    id,
						ScopeId:     proj.PublicId,
						Name:        "test-role",
						Description: "description",
					},
				}
				return role
			},
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			createdRole := tc.setupRole(context.Background(), t)
			deletedRows, err := rw.Delete(context.Background(), &projectRole{
				ProjectRole: &store.ProjectRole{
					PublicId: createdRole.PublicId,
				},
			})
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tc.wantRowsDeleted == 0 {
				require.Equal(t, tc.wantRowsDeleted, deletedRows)
				return
			}
			require.Equal(t, tc.wantRowsDeleted, deletedRows)
			foundRole := &projectRole{ProjectRole: &store.ProjectRole{PublicId: createdRole.PublicId}}
			err = rw.LookupByPublicId(context.Background(), foundRole)
			require.Error(t, err)
			require.True(t, errors.IsNotFoundError(err))

			// also check that base table was deleted
			baseRole := &testBaseRole{PublicId: createdRole.PublicId}
			err = rw.LookupByPublicId(context.Background(), baseRole)
			require.Error(t, err)
			require.True(t, errors.IsNotFoundError(err))
		})
	}
}

func Test_projectRole_Actions(t *testing.T) {
	r := &projectRole{}
	a := r.Actions()
	assert.Equal(t, a[action.Create.String()], action.Create)
	assert.Equal(t, a[action.Update.String()], action.Update)
	assert.Equal(t, a[action.Read.String()], action.Read)
	assert.Equal(t, a[action.Delete.String()], action.Delete)
	assert.Equal(t, a[action.AddGrants.String()], action.AddGrants)
	assert.Equal(t, a[action.RemoveGrants.String()], action.RemoveGrants)
	assert.Equal(t, a[action.SetGrants.String()], action.SetGrants)
	assert.Equal(t, a[action.AddPrincipals.String()], action.AddPrincipals)
	assert.Equal(t, a[action.RemovePrincipals.String()], action.RemovePrincipals)
	assert.Equal(t, a[action.SetPrincipals.String()], action.SetPrincipals)
}

func Test_projectRole_ResourceType(t *testing.T) {
	t.Parallel()
	role := projectRole{}
	result := role.GetResourceType()
	assert.Equal(t, result, resource.Role)
}

func Test_projectRole_GetScope(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	ctx := context.Background()
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	_, proj := TestScopes(t, repo)
	role := projectRole{
		ProjectRole: &store.ProjectRole{
			ScopeId:     proj.PublicId,
			Name:        "test-role",
			Description: "description",
		},
	}
	id, err := newRoleId(ctx)
	require.NoError(t, err)
	role.PublicId = id
	require.NoError(t, rw.Create(ctx, role))
	require.NotEmpty(t, role.PublicId)
	scope, err := role.GetScope(context.Background(), rw)
	require.NoError(t, err)
	require.True(t, proto.Equal(proj, scope))
}

func Test_projectRole_Clone(t *testing.T) {
	t.Parallel()
	role1 := &projectRole{
		ProjectRole: &store.ProjectRole{
			PublicId:    "r_123456",
			ScopeId:     "p_123456",
			Name:        "test-role",
			Description: "description",
			CreateTime:  timestamp.New(time.Date(2025, 4, 12, 3, 15, 15, 30, time.UTC)),
			UpdateTime:  timestamp.New(time.Date(2025, 5, 12, 3, 15, 15, 30, time.UTC)),
			Version:     1,
		},
		GrantScopes: []*RoleGrantScope{
			{
				CreateTime:       timestamp.New(time.Date(2025, 3, 12, 3, 15, 15, 30, time.UTC)),
				RoleId:           "r_123456",
				ScopeIdOrSpecial: "this",
			},
		},
	}
	role2 := &projectRole{
		ProjectRole: &store.ProjectRole{
			PublicId:    "r_abcdef",
			ScopeId:     "o_123456",
			Name:        "another-role",
			Description: "different description",
			CreateTime:  timestamp.New(time.Date(2024, 4, 12, 3, 15, 15, 30, time.UTC)),
			UpdateTime:  timestamp.New(time.Date(2024, 5, 12, 3, 15, 15, 30, time.UTC)),
			Version:     1,
		},
		GrantScopes: []*RoleGrantScope{
			{
				CreateTime:       timestamp.New(time.Date(2024, 3, 12, 3, 15, 15, 30, time.UTC)),
				RoleId:           "r_abcdef",
				ScopeIdOrSpecial: "children",
			},
			{
				CreateTime:       timestamp.New(time.Date(2024, 1, 14, 3, 15, 15, 30, time.UTC)),
				RoleId:           "r_abcdef",
				ScopeIdOrSpecial: "p_abcdef",
			},
		},
	}
	require.NotEqual(t, role1, role2)

	t.Run("valid", func(t *testing.T) {
		clone := role1.Clone()
		assert.True(t, proto.Equal(clone.(*projectRole).ProjectRole, role1.ProjectRole))
		assert.Equal(t, clone.(*projectRole).GrantScopes, role1.GrantScopes)
	})
	t.Run("not-equal", func(t *testing.T) {
		role1Clone := role1.Clone()
		assert.True(t, !proto.Equal(role1Clone.(*projectRole).ProjectRole, role2.ProjectRole))
		assert.NotEqual(t, role1Clone.(*projectRole).GrantScopes, role2.GrantScopes)
	})
}

func Test_projectRole_SetTableName(t *testing.T) {
	defaultTableName := defaultProjectRoleTableName
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
			def := projectRole{}
			require.Equal(t, defaultTableName, def.TableName())
			s := &projectRole{
				ProjectRole: &store.ProjectRole{},
				tableName:   tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(t, tt.want, s.TableName())
		})
	}
}

// testBaseRole is used to interact with `iam_role` table for testing purposes
type testBaseRole struct {
	PublicId   string `gorm:"primary_key"`
	ScopeId    string
	CreateTime *timestamp.Timestamp
	UpdateTime *timestamp.Timestamp
}

func (t *testBaseRole) GetPublicId() string {
	if t == nil {
		return ""
	}
	return t.PublicId
}

func (t *testBaseRole) TableName() string {
	return "iam_role"
}
