// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_CreateRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	id := testId(t)

	org, proj := TestScopes(t, repo)
	dupeOrg, dupeProj := TestScopes(t, repo)

	type args struct {
		role *Role
		opt  []Option
	}
	tests := []struct {
		name        string
		args        args
		dupeSetup   func(*testing.T) *Role
		wantErr     bool
		wantErrMsg  string
		wantIsError errors.Code
	}{
		{
			name: "valid-global",
			args: args{
				role: func() *Role {
					r, err := NewRole(ctx, globals.GlobalPrefix, WithName("valid-global"+id), WithDescription(id))
					assert.NoError(t, err)
					return r
				}(),
			},
			wantErr: false,
		},
		{
			name: "valid-org",
			args: args{
				role: func() *Role {
					r, err := NewRole(ctx, org.PublicId, WithName("valid-org"+id), WithDescription(id))
					assert.NoError(t, err)
					return r
				}(),
			},
			wantErr: false,
		},
		{
			name: "valid-proj",
			args: args{
				role: func() *Role {
					r, err := NewRole(ctx, proj.PublicId, WithName("valid-proj"+id), WithDescription(id))
					assert.NoError(t, err)
					return r
				}(),
			},
			wantErr: false,
		},
		{
			name: "bad-public-id",
			args: args{
				role: func() *Role {
					r, err := NewRole(ctx, proj.PublicId, WithName("valid-proj"+id), WithDescription(id))
					assert.NoError(t, err)
					r.PublicId = id
					return r
				}(),
			},
			wantErrMsg:  "am.(Repository).CreateRole: public id not empty: parameter violation: error #100",
			wantIsError: errors.InvalidParameter,
			wantErr:     true,
		},
		{
			name: "nil-role",
			args: args{
				role: nil,
			},
			wantErr:     true,
			wantErrMsg:  "iam.(Repository).CreateRole: missing role: parameter violation: error #100",
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "bad-scope-id",
			args: args{
				role: func() *Role {
					r, err := NewRole(ctx, id)
					assert.NoError(t, err)
					return r
				}(),
			},
			wantErr:     true,
			wantErrMsg:  "iam.(Repository).CreateRole: invalid scope type: parameter violation: error #100",
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "global-dup-name",
			args: args{
				role: func() *Role {
					r, err := NewRole(ctx, globals.GlobalPrefix, WithName("global-dup-name"+id), WithDescription(id))
					assert.NoError(t, err)
					return r
				}(),
				opt: []Option{WithName("dup-name" + id)},
			},
			dupeSetup: func(t *testing.T) *Role {
				r, err := NewRole(ctx, globals.GlobalPrefix, WithName("global-dup-name"+id), WithDescription(id))
				require.NoError(t, err)
				dup, _, _, _, err := repo.CreateRole(context.Background(), r)
				require.NoError(t, err)
				require.NotNil(t, dup)
				return r
			},
			wantErr:     true,
			wantErrMsg:  "already exists in scope ",
			wantIsError: errors.NotUnique,
		},
		{
			name: "org-dup-name",
			args: args{
				role: func() *Role {
					r, err := NewRole(ctx, org.PublicId, WithName("org-dup-name"+id), WithDescription(id))
					assert.NoError(t, err)
					return r
				}(),
				opt: []Option{WithName("org-dup-name" + id)},
			},
			dupeSetup: func(t *testing.T) *Role {
				r, err := NewRole(ctx, org.PublicId, WithName("org-dup-name"+id), WithDescription(id))
				require.NoError(t, err)
				dup, _, _, _, err := repo.CreateRole(context.Background(), r)
				require.NoError(t, err)
				require.NotNil(t, dup)
				return r
			},
			wantErr:     true,
			wantErrMsg:  "already exists in scope ",
			wantIsError: errors.NotUnique,
		},
		{
			name: "proj-dup-name",
			args: args{
				role: func() *Role {
					r, err := NewRole(ctx, proj.PublicId, WithName("proj-dup-name"+id), WithDescription(id))
					assert.NoError(t, err)
					return r
				}(),
				opt: []Option{WithName("proj-dup-name" + id)},
			},
			dupeSetup: func(t *testing.T) *Role {
				r, err := NewRole(ctx, proj.PublicId, WithName("proj-dup-name"+id), WithDescription(id))
				require.NoError(t, err)
				dup, _, _, _, err := repo.CreateRole(context.Background(), r)
				require.NoError(t, err)
				require.NotNil(t, dup)
				return r
			},
			wantErr:     true,
			wantErrMsg:  "already exists in scope ",
			wantIsError: errors.NotUnique,
		},
		{
			name: "dup-name-but-diff-org",
			args: args{
				role: func() *Role {
					r, err := NewRole(ctx, org.PublicId, WithName("dup-name-but-diff-org"+id), WithDescription(id))
					assert.NoError(t, err)
					return r
				}(),
				opt: []Option{WithName("dup-name-but-diff-scope" + id)},
			},
			dupeSetup: func(t *testing.T) *Role {
				r, err := NewRole(ctx, dupeOrg.PublicId, WithName("dup-name-but-diff-org"+id), WithDescription(id))
				require.NoError(t, err)
				dup, _, _, _, err := repo.CreateRole(context.Background(), r)
				require.NoError(t, err)
				require.NotNil(t, dup)
				return r
			},
			wantErr: false,
		},
		{
			name: "dup-name-but-diff-proj",
			args: args{
				role: func() *Role {
					r, err := NewRole(ctx, proj.PublicId, WithName("dup-name-but-diff-proj"+id), WithDescription(id))
					assert.NoError(t, err)
					return r
				}(),
				opt: []Option{WithName("dup-name-but-diff-scope" + id)},
			},
			dupeSetup: func(t *testing.T) *Role {
				r, err := NewRole(ctx, dupeProj.PublicId, WithName("dup-name-but-diff-proj"+id), WithDescription(id))
				require.NoError(t, err)
				dup, _, _, _, err := repo.CreateRole(context.Background(), r)
				require.NoError(t, err)
				require.NotNil(t, dup)
				return r
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			if tt.dupeSetup != nil {
				_ = tt.dupeSetup(t)
			}

			grp, _, _, _, err := repo.CreateRole(context.Background(), tt.args.role, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(grp)
				assert.Contains(err.Error(), tt.wantErrMsg)
				assert.True(errors.Match(errors.T(tt.wantIsError), err))
				return
			}
			assert.NoError(err)
			assert.NotNil(grp.CreateTime)
			assert.NotNil(grp.UpdateTime)

			foundGrp, _, _, grantScopes, err := repo.LookupRole(context.Background(), grp.PublicId)
			assert.NoError(err)
			assert.Equal(foundGrp, grp)

			// by default, all created roles has `this` role grant scope
			assert.Len(grantScopes, 1)
			assert.Equal(grantScopes[0].ScopeIdOrSpecial, globals.GrantScopeThis)

			err = db.TestVerifyOplog(t, rw, grp.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_UpdateRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	id, err := uuid.GenerateUUID()
	require.NoError(t, err)

	org, proj := TestScopes(t, repo)
	dupeOrg, dupeProj := TestScopes(t, repo)
	u := TestUser(t, repo, org.GetPublicId())

	pubId := func(s string) *string { return &s }

	type args struct {
		name           string
		description    string
		fieldMaskPaths []string
		opt            []Option
		ScopeId        string
		PublicId       *string
	}

	// used to create a role during setup
	type newRoleArg struct {
		ScopeId     string
		Name        string
		Description string
	}

	tests := []struct {
		name string
		args args
		// REQUIRED: newRoleArgs is used to create a role to be updated
		// the result roleId from this create call will be passed to the update call
		// unless args.PublicId is set
		newRoleArgs *newRoleArg
		// OPTIONAL:  dupeArgs is used to create a role for before role in `newRoleArgs` role is created
		// used for testing duplicate names
		dupeArgs       *newRoleArg
		wantRowsUpdate int
		wantErr        bool
		wantErrMsg     string
		wantIsError    errors.Code
		wantDup        bool
	}{
		{
			name: "valid global",
			args: args{
				name:           "valid global" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        globals.GlobalPrefix,
			},
			newRoleArgs: &newRoleArg{
				ScopeId: globals.GlobalPrefix,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "valid org",
			args: args{
				name:           "valid org" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
			},
			newRoleArgs: &newRoleArg{
				ScopeId: org.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "valid project",
			args: args{
				name:           "valid project" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        proj.PublicId,
			},
			newRoleArgs: &newRoleArg{
				ScopeId: proj.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},

		{
			name: "valid global no-op",
			args: args{
				name:           "valid-global-no-op" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        globals.GlobalPrefix,
			},
			newRoleArgs: &newRoleArg{
				ScopeId: globals.GlobalPrefix,
				Name:    "valid-global-no-op" + id,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "valid org no-op",
			args: args{
				name:           "valid-org-no-op" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
			},
			newRoleArgs: &newRoleArg{
				ScopeId: org.PublicId,
				Name:    "valid-org-no-op" + id,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "valid project no-op",
			args: args{
				name:           "valid-project-no-op" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        proj.PublicId,
			},
			newRoleArgs: &newRoleArg{
				ScopeId: proj.PublicId,
				Name:    "valid-project-no-op" + id,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "not-found-global",
			args: args{
				name:           "global-not-found" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        globals.GlobalPrefix,
				PublicId:       func() *string { s := "1"; return &s }(),
			},
			newRoleArgs: &newRoleArg{
				ScopeId: globals.GlobalPrefix,
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "error #1100",
			wantIsError:    errors.RecordNotFound,
		},
		{
			name: "not-found-org",
			args: args{
				name:           "org-not-found" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
				PublicId:       func() *string { s := "1"; return &s }(),
			},
			newRoleArgs: &newRoleArg{
				ScopeId: org.PublicId,
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "error #1100",
			wantIsError:    errors.RecordNotFound,
		},
		{
			name: "not-found-project",
			args: args{
				name:           "proj-not-found" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        proj.PublicId,
				PublicId:       func() *string { s := "1"; return &s }(),
			},
			newRoleArgs: &newRoleArg{
				ScopeId: proj.PublicId,
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "error #1100",
			wantIsError:    errors.RecordNotFound,
		},
		{
			name: "global-null-name",
			args: args{
				name:           "",
				fieldMaskPaths: []string{"Name"},
				ScopeId:        globals.GlobalPrefix,
			},
			newRoleArgs: &newRoleArg{
				Name:    "global-null-name" + id,
				ScopeId: globals.GlobalPrefix,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "org-null-name",
			args: args{
				name:           "",
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
			},
			newRoleArgs: &newRoleArg{
				Name:    "org-null-name" + id,
				ScopeId: org.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "proj-null-name",
			args: args{
				name:           "",
				fieldMaskPaths: []string{"Name"},
				ScopeId:        proj.PublicId,
			},
			newRoleArgs: &newRoleArg{
				Name:    "proj-null-name" + id,
				ScopeId: proj.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "global-null-description",
			args: args{
				description:    "",
				fieldMaskPaths: []string{"Description"},
				ScopeId:        globals.GlobalPrefix,
			},
			newRoleArgs: &newRoleArg{
				Description: "hello",
				ScopeId:     globals.GlobalPrefix,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "org-null-description",
			args: args{
				description:    "",
				fieldMaskPaths: []string{"Description"},
				ScopeId:        org.PublicId,
			},
			newRoleArgs: &newRoleArg{
				Description: "hello",
				ScopeId:     org.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "project-null-description",
			args: args{
				description:    "",
				fieldMaskPaths: []string{"Description"},
				ScopeId:        proj.PublicId,
			},
			newRoleArgs: &newRoleArg{
				Description: "hello",
				ScopeId:     proj.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "input-validation-empty-field-mask",
			args: args{
				name:           "valid-global" + id,
				fieldMaskPaths: []string{},
				ScopeId:        globals.GlobalPrefix,
			},
			newRoleArgs: &newRoleArg{
				Name:    "valid-global" + id,
				ScopeId: globals.GlobalPrefix,
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "iam.(Repository).UpdateRole: empty field mask, parameter violation: error #104",
			wantIsError:    errors.EmptyFieldMask,
		},
		{
			name: "input-validation-nil-fieldmask",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: nil,
				ScopeId:        org.PublicId,
			},
			newRoleArgs: &newRoleArg{
				Name:    "valid" + id,
				ScopeId: globals.GlobalPrefix,
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "iam.(Repository).UpdateRole: empty field mask, parameter violation: error #104",
			wantIsError:    errors.EmptyFieldMask,
		},
		{
			name: "input-validation-read-only-fields",
			args: args{
				name:           "read-only-fields" + id,
				fieldMaskPaths: []string{"CreateTime"},
				ScopeId:        org.PublicId,
			},
			newRoleArgs: &newRoleArg{
				Name:    "read-only-fields" + id,
				ScopeId: globals.GlobalPrefix,
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "iam.(Repository).UpdateRole: invalid field mask: CreateTime: parameter violation: error #103",
			wantIsError:    errors.InvalidFieldMask,
		},
		{
			name: "input-validation-unknown-fields",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"Alice"},
				ScopeId:        org.PublicId,
			},
			newRoleArgs: &newRoleArg{
				ScopeId: globals.GlobalPrefix,
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "iam.(Repository).UpdateRole: invalid field mask: Alice: parameter violation: error #103",
			wantIsError:    errors.InvalidFieldMask,
		},
		{
			name: "input-validation-no-public-id",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
				PublicId:       pubId(""),
			},
			newRoleArgs: &newRoleArg{
				ScopeId: org.PublicId,
			},
			wantErr:        true,
			wantErrMsg:     "iam.(Repository).UpdateRole: missing public id: parameter violation: error #100",
			wantIsError:    errors.InvalidParameter,
			wantRowsUpdate: 0,
		},
		{
			name: "proj-scope-id-no-mask",
			args: args{
				name:    "proj-scope-id" + id,
				ScopeId: proj.PublicId,
			},
			newRoleArgs: &newRoleArg{
				ScopeId: proj.PublicId,
			},
			wantErr:     true,
			wantErrMsg:  "iam.(Repository).UpdateRole: empty field mask, parameter violation: error #104",
			wantIsError: errors.EmptyFieldMask,
		},
		{
			name: "empty-scope-id-with-name-mask",
			args: args{
				name:           "empty-scope-id" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        "",
			},
			newRoleArgs: &newRoleArg{
				ScopeId: org.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "global-dup-name",
			args: args{
				name:           "global-dup-name" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        globals.GlobalPrefix,
			},
			newRoleArgs: &newRoleArg{
				ScopeId: globals.GlobalPrefix,
			},
			dupeArgs: &newRoleArg{
				ScopeId: globals.GlobalPrefix,
				Name:    "global-dup-name" + id,
			},
			wantErr:     true,
			wantDup:     true,
			wantErrMsg:  " already exists in scope " + globals.GlobalPrefix,
			wantIsError: errors.NotUnique,
		},
		{
			name: "org-dup-name",
			args: args{
				name:           "org-dup-name" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
			},
			newRoleArgs: &newRoleArg{
				ScopeId: org.PublicId,
			},
			dupeArgs: &newRoleArg{
				ScopeId: org.PublicId,
				Name:    "org-dup-name" + id,
			},
			wantErr:     true,
			wantDup:     true,
			wantErrMsg:  " already exists in scope " + org.PublicId,
			wantIsError: errors.NotUnique,
		},
		{
			name: "proj-dup-name",
			args: args{
				name:           "proj-dup-name" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        proj.PublicId,
			},
			newRoleArgs: &newRoleArg{
				ScopeId: proj.PublicId,
			},
			dupeArgs: &newRoleArg{
				ScopeId: proj.PublicId,
				Name:    "proj-dup-name" + id,
			},
			wantErr:     true,
			wantDup:     true,
			wantErrMsg:  " already exists in scope " + proj.PublicId,
			wantIsError: errors.NotUnique,
		},
		{
			name: "global-org-dup-name-in-diff-scope",
			args: args{
				name:           "global-org-dup-name-in-diff-scope" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        globals.GlobalPrefix,
			},
			newRoleArgs: &newRoleArg{
				ScopeId: globals.GlobalPrefix,
			},
			dupeArgs: &newRoleArg{
				ScopeId: org.PublicId,
				Name:    "global-org-dup-name-in-diff-scope" + id,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
			wantDup:        true,
		},
		{
			name: "org-proj-dup-name-in-diff-scope",
			args: args{
				name:           "org-proj-dup-name-in-diff-scope" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        proj.PublicId,
			},
			newRoleArgs: &newRoleArg{
				ScopeId: proj.PublicId,
			},
			dupeArgs: &newRoleArg{
				ScopeId: org.PublicId,
				Name:    "org-proj-dup-name-in-diff-scope" + id,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
			wantDup:        true,
		},
		{
			name: "org-dup-name-in-diff-scope",
			args: args{
				name:           "org-dup-name-in-diff-scope" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
			},
			newRoleArgs: &newRoleArg{
				ScopeId: org.PublicId,
			},
			dupeArgs: &newRoleArg{
				ScopeId: dupeOrg.PublicId,
				Name:    "org-dup-name-in-diff-scope" + id,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
			wantDup:        true,
		},
		{
			name: "project-dup-name-in-diff-scope",
			args: args{
				name:           "project-dup-name-in-diff-scope" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        proj.PublicId,
			},
			newRoleArgs: &newRoleArg{
				ScopeId: proj.PublicId,
			},
			dupeArgs: &newRoleArg{
				ScopeId: dupeProj.PublicId,
				Name:    "project-dup-name-in-diff-scope" + id,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
			wantDup:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			if tt.dupeArgs != nil {
				dupedRole := TestRole(t, conn, tt.dupeArgs.ScopeId, WithName(tt.dupeArgs.Name), WithDescription(tt.dupeArgs.Description))
				_ = TestUserRole(t, conn, dupedRole.GetPublicId(), u.GetPublicId())
				_ = TestRoleGrant(t, conn, dupedRole.GetPublicId(), "ids=*;type=*;actions=*")
			}

			testRole := TestRole(t, conn, tt.newRoleArgs.ScopeId, WithName(tt.newRoleArgs.Name), WithDescription(tt.newRoleArgs.Description))
			ur := TestUserRole(t, conn, testRole.GetPublicId(), u.GetPublicId())
			princRole := &PrincipalRole{PrincipalRoleView: &store.PrincipalRoleView{
				Type:              UserRoleType.String(),
				CreateTime:        ur.CreateTime,
				RoleId:            ur.RoleId,
				PrincipalId:       ur.PrincipalId,
				PrincipalScopeId:  org.GetPublicId(),
				ScopedPrincipalId: ur.PrincipalId,
				RoleScopeId:       org.GetPublicId(),
			}}
			if tt.newRoleArgs.ScopeId != u.ScopeId {
				// If the project is in a different scope from the created user we need to update the
				// scope specific fields.
				princRole.RoleScopeId = tt.newRoleArgs.ScopeId
				princRole.ScopedPrincipalId = fmt.Sprintf("%s:%s", u.ScopeId, ur.PrincipalId)
			}

			rGrant := TestRoleGrant(t, conn, testRole.GetPublicId(), "ids=*;type=*;actions=*")

			updateRole := Role{}
			updateRole.PublicId = testRole.PublicId
			updateRole.ScopeId = tt.args.ScopeId
			updateRole.Name = tt.args.name
			updateRole.Description = tt.args.description

			if tt.args.PublicId != nil {
				updateRole.PublicId = *tt.args.PublicId
			}

			roleAfterUpdate, principals, grants, _, updatedRows, err := repo.UpdateRole(context.Background(), &updateRole, testRole.Version, tt.args.fieldMaskPaths, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsError), err))
				assert.Nil(roleAfterUpdate)
				assert.Equal(0, updatedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, testRole.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.IsNotFoundError(err))
				return
			}
			require.NoError(err)
			require.NotNil(roleAfterUpdate)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			assert.Equal([]*PrincipalRole{princRole}, principals)
			assert.Equal([]*RoleGrant{rGrant}, grants)
			switch {
			case strings.Contains(tt.name, "no-op"):
				assert.Equal(testRole.UpdateTime, roleAfterUpdate.UpdateTime)
			default:
				assert.NotEqual(testRole.UpdateTime, roleAfterUpdate.UpdateTime)
			}
			foundRole, _, _, _, err := repo.LookupRole(context.Background(), testRole.PublicId)
			assert.NoError(err)
			assert.Equal(roleAfterUpdate, foundRole)
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)

			var dbRole any
			switch {
			case strings.HasPrefix(foundRole.ScopeId, globals.GlobalPrefix):
				g := allocGlobalRole()
				g.PublicId = foundRole.PublicId
				require.NoError(rw.LookupByPublicId(ctx, &g))
				dbRole = &g
			case strings.HasPrefix(foundRole.ScopeId, globals.OrgPrefix):
				o := allocOrgRole()
				o.PublicId = foundRole.PublicId
				require.NoError(rw.LookupByPublicId(ctx, &o))
				dbRole = &o
			case strings.HasPrefix(foundRole.ScopeId, globals.ProjectPrefix):
				p := allocProjectRole()
				p.PublicId = foundRole.PublicId
				require.NoError(rw.LookupByPublicId(ctx, &p))
				dbRole = &p
			}
			if tt.args.name == "" {

				assert.Equal("", foundRole.Name)
				dbassert.IsNull(dbRole, "name")
			}
			if tt.args.description == "" {
				assert.Equal("", foundRole.Description)
				dbassert.IsNull(dbRole, "description")
			}
			err = db.TestVerifyOplog(t, rw, testRole.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_DeleteRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)

	roleId, err := newRoleId(ctx)
	require.NoError(t, err)

	type args struct {
		role *Role
		opt  []Option
	}
	tests := []struct {
		name            string
		args            args
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name: "valid global",
			args: args{
				role: TestRole(t, conn, globals.GlobalPrefix),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "valid org",
			args: args{
				role: TestRole(t, conn, org.PublicId),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "valid project",
			args: args{
				role: TestRole(t, conn, proj.PublicId),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-public-id",
			args: args{
				role: func() *Role {
					r := Role{}
					return &r
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "iam.(Repository).DeleteRole: missing public id: parameter violation: error #100",
		},

		{
			name: "not-found",
			args: args{
				role: func() *Role {
					r, err := NewRole(ctx, org.PublicId)
					r.PublicId = roleId
					require.NoError(t, err)
					return r
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      fmt.Sprintf("iam.(Repository).DeleteRole: cannot find scope for role %s: iam.getRoleScopeType: role %s not found: search issue: error #1100", roleId, roleId),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			deletedRows, err := repo.DeleteRole(ctx, tt.args.role.PublicId, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, tt.args.role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.IsNotFoundError(err))
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundRole, _, _, _, err := repo.LookupRole(ctx, tt.args.role.PublicId)
			assert.NoError(err)
			assert.Nil(foundRole)

			err = db.TestVerifyOplog(t, rw, tt.args.role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_listRoles(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	const testLimit = 10
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo := TestRepo(t, conn, wrapper, WithLimit(testLimit))
	org, proj := TestScopes(t, repo, WithSkipDefaultRoleCreation(true))

	type args struct {
		withScopeId string
		opt         []Option
	}
	tests := []struct {
		name          string
		createCnt     int
		createScopeId string
		args          args
		wantCnt       int
		wantErr       bool
	}{
		{
			name:          "negative-limit",
			createCnt:     repo.defaultLimit + 1,
			createScopeId: org.PublicId,
			args: args{
				withScopeId: org.PublicId,
				opt:         []Option{WithLimit(-1)},
			},
			wantCnt: repo.defaultLimit + 1,
			wantErr: true,
		},
		{
			name:          "negative-limit-proj-role",
			createCnt:     repo.defaultLimit + 1,
			createScopeId: proj.PublicId,
			args: args{
				withScopeId: proj.PublicId,
				opt:         []Option{WithLimit(-1)},
			},
			wantCnt: repo.defaultLimit + 1,
			wantErr: true,
		},
		{
			name:          "default-limit",
			createCnt:     repo.defaultLimit + 1,
			createScopeId: org.PublicId,
			args: args{
				withScopeId: org.PublicId,
			},
			wantCnt: repo.defaultLimit,
			wantErr: false,
		},
		{
			name:          "custom-limit",
			createCnt:     repo.defaultLimit + 1,
			createScopeId: org.PublicId,
			args: args{
				withScopeId: org.PublicId,
				opt:         []Option{WithLimit(3)},
			},
			wantCnt: 3,
			wantErr: false,
		},
		{
			name:          "bad-org",
			createCnt:     1,
			createScopeId: org.PublicId,
			args: args{
				withScopeId: "bad-id",
			},
			wantCnt: 0,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			t.Cleanup(func() {
				db.TestDeleteWhere(t, conn, func() any { i := allocGlobalRole(); return &i }(), "1=1")
				db.TestDeleteWhere(t, conn, func() any { i := allocOrgRole(); return &i }(), "1=1")
				db.TestDeleteWhere(t, conn, func() any { i := allocProjectRole(); return &i }(), "1=1")
			})
			testRoles := []*Role{}
			for i := 0; i < tt.createCnt; i++ {
				testRoles = append(testRoles, TestRole(t, conn, tt.createScopeId))
			}
			assert.Equal(tt.createCnt, len(testRoles))
			got, ttime, err := repo.listRoles(context.Background(), []string{tt.args.withScopeId}, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		})
	}
	t.Run("withStartPageAfter", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()

		for i := 0; i < 10; i++ {
			_ = TestRole(t, conn, org.GetPublicId())
		}

		repo, err := NewRepository(ctx, rw, rw, kms)
		require.NoError(err)
		page1, ttime, err := repo.listRoles(ctx, []string{org.GetPublicId()}, WithLimit(2))
		require.NoError(err)
		require.Len(page1, 2)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		page2, ttime, err := repo.listRoles(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page1[1]))
		require.NoError(err)
		require.Len(page2, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page1 {
			assert.NotEqual(item.GetPublicId(), page2[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page2[1].GetPublicId())
		}
		page3, ttime, err := repo.listRoles(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page2[1]))
		require.NoError(err)
		require.Len(page3, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page2 {
			assert.NotEqual(item.GetPublicId(), page3[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page3[1].GetPublicId())
		}
		page4, ttime, err := repo.listRoles(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page3[1]))
		require.NoError(err)
		assert.Len(page4, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page3 {
			assert.NotEqual(item.GetPublicId(), page4[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page4[1].GetPublicId())
		}
		page5, ttime, err := repo.listRoles(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page4[1]))
		require.NoError(err)
		assert.Len(page5, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page4 {
			assert.NotEqual(item.GetPublicId(), page5[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page5[1].GetPublicId())
		}
		page6, ttime, err := repo.listRoles(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page5[1]))
		require.NoError(err)
		assert.Empty(page6)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

		// Create 2 new roles
		newR1 := TestRole(t, conn, org.GetPublicId())
		newR2 := TestRole(t, conn, org.GetPublicId())

		// since it will return newest to oldest, we get page1[1] first
		page7, ttime, err := repo.listRolesRefresh(
			ctx,
			time.Now().Add(-1*time.Second),
			[]string{org.GetPublicId()},
			WithLimit(1),
		)
		require.NoError(err)
		require.Len(page7, 1)
		require.Equal(page7[0].GetPublicId(), newR2.GetPublicId())
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

		page8, ttime, err := repo.listRolesRefresh(
			context.Background(),
			time.Now().Add(-1*time.Second),
			[]string{org.GetPublicId()},
			WithLimit(1),
			WithStartPageAfterItem(page7[0]),
		)
		require.NoError(err)
		require.Len(page8, 1)
		require.Equal(page8[0].GetPublicId(), newR1.GetPublicId())
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
	})
}

func TestRepository_ListRoles_Multiple_Scopes(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)

	db.TestDeleteWhere(t, conn, func() any { i := allocGlobalRole(); return &i }(), "1=1")
	db.TestDeleteWhere(t, conn, func() any { i := allocOrgRole(); return &i }(), "1=1")
	db.TestDeleteWhere(t, conn, func() any { i := allocProjectRole(); return &i }(), "1=1")

	const numPerScope = 10
	var total int
	for i := 0; i < numPerScope; i++ {
		TestRole(t, conn, "global")
		total++
		TestRole(t, conn, org.GetPublicId())
		total++
		TestRole(t, conn, proj.GetPublicId())
		total++
	}

	got, ttime, err := repo.listRoles(context.Background(), []string{"global", org.GetPublicId(), proj.GetPublicId()})
	require.NoError(t, err)
	assert.Equal(t, total, len(got))
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func Test_listRoleDeletedIds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo, WithSkipDefaultRoleCreation(true))
	r := TestRole(t, conn, org.GetPublicId())

	// Expect no entries at the start
	deletedIds, ttime, err := repo.listRoleDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Delete a role
	_, err = repo.DeleteRole(ctx, r.GetPublicId())
	require.NoError(t, err)

	// Expect a single entry
	deletedIds, ttime, err = repo.listRoleDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Equal(t, []string{r.GetPublicId()}, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = repo.listRoleDeletedIds(ctx, time.Now())
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func Test_estimatedRoleCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	// Check total entries at start, expect 0
	numItems, err := repo.estimatedRoleCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	iamRepo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, iamRepo, WithSkipDefaultRoleCreation(true))
	// Create a role, expect 1 entry
	r := TestRole(t, conn, org.GetPublicId())

	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems, err = repo.estimatedRoleCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, numItems)

	// Delete the role, expect 0 again
	_, err = repo.DeleteRole(ctx, r.GetPublicId())
	require.NoError(t, err)

	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems, err = repo.estimatedRoleCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)
}

func Test_getRoleScopeType(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	ctx := context.Background()
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	type arg struct {
		roleId   string
		dbReader db.Reader
	}
	testcases := []struct {
		name        string
		inputRoleId func(t *testing.T) arg
		expect      scope.Type
		wantErr     bool
		wantErrMsg  string
	}{
		{
			name: "valid role global scope",
			inputRoleId: func(t *testing.T) arg {
				grpId, err := newRoleId(ctx)
				require.NoError(t, err)
				r := &globalRole{
					GlobalRole: &store.GlobalRole{
						PublicId:           grpId,
						ScopeId:            globals.GlobalPrefix,
						GrantThisRoleScope: true,
						GrantScope:         globals.GrantScopeDescendants,
					},
				}
				require.NoError(t, rw.Create(ctx, r))
				return arg{
					roleId:   r.PublicId,
					dbReader: rw,
				}
			},
			expect: scope.Global,
		},
		{
			name: "valid role org scope",
			inputRoleId: func(t *testing.T) arg {
				grpId, err := newRoleId(ctx)
				require.NoError(t, err)
				r := &orgRole{
					OrgRole: &store.OrgRole{
						PublicId:           grpId,
						ScopeId:            org.PublicId,
						GrantThisRoleScope: true,
						GrantScope:         globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, r))
				return arg{
					roleId:   r.PublicId,
					dbReader: rw,
				}
			},
			expect: scope.Org,
		},
		{
			name: "valid role project scope",
			inputRoleId: func(t *testing.T) arg {
				grpId, err := newRoleId(ctx)
				require.NoError(t, err)
				r := &projectRole{
					ProjectRole: &store.ProjectRole{
						PublicId: grpId,
						ScopeId:  proj.PublicId,
					},
				}
				require.NoError(t, rw.Create(ctx, r))
				return arg{
					roleId:   r.PublicId,
					dbReader: rw,
				}
			},
			expect: scope.Project,
		},
		{
			name: "role does not exist returns error",
			inputRoleId: func(t *testing.T) arg {
				return arg{
					roleId:   "r_123456",
					dbReader: rw,
				}
			},
			wantErr:    true,
			wantErrMsg: `iam.getRoleScopeType: role r_123456 not found: search issue: error #1100`,
		},
		{
			name: "missing role id returns error",
			inputRoleId: func(t *testing.T) arg {
				return arg{
					roleId:   "",
					dbReader: rw,
				}
			},
			wantErr:    true,
			wantErrMsg: `iam.getRoleScopeType: missing role id: parameter violation: error #100`,
		},
		{
			name: "missing db.Reader returns error",
			inputRoleId: func(t *testing.T) arg {
				return arg{
					roleId:   "r_123456",
					dbReader: nil,
				}
			},
			wantErr:    true,
			wantErrMsg: `iam.getRoleScopeType: missing db.Reader: parameter violation: error #100`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			args := tc.inputRoleId(t)
			got, err := getRoleScopeType(ctx, args.dbReader, args.roleId)
			if tc.wantErr {
				require.Error(t, err)
				require.Equal(t, tc.wantErrMsg, err.Error())
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expect, got)
		})
	}
}

func Test_getRoleScope(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	ctx := context.Background()
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)

	globalScope := AllocScope()
	globalScope.PublicId = globals.GlobalPrefix
	require.NoError(t, rw.LookupByPublicId(ctx, &globalScope))
	org, proj := TestScopes(t, repo)
	type arg struct {
		roleId   string
		dbReader db.Reader
	}
	testcases := []struct {
		name        string
		inputRoleId func(t *testing.T) arg
		expect      *Scope
		wantErr     bool
		wantErrMsg  string
	}{
		{
			name: "valid role global scope",
			inputRoleId: func(t *testing.T) arg {
				grpId, err := newRoleId(ctx)
				require.NoError(t, err)
				r := &globalRole{
					GlobalRole: &store.GlobalRole{
						PublicId:           grpId,
						ScopeId:            globals.GlobalPrefix,
						GrantThisRoleScope: true,
						GrantScope:         globals.GrantScopeDescendants,
					},
				}
				require.NoError(t, rw.Create(ctx, r))
				return arg{
					roleId:   r.PublicId,
					dbReader: rw,
				}
			},
			expect: &globalScope,
		},
		{
			name: "valid role org scope",
			inputRoleId: func(t *testing.T) arg {
				grpId, err := newRoleId(ctx)
				require.NoError(t, err)
				r := &orgRole{
					OrgRole: &store.OrgRole{
						PublicId:           grpId,
						ScopeId:            org.PublicId,
						GrantThisRoleScope: true,
						GrantScope:         globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, r))
				return arg{
					roleId:   r.PublicId,
					dbReader: rw,
				}
			},
			expect: org,
		},
		{
			name: "valid role project scope",
			inputRoleId: func(t *testing.T) arg {
				grpId, err := newRoleId(ctx)
				require.NoError(t, err)
				r := &projectRole{
					ProjectRole: &store.ProjectRole{
						PublicId: grpId,
						ScopeId:  proj.PublicId,
					},
				}
				require.NoError(t, rw.Create(ctx, r))
				return arg{
					roleId:   r.PublicId,
					dbReader: rw,
				}
			},
			expect: proj,
		},
		{
			name: "role does not exist returns error",
			inputRoleId: func(t *testing.T) arg {
				return arg{
					roleId:   "r_123456",
					dbReader: rw,
				}
			},
			wantErr:    true,
			wantErrMsg: `iam.getRoleScope: role r_123456 not found: search issue: error #1100`,
		},
		{
			name: "missing role id returns error",
			inputRoleId: func(t *testing.T) arg {
				return arg{
					roleId:   "",
					dbReader: rw,
				}
			},
			wantErr:    true,
			wantErrMsg: `iam.getRoleScope: missing role id: parameter violation: error #100`,
		},
		{
			name: "missing db.Reader returns error",
			inputRoleId: func(t *testing.T) arg {
				return arg{
					roleId:   "r_123456",
					dbReader: nil,
				}
			},
			wantErr:    true,
			wantErrMsg: `iam.getRoleScope: missing db.Reader: parameter violation: error #100`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			args := tc.inputRoleId(t)
			got, err := getRoleScope(ctx, args.dbReader, args.roleId)
			if tc.wantErr {
				require.Error(t, err)
				require.Equal(t, tc.wantErrMsg, err.Error())
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expect.String(), got.String())
		})
	}
}
