// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	iamstore "github.com/hashicorp/boundary/internal/iam/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestScope_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	w := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	new, _ := TestScopes(t, repo)
	tests := []struct {
		name      string
		update    *Scope
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *Scope {
				c := new.Clone().(*Scope)
				c.PublicId = "o_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *Scope {
				c := new.Clone().(*Scope)
				c.CreateTime = &ts
				return c
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "type",
			update: func() *Scope {
				c := new.Clone().(*Scope)
				c.Type = "project"
				return c
			}(),
			fieldMask: []string{"Type"},
		},
		{
			name: "parent_id",
			update: func() *Scope {
				u := new.Clone().(*Scope)
				u.PublicId = "p_thisIsNotAValidId"
				return u
			}(),
			fieldMask: []string{"ParentId"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.Clone()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*Scope), after.(*Scope)))
		})
	}
}

func TestConcreteScope_ImmutableFields(t *testing.T) {
	const (
		query  = `select scope_id from {{rep}} where scope_id = $1`
		update = `update {{rep}} set scope_id = $1 where scope_id = $2;`
	)
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	db, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	org, proj := TestScopes(t, repo)

	tests := []struct {
		name      string
		scopeId   string
		updateTo  string
		tableName string
	}{
		{
			name:      "global",
			scopeId:   "global",
			updateTo:  "o_12345678901",
			tableName: "iam_scope_global",
		},
		{
			name:      "org",
			scopeId:   org.PublicId,
			updateTo:  "o_12345678901",
			tableName: "iam_scope_org",
		},
		{
			name:      "project",
			scopeId:   proj.PublicId,
			updateTo:  "o_12345678901",
			tableName: "iam_scope_project",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			updateStmt := strings.Replace(update, "{{rep}}", tt.tableName, -1)
			queryStmt := strings.Replace(query, "{{rep}}", tt.tableName, -1)

			_, err := db.Exec(updateStmt, tt.updateTo, tt.scopeId)
			assert.Error(err)

			var scopeId string
			err = db.QueryRow(queryStmt, tt.scopeId).Scan(&scopeId)
			assert.NoError(err)
			assert.Equal(tt.scopeId, scopeId)
		})
	}
}

func TestUser_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	w := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	org, proj := TestScopes(t, repo)
	new := TestUser(t, repo, org.PublicId)

	tests := []struct {
		name      string
		update    *User
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *User {
				c := new.Clone().(*User)
				c.PublicId = "o_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *User {
				c := new.Clone().(*User)
				c.CreateTime = &ts
				return c
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "scope id",
			update: func() *User {
				c := new.Clone().(*User)
				c.ScopeId = proj.PublicId
				return c
			}(),
			fieldMask: []string{"ScopeId"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.Clone()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*User), after.(*User)))
		})
	}
}

func Test_globalRole_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	w := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	_, proj := TestScopes(t, repo)

	ctx := context.Background()
	roleId, err := newRoleId(ctx)
	require.NoError(t, err)
	testGlobalRole := &globalRole{
		GlobalRole: &iamstore.GlobalRole{
			PublicId:           roleId,
			ScopeId:            globals.GlobalPrefix,
			GrantScope:         globals.GrantScopeIndividual,
			GrantThisRoleScope: true,
		},
	}
	require.NoError(t, w.Create(ctx, testGlobalRole))
	require.NotEmpty(t, testGlobalRole.PublicId)

	tests := []struct {
		name      string
		update    *globalRole
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *globalRole {
				c := testGlobalRole.Clone().(*globalRole)
				c.PublicId = "r_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create_time",
			update: func() *globalRole {
				c := testGlobalRole.Clone().(*globalRole)
				c.CreateTime = &ts
				return c
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "scope_id",
			update: func() *globalRole {
				c := testGlobalRole.Clone().(*globalRole)
				c.ScopeId = proj.PublicId
				return c
			}(),
			fieldMask: []string{"ScopeId"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := testGlobalRole.Clone()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := testGlobalRole.Clone()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*globalRole), after.(*globalRole)))
		})
	}
}

func Test_orgRole_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	w := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	org, proj := TestScopes(t, repo)

	ctx := context.Background()
	orgRoleId, err := newRoleId(ctx)
	require.NoError(t, err)

	testOrgRole := &orgRole{
		OrgRole: &iamstore.OrgRole{
			PublicId:           orgRoleId,
			ScopeId:            org.PublicId,
			GrantScope:         globals.GrantScopeIndividual,
			GrantThisRoleScope: true,
		},
	}
	require.NoError(t, w.Create(ctx, testOrgRole))
	require.NotEmpty(t, testOrgRole.PublicId)

	tests := []struct {
		name      string
		update    *orgRole
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *orgRole {
				c := testOrgRole.Clone().(*orgRole)
				c.PublicId = "r_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create_time",
			update: func() *orgRole {
				c := testOrgRole.Clone().(*orgRole)
				c.CreateTime = &ts
				return c
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "scope_id",
			update: func() *orgRole {
				c := testOrgRole.Clone().(*orgRole)
				c.ScopeId = proj.PublicId
				return c
			}(),
			fieldMask: []string{"ScopeId"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := testOrgRole.Clone()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := testOrgRole.Clone()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*orgRole), after.(*orgRole)))
		})
	}
}

func Test_projRole_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	w := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	_, proj := TestScopes(t, repo)
	_, proj2 := TestScopes(t, repo)

	ctx := context.Background()
	projRoleId, err := newRoleId(ctx)
	require.NoError(t, err)
	testProjectRole := &projectRole{
		ProjectRole: &iamstore.ProjectRole{
			PublicId: projRoleId,
			ScopeId:  proj.PublicId,
		},
	}
	require.NoError(t, w.Create(ctx, testProjectRole))
	require.NotEmpty(t, testProjectRole.PublicId)

	tests := []struct {
		name      string
		update    *projectRole
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *projectRole {
				c := testProjectRole.Clone().(*projectRole)
				c.PublicId = "r_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create_time",
			update: func() *projectRole {
				c := testProjectRole.Clone().(*projectRole)
				c.CreateTime = &ts
				return c
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "scope_id",
			update: func() *projectRole {
				c := testProjectRole.Clone().(*projectRole)
				c.ScopeId = proj2.PublicId
				return c
			}(),
			fieldMask: []string{"ScopeId"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := testProjectRole.Clone()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := testProjectRole.Clone()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*projectRole), after.(*projectRole)))
		})
	}
}

func TestGroup_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	w := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	org, proj := TestScopes(t, repo)
	new := TestGroup(t, conn, org.PublicId)

	tests := []struct {
		name      string
		update    *Group
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *Group {
				c := new.Clone().(*Group)
				c.PublicId = "g_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *Group {
				c := new.Clone().(*Group)
				c.CreateTime = &ts
				return c
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "scope id",
			update: func() *Group {
				c := new.Clone().(*Group)
				c.ScopeId = proj.PublicId
				return c
			}(),
			fieldMask: []string{"ScopeId"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.Clone()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*Group), after.(*Group)))
		})
	}
}
