// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestScope_New(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	t.Run("valid-org-with-project", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		s, err := NewOrg(ctx)
		require.NoError(err)
		require.NotNil(s.Scope)
		s.PublicId, err = newScopeId(ctx, scope.Org)
		require.NoError(err)
		err = w.Create(ctx, s)
		require.NoError(err)
		require.NotEmpty(s.PublicId)

		id := testId(t)
		projScope, err := NewProject(ctx, s.PublicId, WithDescription(id))
		require.NoError(err)
		require.NotNil(projScope.Scope)
		assert.Equal(projScope.GetParentId(), s.PublicId)
		assert.Equal(projScope.GetDescription(), id)
	})
	t.Run("unknown-scope", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		s, err := newScope(ctx, nil)
		require.Error(err)
		require.Nil(s)
		assert.Contains(err.Error(), "iam.newScope: child scope is missing its parent: parameter violation: error #100")
	})
	t.Run("proj-scope-with-no-org", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		s, err := NewProject(ctx, "")
		require.Error(err)
		require.Nil(s)
		assert.Contains(err.Error(), "iam.NewProject: iam.newScope: child scope is missing its parent: parameter violation: error #100")
	})
}

func TestScope_Create(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		s, err := NewOrg(ctx)
		require.NoError(err)
		require.NotNil(s.Scope)
		s.PublicId, err = newScopeId(ctx, scope.Org)
		require.NoError(err)
		err = w.Create(ctx, s)
		require.NoError(err)
		assert.NotEmpty(s.PublicId)
	})
	t.Run("valid-with-parent", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		s, err := NewOrg(ctx)
		require.NoError(err)
		require.NotNil(s.Scope)
		s.PublicId, err = newScopeId(ctx, scope.Org)
		require.NoError(err)
		err = w.Create(ctx, s)
		require.NoError(err)
		require.NotEmpty(s.PublicId)

		id := testId(t)
		project, err := NewProject(ctx, s.PublicId, WithDescription(id))
		require.NoError(err)
		require.NotNil(project.Scope)
		assert.Equal(project.Scope.ParentId, s.PublicId)
		assert.Equal(project.GetDescription(), id)
		project.PublicId, err = newScopeId(ctx, scope.Org)
		require.NoError(err)

		err = w.Create(ctx, project)
		require.NoError(err)
		assert.Equal(project.ParentId, s.PublicId)
	})
}

func TestScope_Update(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		s, _ := TestScopes(t, repo)

		s.Name = testId(t)
		updatedRows, err := w.Update(context.Background(), s, []string{"Name"}, nil)
		require.NoError(err)
		assert.Equal(1, updatedRows)
	})
	t.Run("type-update-not-allowed", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		s, _ := TestScopes(t, repo)

		s.Type = scope.Project.String()
		updatedRows, err := w.Update(context.Background(), s, []string{"Type"}, nil)
		require.Error(err)
		assert.Equal(0, updatedRows)
	})
}

func TestScope_GetScope(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	t.Run("valid-scope", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		org, proj := TestScopes(t, repo)
		global := Scope{
			Scope: &store.Scope{Type: scope.Global.String(), PublicId: "global"},
		}
		globalScope, err := global.GetScope(context.Background(), w)
		require.NoError(err)
		assert.Nil(globalScope)

		foundScope, err := org.GetScope(context.Background(), w)
		require.NoError(err)
		assert.Equal(foundScope.PublicId, "global")

		projectOrg, err := proj.GetScope(context.Background(), w)
		require.NoError(err)
		assert.NotNil(projectOrg)
		assert.Equal(projectOrg.PublicId, proj.ParentId)

		p := AllocScope()
		p.PublicId = proj.PublicId
		p.Type = scope.Project.String()
		projectOrg, err = p.GetScope(context.Background(), w)
		require.NoError(err)
		assert.Equal(org.PublicId, projectOrg.PublicId)
	})
}

func TestScope_Actions(t *testing.T) {
	assert := assert.New(t)
	s := &Scope{}
	a := s.Actions()
	assert.Equal(a[action.Create.String()], action.Create)
	assert.Equal(a[action.Update.String()], action.Update)
	assert.Equal(a[action.Read.String()], action.Read)
	assert.Equal(a[action.Delete.String()], action.Delete)
	assert.Equal(a[action.List.String()], action.List)
}

func TestScope_ResourceType(t *testing.T) {
	o, err := NewOrg(context.Background())
	require.NoError(t, err)
	assert.Equal(t, o.GetResourceType(), resource.Scope)
	assert.Equal(t, o.GetParentId(), scope.Global.String())
}

func TestScope_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		s, _ := TestScopes(t, repo)
		cp := s.Clone()
		assert.True(proto.Equal(cp.(*Scope).Scope, s.Scope))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		s, _ := TestScopes(t, repo)
		s2, _ := TestScopes(t, repo)
		cp := s.Clone()
		assert.True(!proto.Equal(cp.(*Scope).Scope, s2.Scope))
	})
}

// TestScope_GlobalErrors tests various expected error conditions related to the
// global scope at a layer below the repository, e.g. within the scope logic or the
// DB itself
func TestScope_GlobalErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	t.Run("newScope errors", func(t *testing.T) {
		// Not allowed
		_, err := newScope(ctx, &Scope{Scope: &store.Scope{PublicId: "blahblah"}})
		require.Error(t, err)

		// Should fail as there's no scope
		_, err = newScope(ctx, nil)
		require.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "missing its parent"))
	})
	t.Run("creation disallowed at vet time", func(t *testing.T) {
		// Not allowed to create
		s := AllocScope()
		s.Type = scope.Global.String()
		s.PublicId = "global"
		err := s.VetForWrite(ctx, nil, db.CreateOp)
		require.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "iam.(Scope).VetForWrite: you cannot create a global scope: parameter violation: error #100"))
	})
	t.Run("check org parent at vet time", func(t *testing.T) {
		// Org must have global parent
		s := AllocScope()
		s.Type = scope.Org.String()
		s.PublicId = "o_1234"
		s.ParentId = "global"
		err := s.VetForWrite(ctx, nil, db.CreateOp)
		require.NoError(t, err)
		s.ParentId = "o_2345"
		err = s.VetForWrite(ctx, nil, db.CreateOp)
		require.Error(t, err)
	})
	t.Run("not deletable in db", func(t *testing.T) {
		// Should not be deletable
		s := AllocScope()
		s.PublicId = "global"
		// Add this to validate that we did in fact delete
		err := w.LookupById(ctx, &s)
		require.NoError(t, err)
		require.Equal(t, s.Type, scope.Global.String())
		rows, err := w.Delete(ctx, &s)
		require.Error(t, err)
		assert.Equal(t, 0, rows)
	})
}

func TestScope_SetTableName(t *testing.T) {
	defaultTableName := defaultScopeTableName
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
			def := AllocScope()
			require.Equal(defaultTableName, def.TableName())
			s := &Scope{
				Scope:     &store.Scope{},
				tableName: tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
