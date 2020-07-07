package iam

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/hashicorp/watchtower/internal/types/action"
	"github.com/hashicorp/watchtower/internal/types/resource"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestScope_New(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	t.Run("valid-org-with-project", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		s, err := NewOrganization()
		require.NoError(err)
		require.NotNil(s.Scope)
		s.PublicId, err = newScopeId(scope.Organization)
		require.NoError(err)
		err = w.Create(context.Background(), s)
		require.NoError(err)
		require.NotEmpty(s.PublicId)

		id := testId(t)
		projScope, err := NewProject(s.PublicId, WithDescription(id))
		require.NoError(err)
		require.NotNil(projScope.Scope)
		assert.Equal(projScope.GetParentId(), s.PublicId)
		assert.Equal(projScope.GetDescription(), id)
	})
	t.Run("unknown-scope", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		s, err := newScope(scope.Unknown)
		require.Error(err)
		require.Nil(s)
		assert.Equal(err.Error(), "new scope: unknown scope type: invalid parameter")
	})
	t.Run("proj-scope-with-no-org", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		s, err := NewProject("")
		require.Error(err)
		require.Nil(s)
		assert.Equal(err.Error(), "error creating new project: new scope: with scope's parent id is missing: invalid parameter")
	})
}
func TestScope_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		s, err := NewOrganization()
		require.NoError(err)
		require.NotNil(s.Scope)
		s.PublicId, err = newScopeId(scope.Organization)
		require.NoError(err)
		err = w.Create(context.Background(), s)
		require.NoError(err)
		assert.NotEmpty(s.PublicId)
	})
	t.Run("valid-with-parent", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		s, err := NewOrganization()
		require.NoError(err)
		require.NotNil(s.Scope)
		s.PublicId, err = newScopeId(scope.Organization)
		require.NoError(err)
		err = w.Create(context.Background(), s)
		require.NoError(err)
		require.NotEmpty(s.PublicId)

		id := testId(t)
		project, err := NewProject(s.PublicId, WithDescription(id))
		require.NoError(err)
		require.NotNil(project.Scope)
		assert.Equal(project.Scope.ParentId, s.PublicId)
		assert.Equal(project.GetDescription(), id)
		project.PublicId, err = newScopeId(scope.Organization)
		require.NoError(err)

		err = w.Create(context.Background(), project)
		require.NoError(err)
		assert.Equal(project.ParentId, s.PublicId)
	})
}

func TestScope_Update(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		s, _ := TestScopes(t, conn)

		s.Name = testId(t)
		updatedRows, err := w.Update(context.Background(), s, []string{"Name"}, nil)
		require.NoError(err)
		assert.Equal(1, updatedRows)
	})
	t.Run("type-update-not-allowed", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		s, _ := TestScopes(t, conn)

		s.Type = scope.Project.String()
		updatedRows, err := w.Update(context.Background(), s, []string{"Type"}, nil)
		require.Error(err)
		assert.Equal(0, updatedRows)
	})
}
func TestScope_GetScope(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	t.Run("valid-scope", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		org, proj := TestScopes(t, conn)
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

		p := allocScope()
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

	if _, ok := a[action.List.String()]; ok {
		t.Errorf("scopes should not include %s as an action", action.List.String())
	}
}

func TestScope_ResourceType(t *testing.T) {
	o, err := NewOrganization()
	require.NoError(t, err)
	assert.Equal(t, o.ResourceType(), resource.Organization)
	assert.Equal(t, o.GetParentId(), resource.Global.String())
}

func TestScope_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		s, _ := TestScopes(t, conn)
		cp := s.Clone()
		assert.True(proto.Equal(cp.(*Scope).Scope, s.Scope))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		s, _ := TestScopes(t, conn)
		s2, _ := TestScopes(t, conn)
		cp := s.Clone()
		assert.True(!proto.Equal(cp.(*Scope).Scope, s2.Scope))
	})
}

// TestScope_GlobalErrors tests various expected error conditions related to the
// global scope at a layer below the repository, e.g. within the scope logic or the
// DB itself
func TestScope_GlobalErrors(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	t.Run("newScope errors", func(t *testing.T) {
		// Not allowed
		_, err := newScope(scope.Global)
		require.Error(t, err)

		// Should fail as there's no scope
		_, err = newScope(scope.Organization)
		require.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "missing its parent"))
	})
	t.Run("creation disallowed at vet time", func(t *testing.T) {
		// Not allowed to create
		s := allocScope()
		s.Type = scope.Global.String()
		s.PublicId = "global"
		err := s.VetForWrite(context.Background(), nil, db.CreateOp)
		require.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "global scope cannot be created"))
	})
	t.Run("check org parent at vet time", func(t *testing.T) {
		// Org must have global parent
		s := allocScope()
		s.Type = scope.Organization.String()
		s.PublicId = "o_1234"
		s.ParentId = "global"
		err := s.VetForWrite(context.Background(), nil, db.CreateOp)
		require.NoError(t, err)
		s.ParentId = "o_2345"
		err = s.VetForWrite(context.Background(), nil, db.CreateOp)
		require.Error(t, err)
	})
	t.Run("not deletable in db", func(t *testing.T) {
		// Should not be deletable
		s := allocScope()
		s.PublicId = "global"
		// Add this to validate that we did in fact delete
		err := w.LookupById(context.Background(), &s)
		require.NoError(t, err)
		require.Equal(t, s.Type, scope.Global.String())
		rows, err := w.Delete(context.Background(), &s)
		require.Error(t, err)
		assert.Equal(t, 0, rows)
	})
}
