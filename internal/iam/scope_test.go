package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func Test_NewScope(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	t.Run("valid-org-with-project", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		s, err := NewOrganization()
		require.NoError(err)
		require.NotNil(s.Scope)
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
		s, err := newScope(UnknownScope)
		require.Error(err)
		require.Nil(s)
		assert.Equal(err.Error(), "error unknown scope type for new scope")
	})
	t.Run("proj-scope-with-no-org", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		s, err := NewProject("")
		require.Error(err)
		require.Nil(s)
		assert.Equal(err.Error(), "error creating new project: error project scope parent id is unset")
	})
}
func Test_ScopeCreate(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		s, err := NewOrganization()
		require.NoError(err)
		require.NotNil(s.Scope)
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
		err = w.Create(context.Background(), s)
		require.NoError(err)
		require.NotEmpty(s.PublicId)

		id := testId(t)
		project, err := NewProject(s.PublicId, WithDescription(id))
		require.NoError(err)
		require.NotNil(project.Scope)
		assert.Equal(project.Scope.ParentId, s.PublicId)
		assert.Equal(project.GetDescription(), id)

		err = w.Create(context.Background(), project)
		require.NoError(err)
		assert.Equal(project.ParentId, s.PublicId)
	})
}

func Test_ScopeUpdate(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
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

		s.Type = ProjectScope.String()
		updatedRows, err := w.Update(context.Background(), s, []string{"Type"}, nil)
		require.Error(err)
		assert.Equal(0, updatedRows)
	})
}
func Test_ScopeGetScope(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	t.Run("valid-scope", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		org, proj := TestScopes(t, conn)
		foundScope, err := org.GetScope(context.Background(), w)
		require.NoError(err)
		assert.Nil(foundScope)

		projectOrg, err := proj.GetScope(context.Background(), w)
		require.NoError(err)
		assert.NotNil(projectOrg)
		assert.Equal(projectOrg.PublicId, proj.ParentId)

		p := allocScope()
		p.PublicId = proj.PublicId
		p.Type = ProjectScope.String()
		projectOrg, err = p.GetScope(context.Background(), w)
		require.NoError(err)
		assert.Equal(org.PublicId, projectOrg.PublicId)
	})
}

func TestScope_Actions(t *testing.T) {
	assert := assert.New(t)
	s := &Scope{}
	a := s.Actions()
	assert.Equal(a[ActionCreate.String()], ActionCreate)
	assert.Equal(a[ActionUpdate.String()], ActionUpdate)
	assert.Equal(a[ActionRead.String()], ActionRead)
	assert.Equal(a[ActionDelete.String()], ActionDelete)

	if _, ok := a[ActionList.String()]; ok {
		t.Errorf("scopes should not include %s as an action", ActionList.String())
	}
}

func TestScope_ResourceType(t *testing.T) {
	o, err := NewOrganization()
	require.NoError(t, err)
	assert.Equal(t, o.ResourceType(), ResourceTypeOrganization)
}

func TestScope_Clone(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
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
