package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func Test_NewScope(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid-org-with-project", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.NotEmpty(s.PublicId)

		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		projScope, err := NewProject(s.PublicId, WithDescription(id))
		assert.NoError(err)
		assert.NotNil(projScope.Scope)
		assert.Equal(projScope.GetParentId(), s.PublicId)
		assert.Equal(projScope.GetDescription(), id)
	})
	t.Run("unknown-scope", func(t *testing.T) {
		s, err := newScope(UnknownScope)
		assert.NotNil(err)
		assert.Nil(s)
		assert.Equal(err.Error(), "error unknown scope type for new scope")
	})
	t.Run("proj-scope-with-no-org", func(t *testing.T) {
		s, err := NewProject("")
		assert.NotNil(err)
		assert.Nil(s)
		assert.Equal(err.Error(), "error creating new project: error project scope parent id is unset")
	})
}
func Test_ScopeCreate(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.NotEmpty(s.PublicId)
	})
	t.Run("valid-with-parent", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.NotEmpty(s.PublicId)

		id, err := uuid.GenerateUUID()
		assert.NoError(err)

		project, err := NewProject(s.PublicId, WithDescription(id))
		assert.NoError(err)
		assert.NotNil(project.Scope)
		assert.Equal(project.Scope.ParentId, s.PublicId)
		assert.Equal(project.GetDescription(), id)

		err = w.Create(context.Background(), project)
		assert.NoError(err)
		assert.Equal(project.ParentId, s.PublicId)
	})
}

func Test_ScopeUpdate(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.NotEmpty(s.PublicId)

		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		s.Name = id
		updatedRows, err := w.Update(context.Background(), s, []string{"Name"})
		assert.NoError(err)
		assert.Equal(1, updatedRows)
	})
	t.Run("type-update-not-allowed", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.NotEmpty(s.PublicId)

		s.Type = ProjectScope.String()
		updatedRows, err := w.Update(context.Background(), s, []string{"Type"})
		assert.NotNil(err)
		assert.Equal(0, updatedRows)
	})
}
func Test_ScopeGetScope(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer conn.Close()
	t.Run("valid-scope", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.NotEmpty(s.PublicId)

		foundScope, err := s.GetScope(context.Background(), w)
		assert.NoError(err)
		assert.Nil(foundScope)

		project, err := NewProject(s.PublicId)
		assert.NoError(err)
		assert.NotNil(project.Scope)
		assert.Equal(project.ParentId, s.PublicId)
		err = w.Create(context.Background(), project)
		assert.NoError(err)

		projectOrg, err := project.GetScope(context.Background(), w)
		assert.NoError(err)
		assert.NotNil(projectOrg)
		assert.Equal(projectOrg.PublicId, project.ParentId)

		p := allocScope()
		p.PublicId = project.PublicId
		p.Type = ProjectScope.String()
		projectOrg, err = p.GetScope(context.Background(), w)
		assert.NoError(err)
		assert.Equal(s.PublicId, projectOrg.PublicId)
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
	assert := assert.New(t)
	o, err := NewOrganization()
	assert.NoError(err)
	ty := o.ResourceType()
	assert.Equal(ty, ResourceTypeOrganization)
}

func TestScope_Clone(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.NotEmpty(s.PublicId)

		cp := s.Clone()
		assert.True(proto.Equal(cp.(*Scope).Scope, s.Scope))
	})
	t.Run("not-equal", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.NotEmpty(s.PublicId)

		s2, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s2.Scope)
		err = w.Create(context.Background(), s2)
		assert.NoError(err)
		assert.NotEmpty(s2.PublicId)

		cp := s.Clone()
		assert.True(!proto.Equal(cp.(*Scope).Scope, s2.Scope))
	})
}
