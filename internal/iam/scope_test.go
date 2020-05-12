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
	cleanup, conn := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid-org-with-project", func(t *testing.T) {
		w := db.Db{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		projScope, err := NewProject(s.PublicId, WithDescription(id))
		assert.Nil(err)
		assert.True(projScope.Scope != nil)
		assert.Equal(projScope.GetParentId(), s.PublicId)
		assert.Equal(projScope.GetDescription(), id)
	})
	t.Run("unknown-scope", func(t *testing.T) {
		s, err := newScope(UnknownScope)
		assert.True(err != nil)
		assert.True(s == nil)
		assert.Equal(err.Error(), "error unknown scope type for new scope")
	})
	t.Run("proj-scope-with-no-org", func(t *testing.T) {
		s, err := NewProject("")
		assert.True(err != nil)
		assert.True(s == nil)
		assert.Equal(err.Error(), "error creating new project: error project scope parent id is unset")
	})
}
func Test_ScopeCreate(t *testing.T) {
	t.Parallel()
	cleanup, conn := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.Db{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")
	})
	t.Run("valid-with-parent", func(t *testing.T) {
		w := db.Db{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		id, err := uuid.GenerateUUID()
		assert.Nil(err)

		project, err := NewProject(s.PublicId, WithDescription(id))
		assert.Nil(err)
		assert.True(project.Scope != nil)
		assert.Equal(project.Scope.ParentId, s.PublicId)
		assert.Equal(project.GetDescription(), id)

		err = w.Create(context.Background(), project)
		assert.Nil(err)
		assert.Equal(project.ParentId, s.PublicId)
	})
}

func Test_ScopeUpdate(t *testing.T) {
	t.Parallel()
	cleanup, conn := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.Db{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		s.Name = id
		err = w.Update(context.Background(), s, []string{"Name"})
		assert.Nil(err)
	})
	t.Run("type-update-not-allowed", func(t *testing.T) {
		w := db.Db{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		s.Type = ProjectScope.String()
		err = w.Update(context.Background(), s, []string{"Type"})
		assert.True(err != nil)
	})
}
func Test_ScopeGetScope(t *testing.T) {
	t.Parallel()
	cleanup, conn := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()
	t.Run("valid-scope", func(t *testing.T) {
		w := db.Db{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		project, err := NewProject(s.PublicId)
		assert.Nil(err)
		assert.True(project.Scope != nil)
		assert.Equal(project.ParentId, s.PublicId)
		err = w.Create(context.Background(), project)
		assert.Nil(err)

		projectOrg, err := project.GetScope(context.Background(), &w)
		assert.Nil(err)
		assert.True(projectOrg != nil)
		assert.Equal(projectOrg.PublicId, project.ParentId)
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
	assert.Nil(err)
	ty := o.ResourceType()
	assert.Equal(ty, ResourceTypeOrganization)
}

func TestScope_Clone(t *testing.T) {
	t.Parallel()
	cleanup, conn := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.Db{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		cp := s.Clone()
		assert.True(proto.Equal(cp.(*Scope).Scope, s.Scope))
	})
	t.Run("not-equal", func(t *testing.T) {
		w := db.Db{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		s2, err := NewOrganization()
		assert.Nil(err)
		assert.True(s2.Scope != nil)
		err = w.Create(context.Background(), s2)
		assert.Nil(err)
		assert.True(s2.PublicId != "")

		cp := s.Clone()
		assert.True(!proto.Equal(cp.(*Scope).Scope, s2.Scope))
	})
}
