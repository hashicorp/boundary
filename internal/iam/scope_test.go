package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func Test_NewScope(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()

	t.Run("valid-with-child", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		lowerScope, err := NewScope(ProjectScope, WithScope(s))
		assert.Nil(err)
		assert.True(lowerScope.Scope != nil)
		assert.Equal(lowerScope.GetParentId(), s.PublicId)
	})
	t.Run("unknown-scope", func(t *testing.T) {
		s, err := NewScope(UnknownScope)
		assert.True(err != nil)
		assert.True(s == nil)
		assert.Equal(err.Error(), "error unknown scope type for new scope")
	})
	t.Run("proj-scope-with-no-parent", func(t *testing.T) {
		s, err := NewScope(ProjectScope)
		assert.True(err != nil)
		assert.True(s == nil)
		assert.Equal(err.Error(), "error project scope must be with a scope")
	})
}
func Test_ScopeCreate(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")
	})
	t.Run("valid-with-parent", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		scopeWithParent, err := NewScope(ProjectScope, WithScope(s))
		assert.Nil(err)
		assert.True(scopeWithParent.Scope != nil)
		assert.Equal(scopeWithParent.Scope.ParentId, s.PublicId)

		err = w.Create(context.Background(), scopeWithParent)
		assert.Nil(err)
		assert.Equal(scopeWithParent.ParentId, s.PublicId)
	})
}

func Test_ScopeGetPrimaryScope(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()
	t.Run("valid primary scope", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		scopeWithParent, err := NewScope(ProjectScope, WithScope(s))
		assert.Nil(err)
		assert.True(scopeWithParent.Scope != nil)
		assert.Equal(scopeWithParent.ParentId, s.PublicId)
		err = w.Create(context.Background(), scopeWithParent)
		assert.Nil(err)

		primaryScope, err := scopeWithParent.GetPrimaryScope(context.Background(), &w)
		assert.Nil(err)
		assert.True(primaryScope != nil)
		assert.Equal(primaryScope.PublicId, scopeWithParent.ParentId)
	})
}

func Test_ScopeOrganization(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()
	t.Run("valid org scope", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		org, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(org.Scope != nil)
		err = w.Create(context.Background(), org)
		assert.Nil(err)
		assert.True(org.PublicId != "")

		projScope, err := NewScope(ProjectScope, WithScope(org))
		assert.Nil(err)
		assert.True(projScope.Scope != nil)
		assert.Equal(projScope.ParentId, org.PublicId)
		err = w.Create(context.Background(), projScope)
		assert.Nil(err)

		scopeOrg, err := projScope.Organization(context.Background(), &w)
		assert.Nil(err)
		assert.True(scopeOrg != nil)
		assert.Equal(scopeOrg.PublicId, org.PublicId)
	})
}

func TestScope_Actions(t *testing.T) {
	assert := assert.New(t)
	s := &Scope{}
	a := s.Actions()
	assert.Equal(a[ActionList.String()], ActionList)
	assert.Equal(a[ActionCreate.String()], ActionCreate)
	assert.Equal(a[ActionUpdate.String()], ActionUpdate)
	assert.Equal(a[ActionRead.String()], ActionRead)
	assert.Equal(a[ActionDelete.String()], ActionDelete)
}

func TestScope_ResourceType(t *testing.T) {
	assert := assert.New(t)
	r := &Scope{}
	ty := r.ResourceType()
	assert.Equal(ty, ResourceTypeScope)
}

func TestScope_Clone(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		cp := s.Clone()
		assert.True(proto.Equal(cp.(*Scope).Scope, s.Scope))
	})
	t.Run("not-equal", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		s2, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s2.Scope != nil)
		err = w.Create(context.Background(), s2)
		assert.Nil(err)
		assert.True(s2.PublicId != "")

		cp := s.Clone()
		assert.True(!proto.Equal(cp.(*Scope).Scope, s2.Scope))
	})
}
