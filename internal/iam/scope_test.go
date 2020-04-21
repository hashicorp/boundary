package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"gotest.tools/assert"
)

func Test_NewScope(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid-with-child", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		lowerScope, err := NewScope(ProjectScope, WithScope(s))
		assert.NilError(t, err)
		assert.Check(t, lowerScope.Scope != nil)
		assert.Equal(t, lowerScope.GetParentId(), s.Id)
	})
}
func Test_ScopeCreate(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)
	})
	t.Run("valid-with-parent", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		scopeWithParent, err := NewScope(ProjectScope, WithScope(s))
		assert.NilError(t, err)
		assert.Check(t, scopeWithParent.Scope != nil)
		assert.Equal(t, scopeWithParent.Scope.ParentId, s.Id)

		err = w.Create(context.Background(), scopeWithParent)
		assert.NilError(t, err)
		assert.Equal(t, scopeWithParent.ParentId, s.Id)
	})
}

func Test_ScopeGetPrimaryScope(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	t.Run("valid primary scope", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		scopeWithParent, err := NewScope(ProjectScope, WithScope(s))
		assert.NilError(t, err)
		assert.Check(t, scopeWithParent.Scope != nil)
		assert.Equal(t, scopeWithParent.ParentId, s.Id)
		err = w.Create(context.Background(), scopeWithParent)
		assert.NilError(t, err)

		primaryScope, err := scopeWithParent.GetPrimaryScope(context.Background(), &w)
		assert.NilError(t, err)
		assert.Check(t, primaryScope != nil)
		assert.Equal(t, primaryScope.Id, scopeWithParent.ParentId)
	})
}

func Test_ScopeOrganization(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	t.Run("valid org scope", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		org, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, org.Scope != nil)
		err = w.Create(context.Background(), org)
		assert.NilError(t, err)
		assert.Check(t, org.Id != 0)

		projScope, err := NewScope(ProjectScope, WithScope(org))
		assert.NilError(t, err)
		assert.Check(t, projScope.Scope != nil)
		assert.Equal(t, projScope.ParentId, org.Id)
		err = w.Create(context.Background(), projScope)
		assert.NilError(t, err)

		scopeOrg, err := projScope.Organization(context.Background(), &w)
		assert.NilError(t, err)
		assert.Check(t, scopeOrg != nil)
		assert.Equal(t, scopeOrg.Id, org.Id)
	})
}
