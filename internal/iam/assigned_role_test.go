package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	"gotest.tools/assert"
)

func Test_NewPrincipalRole(t *testing.T) {
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

		user, err := NewUser(s)
		assert.NilError(t, err)
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.NilError(t, err)
		assert.Check(t, role != nil)
		assert.Equal(t, role.Description, "this is a test role")
		assert.Equal(t, s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.NilError(t, err)
		assert.Check(t, role.Id != 0)

		uRole, err := NewAssignedRole(s, role, user)
		assert.NilError(t, err)
		assert.Check(t, uRole != nil)
		assert.Equal(t, uRole.GetRoleId(), role.Id)
		assert.Equal(t, uRole.GetPrincipalId(), user.Id)
		err = w.Create(context.Background(), uRole)
		assert.NilError(t, err)
		assert.Check(t, uRole != nil)
		assert.Equal(t, uRole.GetPrincipalId(), user.Id)

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.NilError(t, err)
		assert.Check(t, grp != nil)
		assert.Equal(t, grp.Description, "this is a test group")
		assert.Equal(t, s.Id, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.NilError(t, err)
		assert.Check(t, grp.Id != 0)

		gRole, err := NewAssignedRole(s, role, grp)
		assert.NilError(t, err)
		assert.Check(t, gRole != nil)
		assert.Equal(t, gRole.GetRoleId(), role.Id)
		assert.Equal(t, gRole.GetPrincipalId(), grp.Id)
		err = w.Create(context.Background(), gRole)
		assert.NilError(t, err)
		assert.Check(t, gRole != nil)
		assert.Equal(t, gRole.GetPrincipalId(), grp.Id)

		meth, err := NewAuthMethod(s, AuthUserPass)
		assert.NilError(t, err)
		assert.Check(t, meth != nil)
		err = w.Create(context.Background(), meth)
		assert.NilError(t, err)

		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		alias, err := NewUserAlias(s, user, meth, id)
		assert.NilError(t, err)
		assert.Check(t, alias != nil)
		err = w.Create(context.Background(), alias)
		assert.NilError(t, err)

		aRole, err := NewAssignedRole(s, role, alias)
		assert.NilError(t, err)
		assert.Check(t, aRole != nil)
		assert.Equal(t, aRole.GetRoleId(), role.Id)
		assert.Equal(t, aRole.GetPrincipalId(), alias.Id)
		err = w.Create(context.Background(), aRole)
		assert.NilError(t, err)
		assert.Check(t, aRole.GetId() != 0)
	})
}
