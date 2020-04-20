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

		rootUser, err := NewUser(s, AsRootUser(true))
		assert.NilError(t, err)
		err = w.Create(context.Background(), rootUser)
		assert.NilError(t, err)

		role, err := NewRole(s, rootUser, WithDescription("this is a test role"))
		assert.NilError(t, err)
		assert.Check(t, role != nil)
		assert.Equal(t, rootUser.Id, role.OwnerId)
		assert.Equal(t, role.Description, "this is a test role")
		assert.Equal(t, s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.NilError(t, err)
		assert.Check(t, role.Id != 0)

		uRole, err := NewPrincipalRole(s, role, rootUser)
		assert.NilError(t, err)
		assert.Check(t, uRole != nil)
		assert.Equal(t, uRole.GetRoleId(), role.Id)
		assert.Equal(t, uRole.GetPrincipalId(), rootUser.Id)
		err = w.Create(context.Background(), uRole)
		assert.NilError(t, err)
		assert.Check(t, uRole != nil)
		assert.Equal(t, uRole.GetPrincipalId(), rootUser.Id)

		grp, err := NewGroup(s, rootUser, WithDescription("this is a test group"))
		assert.NilError(t, err)
		assert.Check(t, grp != nil)
		assert.Equal(t, rootUser.Id, grp.OwnerId)
		assert.Equal(t, grp.Description, "this is a test group")
		assert.Equal(t, s.Id, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.NilError(t, err)
		assert.Check(t, grp.Id != 0)

		gRole, err := NewPrincipalRole(s, role, grp)
		assert.NilError(t, err)
		assert.Check(t, gRole != nil)
		assert.Equal(t, gRole.GetRoleId(), role.Id)
		assert.Equal(t, gRole.GetPrincipalId(), grp.Id)
		err = w.Create(context.Background(), gRole)
		assert.NilError(t, err)
		assert.Check(t, gRole != nil)
		assert.Equal(t, gRole.GetPrincipalId(), grp.Id)

		meth, err := NewAuthMethod(s, rootUser, AuthUserPass)
		assert.NilError(t, err)
		assert.Check(t, meth != nil)
		err = w.Create(context.Background(), meth)
		assert.NilError(t, err)

		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		alias, err := NewUserAlias(s, rootUser, meth, id)
		assert.NilError(t, err)
		assert.Check(t, alias != nil)
		err = w.Create(context.Background(), alias)
		assert.NilError(t, err)
		assert.Equal(t, alias.OwnerId, rootUser.Id)

		aRole, err := NewPrincipalRole(s, role, alias)
		assert.NilError(t, err)
		assert.Check(t, aRole != nil)
		assert.Equal(t, aRole.GetRoleId(), role.Id)
		assert.Equal(t, aRole.GetPrincipalId(), alias.Id)
		err = w.Create(context.Background(), aRole)
		assert.NilError(t, err)
		assert.Check(t, aRole.GetId() != 0)
	})
}
