// +build integration

package e2e

import (
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api/roles"
	"github.com/stretchr/testify/assert"
)

const rolesCmd = "roles"

type testRole struct {
	role *roles.Role
}

func (x *testRole) create(t *testing.T) error {
	createCase := testCase{
		cmd:      boundary,
		resource: rolesCmd,
		action:   create,
		args: []string{
			"-scope-id", x.role.ScopeId,
			"-name", x.role.Name,
			"-description", x.role.Description,
			"-format", "json"},
	}

	x.role = caseRunner(createCase, x.role, t).(*roles.Role)
	return nil
}

func (x *testRole) read(t *testing.T) error {
	readCase := testCase{
		cmd:      boundary,
		resource: rolesCmd,
		action:   read,
		args: []string{
			"-id", x.role.Id,
			"-format", "json"},
	}

	x.role = caseRunner(readCase, x.role, t).(*roles.Role)
	return nil
}

func (x *testRole) update(t *testing.T) error {
	updateCase := testCase{
		cmd:      boundary,
		resource: rolesCmd,
		action:   update,
		args: []string{
			"-id", x.role.Id,
			"-name", x.role.Name,
			"-description", x.role.Description,
			"-format", "json"},
	}

	x.role = caseRunner(updateCase, x.role, t).(*roles.Role)
	return nil
}

func (x *testRole) delete(t *testing.T) error {
	deleteCase := testCase{
		cmd:      boundary,
		resource: rolesCmd,
		action:   vDelete,
		args: []string{
			"-id", x.role.Id,
		},
	}

	x.role = caseRunner(deleteCase, x.role, t).(*roles.Role)
	return nil
}

func TestRoles_HappyPath(t *testing.T) {
	var (
		name       = "test"
		desc       = "testdescription"
		descUpdate = "testdescriptionupdate"
		scopeID    = "global"

		ta = testRole{
			role: &roles.Role{
				Name:        name,
				Description: desc,
				ScopeId:     scopeID,
			},
		}
	)

	t.Run(fmt.Sprintf("%s %s %s", boundary, rolesCmd, create), func(t *testing.T) {
		if err := ta.create(t); err != nil {
			t.Error(err)
		}
		assert.NotEmpty(t, ta.role.Id, "role ID must not be empty")
	})

	createID := ta.role.Id

	t.Run(fmt.Sprintf("%s %s %s", boundary, rolesCmd, read), func(t *testing.T) {
		if err := ta.read(t); err != nil {
			t.Error(err)
		}
		assert.Equal(t, createID, ta.role.Id, "create and read ID must be equal")
		assert.Equal(t, ta.role.Name, name, "create name and read role name must be equal")
		assert.Equal(t, ta.role.Description, desc, "create name and read role description must be equal")
	})

	t.Run(fmt.Sprintf("%s %s %s", boundary, rolesCmd, update), func(t *testing.T) {
		ta.role.Description = descUpdate
		if err := ta.update(t); err != nil {
			t.Error(err)
		}
		assert.Equal(t, ta.role.Description, descUpdate, "role description must be updated")
	})

	t.Run(fmt.Sprintf("%s %s %s", boundary, rolesCmd, vDelete), func(t *testing.T) {
		if err := ta.delete(t); err != nil {
			t.Error(err)
		}
		assert.NotEmpty(t, ta.role.Id, "role ID must not be empty on delete")
	})

}
