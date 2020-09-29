// +build integration

package e2e

import (
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api/users"
	"github.com/stretchr/testify/assert"
)

const usersCmd = "users"

type testUser struct {
	user *users.User
}

func (x *testUser) create(t *testing.T) error {
	createCase := testCase{
		cmd:      boundary,
		resource: usersCmd,
		action:   create,
		args: []string{
			"-scope-id", x.user.ScopeId,
			"-name", x.user.Name,
			"-description", x.user.Description,
			"-format", "json"},
	}

	x.user = caseRunner(createCase, x.user, t).(*users.User)
	return nil
}

func (x *testUser) read(t *testing.T) error {
	readCase := testCase{
		cmd:      boundary,
		resource: usersCmd,
		action:   read,
		args: []string{
			"-id", x.user.Id,
			"-format", "json",
		},
	}

	x.user = caseRunner(readCase, x.user, t).(*users.User)
	return nil
}

func (x *testUser) update(t *testing.T) error {
	updateCase := testCase{
		cmd:      boundary,
		resource: usersCmd,
		action:   update,
		args: []string{
			"-id", x.user.Id,
			"-name", x.user.Name,
			"-description", x.user.Description,
			"-format", "json"},
	}
	x.user = caseRunner(updateCase, x.user, t).(*users.User)
	return nil
}

func (x *testUser) delete(t *testing.T) error {
	deleteCase := testCase{
		cmd:      boundary,
		resource: usersCmd,
		action:   vDelete,
		args: []string{
			"-id", x.user.Id,
		},
	}
	x.user = caseRunner(deleteCase, x.user, t).(*users.User)
	return nil
}

func TestUsers(t *testing.T) {
	var (
		name       = "test"
		desc       = "testdescription"
		descUpdate = "testdescriptionupdate"
		scopeID    = "global"

		ta = testUser{
			user: &users.User{
				Name:        name,
				Description: desc,
				ScopeId:     scopeID,
			},
		}
	)

	t.Run(fmt.Sprintf("%s %s %s", boundary, usersCmd, create), func(t *testing.T) {
		if err := ta.create(t); err != nil {
			t.Error(err)
		}
		assert.NotEmpty(t, ta.user.Id, "user ID must not be empty")
	})

	createID := ta.user.Id

	t.Run(fmt.Sprintf("%s %s %s", boundary, usersCmd, read), func(t *testing.T) {
		if err := ta.read(t); err != nil {
			t.Error(err)
		}
		assert.Equal(t, createID, ta.user.Id, "create and read ID must be equal")
		assert.Equal(t, ta.user.Name, name, "create name and read user name must be equal")
		assert.Equal(t, ta.user.Description, desc, "create name and read user description must be equal")
	})

	t.Run(fmt.Sprintf("%s %s %s", boundary, usersCmd, update), func(t *testing.T) {
		ta.user.Description = descUpdate
		if err := ta.update(t); err != nil {
			t.Error(err)
		}
		assert.Equal(t, ta.user.Description, descUpdate, "user description must be updated")
	})

	t.Run(fmt.Sprintf("%s %s %s", boundary, usersCmd, vDelete), func(t *testing.T) {
		if err := ta.delete(t); err != nil {
			t.Error(err)
		}
		assert.NotEmpty(t, ta.user.Id, "user ID must not be empty on delete")
	})
}
