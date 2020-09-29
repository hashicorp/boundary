// +build integration

package e2e

import (
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/stretchr/testify/assert"
)

const amCmd = "auth-methods"

type testAuthMethod struct {
	am *authmethods.AuthMethod
}

func (x *testAuthMethod) create(t *testing.T, kind string) error {
	if kind == "" {
		kind = kindPassword
	}

	createCase := testCase{
		cmd:      boundary,
		resource: amCmd,
		action:   create,
		args: []string{
			kindPassword,
			"-scope-id", "global",
			"-name", x.am.Name,
			"-description", x.am.Description,
			"-format", "json"},
	}

	x.am = caseRunner(createCase, x.am, t).(*authmethods.AuthMethod)
	return nil
}

func (x *testAuthMethod) read(t *testing.T) error {
	readCase := testCase{
		cmd:      boundary,
		resource: amCmd,
		action:   read,
		args: []string{
			"-id", x.am.Id,
			"-format", "json"},
	}

	x.am = caseRunner(readCase, x.am, t).(*authmethods.AuthMethod)
	return nil
}

func (x *testAuthMethod) update(t *testing.T) error {
	updateCase := testCase{
		cmd:      boundary,
		resource: amCmd,
		action:   update,
		args: []string{
			"password",
			"-id", x.am.Id,
			"-name", x.am.Name,
			"-description", x.am.Description,
			"-format", "json"},
	}

	x.am = caseRunner(updateCase, x.am, t).(*authmethods.AuthMethod)
	return nil
}

func (x *testAuthMethod) delete(t *testing.T) error {
	deleteCase := testCase{
		cmd:      boundary,
		resource: amCmd,
		action:   vDelete,
		args: []string{
			"-id", x.am.Id,
		},
	}

	x.am = caseRunner(deleteCase, x.am, t).(*authmethods.AuthMethod)
	return nil
}

func TestAuthMethods(t *testing.T) {
	var (
		name       = "test"
		desc       = "testdescription"
		descUpdate = "testdescriptionupdate"

		ta = testAuthMethod{
			am: &authmethods.AuthMethod{
				Name:        name,
				Description: desc,
			},
		}
	)

	t.Run(fmt.Sprintf("%s %s %s", boundary, amCmd, create), func(t *testing.T) {
		if err := ta.create(t, ""); err != nil {
			t.Error(err)
		}
		assert.NotEmpty(t, ta.am.Id, "auth method ID must not be empty")
	})

	createID := ta.am.Id

	t.Run(fmt.Sprintf("%s %s %s", boundary, amCmd, read), func(t *testing.T) {
		if err := ta.read(t); err != nil {
			t.Error(err)
		}
		assert.Equal(t, createID, ta.am.Id, "create and read ID must be equal")
		assert.Equal(t, ta.am.Name, name, "create name and read auth method name must be equal")
		assert.Equal(t, ta.am.Description, desc, "create name and read auth method description must be equal")
	})

	t.Run(fmt.Sprintf("%s %s %s", boundary, amCmd, update), func(t *testing.T) {
		ta.am.Description = descUpdate
		if err := ta.update(t); err != nil {
			t.Error(err)
		}
		assert.Equal(t, ta.am.Description, descUpdate, "auth method description must be updated")
	})

	t.Run(fmt.Sprintf("%s %s %s", boundary, amCmd, vDelete), func(t *testing.T) {
		if err := ta.delete(t); err != nil {
			t.Error(err)
		}
		assert.NotEmpty(t, ta.am.Id, "auth method ID must not be empty on delete")
	})
}
