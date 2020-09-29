// +build integration

package e2e

import (
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api/groups"
	"github.com/stretchr/testify/assert"
)

const groupsCmd = "groups"

type testGroup struct {
	group *groups.Group
}

func (x *testGroup) create(t *testing.T, kind string) error {
	if kind == "" {
		kind = kindPassword
	}

	createCase := testCase{
		cmd:      boundary,
		resource: groupsCmd,
		action:   create,
		args: []string{
			"-scope-id", x.group.ScopeId,
			"-name", x.group.Name,
			"-description", x.group.Description,
			"-format", "json"},
	}

	x.group = caseRunner(createCase, x.group, t).(*groups.Group)
	return nil
}

func (x *testGroup) read(t *testing.T) error {
	readCase := testCase{
		cmd:      boundary,
		resource: groupsCmd,
		action:   read,
		args: []string{
			"-id", x.group.Id,
			"-format", "json",
		},
	}

	x.group = caseRunner(readCase, x.group, t).(*groups.Group)
	return nil
}

func (x *testGroup) update(t *testing.T) error {
	updateCase := testCase{
		cmd:      boundary,
		resource: groupsCmd,
		action:   update,
		args: []string{
			"-id", x.group.Id,
			"-name", x.group.Name,
			"-description", x.group.Description,
			"-format", "json"},
	}
	x.group = caseRunner(updateCase, x.group, t).(*groups.Group)
	return nil
}

func (x *testGroup) delete(t *testing.T) error {
	deleteCase := testCase{
		cmd:      boundary,
		resource: groupsCmd,
		action:   vDelete,
		args: []string{
			"-id", x.group.Id,
		},
	}
	x.group = caseRunner(deleteCase, x.group, t).(*groups.Group)
	return nil
}

func TestGroups(t *testing.T) {
	var (
		name       = "test"
		desc       = "testdescription"
		descUpdate = "testdescriptionupdate"
		scopeID    = "global"

		ta = testGroup{
			group: &groups.Group{
				Name:        name,
				Description: desc,
				ScopeId:     scopeID,
			},
		}
	)

	t.Run(fmt.Sprintf("%s %s %s", boundary, groupsCmd, create), func(t *testing.T) {
		if err := ta.create(t, ""); err != nil {
			t.Error(err)
		}
		assert.NotEmpty(t, ta.group.Id, "group ID must not be empty")
	})

	createID := ta.group.Id

	t.Run(fmt.Sprintf("%s %s %s", boundary, groupsCmd, read), func(t *testing.T) {
		if err := ta.read(t); err != nil {
			t.Error(err)
		}
		assert.Equal(t, createID, ta.group.Id, "create and read ID must be equal")
		assert.Equal(t, ta.group.Name, name, "create name and read group name must be equal")
		assert.Equal(t, ta.group.Description, desc, "create name and read group description must be equal")
	})

	t.Run(fmt.Sprintf("%s %s %s", boundary, groupsCmd, update), func(t *testing.T) {
		ta.group.Description = descUpdate
		if err := ta.update(t); err != nil {
			t.Error(err)
		}
		assert.Equal(t, ta.group.Description, descUpdate, "group description must be updated")
	})

	t.Run(fmt.Sprintf("%s %s %s", boundary, groupsCmd, vDelete), func(t *testing.T) {
		if err := ta.delete(t); err != nil {
			t.Error(err)
		}
		assert.NotEmpty(t, ta.group.Id, "group ID must not be empty on delete")
	})
}
