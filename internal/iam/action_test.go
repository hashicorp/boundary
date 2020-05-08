package iam

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_CrudActions provides unit tests for CrudActions()
func Test_CrudActions(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	t.Run("valid", func(t *testing.T) {
		a := CrudlActions()
		assert.Equal(a[ActionCreate.String()], ActionCreate)
		assert.Equal(a[ActionUpdate.String()], ActionUpdate)
		assert.Equal(a[ActionRead.String()], ActionRead)
		assert.Equal(a[ActionDelete.String()], ActionDelete)
	})
	t.Run("invalid", func(t *testing.T) {
		a := CrudlActions()
		action, ok := a["invalid"]
		assert.Equal(ok, false)
		assert.Equal(action, ActionUnknown)
	})
}

// Test_CrudlActions provides unit tests for CrudlActions()
func Test_CrudlActions(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	t.Run("valid", func(t *testing.T) {
		a := CrudlActions()
		assert.Equal(a[ActionCreate.String()], ActionCreate)
		assert.Equal(a[ActionUpdate.String()], ActionUpdate)
		assert.Equal(a[ActionRead.String()], ActionRead)
		assert.Equal(a[ActionDelete.String()], ActionDelete)
	})
	t.Run("invalid", func(t *testing.T) {
		a := CrudlActions()
		action, ok := a["invalid"]
		assert.Equal(ok, false)
		assert.Equal(action, ActionUnknown)
	})
}
