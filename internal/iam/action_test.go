package iam

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_StdActions provides unit tests for StdActions()
func Test_StdActions(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	t.Run("valid", func(t *testing.T) {
		a := CrudActions()
		assert.Equal(a[ActionList.String()], ActionList)
		assert.Equal(a[ActionCreate.String()], ActionCreate)
		assert.Equal(a[ActionUpdate.String()], ActionUpdate)
		assert.Equal(a[ActionRead.String()], ActionRead)
		assert.Equal(a[ActionDelete.String()], ActionDelete)
	})
	t.Run("invalid", func(t *testing.T) {
		a := CrudActions()
		action, ok := a["invalid"]
		assert.Equal(ok, false)
		assert.Equal(action, ActionUnknown)
	})
}
