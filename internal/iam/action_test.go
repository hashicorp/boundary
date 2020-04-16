package iam

import (
	"testing"

	"gotest.tools/assert"
)

// Test_StdActions provides unit tests for StdActions()
func Test_StdActions(t *testing.T) {
	t.Parallel()
	t.Run("valid", func(t *testing.T) {
		a := StdActions()
		assert.Equal(t, a[ActionList.String()], ActionList)
		assert.Equal(t, a[ActionCreate.String()], ActionCreate)
		assert.Equal(t, a[ActionUpdate.String()], ActionUpdate)
		assert.Equal(t, a[ActionDelete.String()], ActionDelete)
	})
	t.Run("invalid", func(t *testing.T) {
		a := StdActions()
		action, ok := a["invalid"]
		assert.Equal(t, ok, false)
		assert.Equal(t, action, ActionUnknown)
	})
}
