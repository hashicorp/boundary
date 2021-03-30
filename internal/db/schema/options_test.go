package schema

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithMigrationStates", func(t *testing.T) {
		assert := assert.New(t)
		oState := TestCloneMigrationStates(t)
		nState := TestCreatePartialMigrationState(oState["postgres"], 8)
		oState["postgres"] = nState
		opts := getOpts(WithMigrationStates(oState))
		testOpts := getDefaultOptions()
		testOpts.withMigrationStates = oState
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDeleteLog", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithDeleteLog(true))
		testOpts := getDefaultOptions()
		testOpts.withDeleteLog = true
		assert.Equal(opts, testOpts)
	})
}
