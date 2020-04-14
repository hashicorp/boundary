package db

import (
	"reflect"
	"testing"

	"gotest.tools/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithOplog", func(t *testing.T) {
		opts := GetOpts(WithOplog(true))
		testOpts := getDefaultOptions()
		testOpts[optionWithOplog] = true
		assert.Check(t, reflect.DeepEqual(opts, testOpts))
	})

}
