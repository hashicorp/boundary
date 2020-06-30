package authtoken

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("withTokenValue", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(withTokenValue())
		testOpts := getDefaultOptions()
		testOpts.withTokenValue = true
		assert.Equal(opts, testOpts)
	})
}
