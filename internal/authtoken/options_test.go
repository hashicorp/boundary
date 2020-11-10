package authtoken

import (
	"testing"
	"time"

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

	t.Run("WithTokenTimeToLiveDuration", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithTokenTimeToLiveDuration(1 * time.Hour))
		testOpts := getDefaultOptions()
		testOpts.withTokenTimeToLiveDuration = 1 * time.Hour
		assert.Equal(opts, testOpts)
	})

	t.Run("WithTokenTimeToLiveDurationZeroed", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithTokenTimeToLiveDuration(0))
		testOpts := getDefaultOptions()
		assert.Equal(opts, testOpts)
	})

	t.Run("WithTokenTimeToLiveStale", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithTokenTimeToStaleDuration(1 * time.Hour))
		testOpts := getDefaultOptions()
		testOpts.withTokenTimeToStaleDuration = 1 * time.Hour
		assert.Equal(opts, testOpts)
	})

	t.Run("WithTokenTimeToLiveStaleZeroed", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithTokenTimeToStaleDuration(0))
		testOpts := getDefaultOptions()
		assert.Equal(opts, testOpts)
	})
}
