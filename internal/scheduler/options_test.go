package scheduler

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithRunJobsLimit", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithRunJobsLimit(10))
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withRunJobsLimit = 10
		assert.Equal(opts, testOpts)
	})
	t.Run("WithZeroRunJobsLimit", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithRunJobsLimit(0))
		testOpts := getDefaultOptions()
		assert.Equal(opts, testOpts)
	})
	t.Run("WithRunJobsInterval", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithRunJobsInterval(time.Hour))
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withRunJobInterval = time.Hour
		assert.Equal(opts, testOpts)
	})
	t.Run("WithZeroRunJobsInterval", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithRunJobsInterval(0))
		testOpts := getDefaultOptions()
		assert.Equal(opts, testOpts)
	})
}
