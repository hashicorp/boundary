package job

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithNextRunAt", func(t *testing.T) {
		assert := assert.New(t)
		ts := time.Now().Add(time.Hour)
		opts := getOpts(WithNextRunAt(ts))
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withNextRunAt = ts
		assert.Equal(opts, testOpts)
	})
	t.Run("WithStatus", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithStatus(Completed))
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withStatus = Completed
		assert.Equal(opts, testOpts)
	})
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
		assert.Equal(uint(defaultRunJobsLimit), opts.withRunJobsLimit)
	})
}
