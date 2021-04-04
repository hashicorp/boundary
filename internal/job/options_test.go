package job

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithNextScheduledRun", func(t *testing.T) {
		assert := assert.New(t)
		ts := time.Now().Add(time.Hour)
		opts := getOpts(WithNextScheduledRun(ts))
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withNextScheduledRun = ts
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
}
