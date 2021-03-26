package job

import (
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithNextScheduledRun", func(t *testing.T) {
		assert := assert.New(t)
		ts := &timestamp.Timestamp{Timestamp: timestamppb.New(time.Now().Add(time.Hour))}
		opts := getOpts(WithNextScheduledRun(ts))
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withNextScheduledRun = ts
		assert.Equal(opts, testOpts)
	})
	t.Run("WithLimit", func(t *testing.T) {
		assert := assert.New(t)
		// test default of 0
		opts := getOpts()
		testOpts := getDefaultOptions()
		testOpts.withLimit = 0
		assert.Equal(opts, testOpts)

		opts = getOpts(WithLimit(-1))
		testOpts = getDefaultOptions()
		testOpts.withLimit = -1
		assert.Equal(opts, testOpts)

		opts = getOpts(WithLimit(1))
		testOpts = getDefaultOptions()
		testOpts.withLimit = 1
		assert.Equal(opts, testOpts)
	})
	t.Run("withJobRunStatus", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithJobRunStatus(Completed))
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withJobRunStatus = Completed
		assert.Equal(opts, testOpts)
	})
}
