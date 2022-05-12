package servers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	opts := getOpts()
	assert.Equal(t, options{}, opts)

	t.Run("WithName", func(t *testing.T) {
		opts := getOpts(WithName("test"))
		testOpts := getDefaultOptions()
		testOpts.withName = "test"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithDescription", func(t *testing.T) {
		opts := getOpts(WithDescription("test desc"))
		testOpts := getDefaultOptions()
		testOpts.withDescription = "test desc"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithLimit", func(t *testing.T) {
		opts := getOpts(WithLimit(5))
		testOpts := getDefaultOptions()
		testOpts.withLimit = 5
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithAddress", func(t *testing.T) {
		opts := getOpts(WithAddress("test"))
		testOpts := getDefaultOptions()
		testOpts.withAddress = "test"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithPublicId", func(t *testing.T) {
		opts := getOpts(WithPublicId("test"))
		testOpts := getDefaultOptions()
		testOpts.withPublicId = "test"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithLiveness", func(t *testing.T) {
		opts := getOpts(WithLiveness(time.Hour))
		testOpts := getDefaultOptions()
		testOpts.withLiveness = time.Hour
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithUpdateTags", func(t *testing.T) {
		opts := getOpts(WithUpdateTags(true))
		testOpts := getDefaultOptions()
		testOpts.withUpdateTags = true
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithWorkerTags", func(t *testing.T) {
		tags := []*Tag{
			{Key: "key1", Value: "val1"},
			{Key: "key2", Value: "val2"},
		}
		opts := getOpts(WithWorkerTags(tags...))
		testOpts := getDefaultOptions()
		testOpts.withWorkerTags = tags
		assert.Equal(t, opts, testOpts)
	})
}
