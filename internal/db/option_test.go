package db

import (
	"reflect"
	"testing"

	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/stretchr/testify/assert"
)

// Test_getOpts provides unit tests for GetOpts and all the options
func Test_getOpts(t *testing.T) {
	assert := assert.New(t)
	t.Parallel()
	t.Run("WithOplog", func(t *testing.T) {
		// test default of false
		opts := getOpts()
		testOpts := getDefaultOptions()
		testOpts.withOplog = false
		assert.True(reflect.DeepEqual(opts, testOpts))

		wrapper := TestWrapper(t)
		md := oplog.Metadata{
			"key-only":   nil,
			"deployment": []string{"amex"},
			"project":    []string{"central-info-systems", "local-info-systems"},
		}
		// try setting to true
		opts = getOpts(WithOplog(wrapper, md))
		testOpts = getDefaultOptions()
		testOpts.withOplog = true
		testOpts.oplogOpts = oplogOpts{
			wrapper:  wrapper,
			metadata: md,
		}
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
	t.Run("WithLookup", func(t *testing.T) {
		// test default of true
		opts := getOpts()
		testOpts := getDefaultOptions()
		testOpts.withLookup = false
		assert.True(reflect.DeepEqual(opts, testOpts))

		// try setting to false
		opts = getOpts(WithLookup(true))
		testOpts = getDefaultOptions()
		testOpts.withLookup = true
		assert.True(reflect.DeepEqual(opts, testOpts))

	})
	t.Run("WithDebug", func(t *testing.T) {
		// test default of false
		opts := getOpts()
		testOpts := getDefaultOptions()
		testOpts.withDebug = false
		assert.True(reflect.DeepEqual(opts, testOpts))

		// try setting to true
		opts = getOpts(WithDebug(true))
		testOpts = getDefaultOptions()
		testOpts.withDebug = true
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
}
