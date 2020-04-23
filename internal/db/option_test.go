package db

import (
	"reflect"
	"testing"

	"github.com/hashicorp/watchtower/internal/oplog"
	"gotest.tools/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithOplog", func(t *testing.T) {
		// test default of false
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts[optionWithOplog] = false
		assert.Check(t, reflect.DeepEqual(opts, testOpts))

		// try setting to true
		opts = GetOpts(WithOplog(true))
		testOpts = getDefaultOptions()
		testOpts[optionWithOplog] = true
		assert.Check(t, reflect.DeepEqual(opts, testOpts))
	})
	t.Run("WithLookup", func(t *testing.T) {
		// test default of true
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts[optionWithLookup] = false
		assert.Check(t, reflect.DeepEqual(opts, testOpts))

		// try setting to false
		opts = GetOpts(WithLookup(true))
		testOpts = getDefaultOptions()
		testOpts[optionWithLookup] = true
		assert.Check(t, reflect.DeepEqual(opts, testOpts))

	})
	t.Run("WithMetadata", func(t *testing.T) {
		// default of no metadata
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts[optionWithMetadata] = oplog.Metadata{}
		assert.Check(t, reflect.DeepEqual(opts, testOpts))

		// try setting metadata
		opts = GetOpts(WithMetadata(oplog.Metadata{
			"key-only":   nil,
			"deployment": []string{"amex"},
			"project":    []string{"central-info-systems", "local-info-systems"},
		}))
		testOpts = getDefaultOptions()
		testOpts[optionWithMetadata] = oplog.Metadata{
			"key-only":   nil,
			"deployment": []string{"amex"},
			"project":    []string{"central-info-systems", "local-info-systems"},
		}
		assert.Check(t, reflect.DeepEqual(opts, testOpts))
	})
	t.Run("WithWrapper", func(t *testing.T) {
		// default of no wrapper
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts[optionWithWrapper] = nil
		assert.Check(t, reflect.DeepEqual(opts, testOpts))

		// try setting wrapper
		wrapper := InitTestWrapper(t)
		opts = GetOpts(WithWrapper(wrapper))
		testOpts = getDefaultOptions()
		testOpts[optionWithWrapper] = wrapper
		assert.Check(t, reflect.DeepEqual(opts, testOpts))
	})
}
