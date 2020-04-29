package db

import (
	"reflect"
	"testing"

	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	assert := assert.New(t)
	t.Parallel()
	t.Run("WithOplog", func(t *testing.T) {
		// test default of false
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts[optionWithOplog] = false
		assert.True(reflect.DeepEqual(opts, testOpts))

		// try setting to true
		opts = GetOpts(WithOplog(true))
		testOpts = getDefaultOptions()
		testOpts[optionWithOplog] = true
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
	t.Run("WithLookup", func(t *testing.T) {
		// test default of true
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts[optionWithLookup] = false
		assert.True(reflect.DeepEqual(opts, testOpts))

		// try setting to false
		opts = GetOpts(WithLookup(true))
		testOpts = getDefaultOptions()
		testOpts[optionWithLookup] = true
		assert.True(reflect.DeepEqual(opts, testOpts))

	})
	t.Run("WithMetadata", func(t *testing.T) {
		// default of no metadata
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts[optionWithMetadata] = oplog.Metadata{}
		assert.True(reflect.DeepEqual(opts, testOpts))

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
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
	t.Run("WithWrapper", func(t *testing.T) {
		// default of no wrapper
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts[optionWithWrapper] = nil
		assert.True(reflect.DeepEqual(opts, testOpts))

		// try setting wrapper
		wrapper := InitTestWrapper(t)
		opts = GetOpts(WithWrapper(wrapper))
		testOpts = getDefaultOptions()
		testOpts[optionWithWrapper] = wrapper
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
	t.Run("WithDebug", func(t *testing.T) {
		// test default of false
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts[optionWithDebug] = false
		assert.True(reflect.DeepEqual(opts, testOpts))

		// try setting to true
		opts = GetOpts(WithDebug(true))
		testOpts = getDefaultOptions()
		testOpts[optionWithDebug] = true
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
}
