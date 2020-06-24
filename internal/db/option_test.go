package db

import (
	"testing"

	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/stretchr/testify/assert"
)

// Test_getOpts provides unit tests for GetOpts and all the options
func Test_getOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithOplog", func(t *testing.T) {
		assert := assert.New(t)
		// test default of false
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.withOplog = false
		assert.Equal(opts, testOpts)

		wrapper := TestWrapper(t)
		md := oplog.Metadata{
			"key-only":   nil,
			"deployment": []string{"amex"},
			"project":    []string{"central-info-systems", "local-info-systems"},
		}
		// try setting to true
		opts = GetOpts(WithOplog(wrapper, md))
		testOpts = getDefaultOptions()
		testOpts.withOplog = true
		testOpts.oplogOpts = oplogOpts{
			wrapper:  wrapper,
			metadata: md,
		}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithLookup", func(t *testing.T) {
		assert := assert.New(t)
		// test default of true
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.withLookup = false
		assert.Equal(opts, testOpts)

		// try setting to false
		opts = GetOpts(WithLookup(true))
		testOpts = getDefaultOptions()
		testOpts.withLookup = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithFieldMaskPaths", func(t *testing.T) {
		assert := assert.New(t)
		// test default of []string{}
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.WithFieldMaskPaths = []string{}
		assert.Equal(opts, testOpts)

		testPaths := []string{"alice", "bob"}
		opts = GetOpts(WithFieldMaskPaths(testPaths))
		testOpts = getDefaultOptions()
		testOpts.WithFieldMaskPaths = testPaths
		assert.Equal(opts, testOpts)
	})
	t.Run("WithNullPaths", func(t *testing.T) {
		assert := assert.New(t)
		// test default of []string{}
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.WithNullPaths = []string{}
		assert.Equal(opts, testOpts)

		testPaths := []string{"alice", "bob"}
		opts = GetOpts(WithNullPaths(testPaths))
		testOpts = getDefaultOptions()
		testOpts.WithNullPaths = testPaths
		assert.Equal(opts, testOpts)
	})
	t.Run("WithLimit", func(t *testing.T) {
		assert := assert.New(t)
		// test default of 0
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.WithLimit = 0
		assert.Equal(opts, testOpts)

		opts = GetOpts(WithLimit(-1))
		testOpts = getDefaultOptions()
		testOpts.WithLimit = -1
		assert.Equal(opts, testOpts)

		opts = GetOpts(WithLimit(1))
		testOpts = getDefaultOptions()
		testOpts.WithLimit = 1
		assert.Equal(opts, testOpts)
	})
	t.Run("NewOplogMsg", func(t *testing.T) {
		assert := assert.New(t)
		// test default of false
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.newOplogMsg = nil
		assert.Equal(opts, testOpts)

		msg := oplog.Message{}
		// try setting to true
		opts = GetOpts(NewOplogMsg(&msg))
		testOpts = getDefaultOptions()
		testOpts.newOplogMsg = &msg
		assert.Equal(opts, testOpts)
	})
	t.Run("WithVersion", func(t *testing.T) {
		assert := assert.New(t)
		// test default of 0
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.WithVersion = 0
		assert.Equal(opts, testOpts)
		opts = GetOpts(WithVersion(2))
		testOpts = getDefaultOptions()
		testOpts.WithVersion = 2
		assert.Equal(opts, testOpts)
	})
}
