package db

import (
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-hclog"
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
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.newOplogMsg = nil
		assert.Equal(opts, testOpts)

		msg := oplog.Message{}
		opts = GetOpts(NewOplogMsg(&msg))
		testOpts = getDefaultOptions()
		testOpts.newOplogMsg = &msg
		assert.Equal(opts, testOpts)
	})
	t.Run("NewOplogMsgs", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.newOplogMsgs = nil
		assert.Equal(opts, testOpts)

		msgs := []*oplog.Message{}
		opts = GetOpts(NewOplogMsgs(&msgs))
		testOpts = getDefaultOptions()
		testOpts.newOplogMsgs = &msgs
		assert.Equal(opts, testOpts)
	})
	t.Run("WithVersion", func(t *testing.T) {
		assert := assert.New(t)
		// test default of 0
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.WithVersion = nil
		assert.Equal(opts, testOpts)
		versionTwo := uint32(2)
		opts = GetOpts(WithVersion(&versionTwo))
		testOpts = getDefaultOptions()
		testOpts.WithVersion = &versionTwo
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSkipVetForWrite", func(t *testing.T) {
		assert := assert.New(t)
		// test default of false
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.withSkipVetForWrite = false
		assert.Equal(opts, testOpts)
		opts = GetOpts(WithSkipVetForWrite(true))
		testOpts = getDefaultOptions()
		testOpts.withSkipVetForWrite = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithWhere", func(t *testing.T) {
		assert := assert.New(t)
		// test default of false
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.withWhereClause = ""
		testOpts.withWhereClauseArgs = nil
		assert.Equal(opts, testOpts)
		opts = GetOpts(WithWhere("id = ? and foo = ?", 1234, "bar"))
		testOpts.withWhereClause = "id = ? and foo = ?"
		testOpts.withWhereClauseArgs = []interface{}{1234, "bar"}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithOrder", func(t *testing.T) {
		assert := assert.New(t)
		// test default of false
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.withOrder = ""
		assert.Equal(opts, testOpts)
		opts = GetOpts(WithOrder("version desc"))
		testOpts.withOrder = "version desc"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithGormFormatter", func(t *testing.T) {
		assert := assert.New(t)
		// test default of false
		opts := GetOpts()
		testOpts := getDefaultOptions()
		assert.Equal(opts, testOpts)

		testLogger := hclog.New(&hclog.LoggerOptions{})
		opts = GetOpts(WithGormFormatter(testLogger))
		testOpts.withGormFormatter = testLogger
		assert.Equal(opts, testOpts)
	})
	t.Run("WithMaxOpenConnections", func(t *testing.T) {
		assert := assert.New(t)
		// test default of false
		opts := GetOpts()
		testOpts := getDefaultOptions()
		assert.Equal(opts, testOpts)
		opts = GetOpts(WithMaxOpenConnections(22))
		testOpts.withMaxOpenConnections = 22
		assert.Equal(opts, testOpts)
	})
	t.Run("WithMaxIdleConnections", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts()
		testOpts := getDefaultOptions()
		assert.Equal(opts, testOpts)
		ic := 22
		opts = GetOpts(WithMaxIdleConnections(&ic))
		testOpts.withMaxIdleConnections = &ic
		assert.Equal(opts, testOpts)
	})
	t.Run("WithConnMaxIdleTimeDuration", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts()
		testOpts := getDefaultOptions()
		assert.Equal(opts, testOpts)
		d := time.Minute * 5
		opts = GetOpts(WithConnMaxIdleTimeDuration(&d))
		testOpts.withConnMaxIdleTimeDuration = &d
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDebug", func(t *testing.T) {
		assert := assert.New(t)
		// test default of false
		opts := GetOpts()
		testOpts := getDefaultOptions()
		assert.Equal(opts, testOpts)
		// try setting to true
		opts = GetOpts(WithDebug(true))
		testOpts.withDebug = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithOnConflict", func(t *testing.T) {
		assert := assert.New(t)
		// test default of false
		opts := GetOpts()
		testOpts := getDefaultOptions()
		assert.Equal(opts, testOpts)
		columns := SetColumns([]string{"name", "description"})
		columnValues := SetColumnValues(map[string]interface{}{"expiration": "NULL"})
		testOnConflict := OnConflict{
			Target: Constraint("uniq-name"),
			Action: append(columns, columnValues...),
		}
		opts = GetOpts(WithOnConflict(&testOnConflict))
		testOpts.withOnConflict = &testOnConflict
		assert.Equal(opts, testOpts)
	})
	t.Run("WithReturnRowsAffected", func(t *testing.T) {
		assert := assert.New(t)
		// test default of false
		opts := GetOpts()
		testOpts := getDefaultOptions()
		assert.Equal(opts, testOpts)

		var rowsAffected int64
		opts = GetOpts(WithReturnRowsAffected(&rowsAffected))
		testOpts.withRowsAffected = &rowsAffected
		assert.Equal(opts, testOpts)
	})
}
