package iam

import (
	"reflect"
	"testing"

	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	t.Run("WithName", func(t *testing.T) {
		opts := getOpts(WithName("test"))
		testOpts := getDefaultOptions()
		testOpts.withName = "test"
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
	t.Run("withScope", func(t *testing.T) {
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)

		opts := getOpts(withScope(s))
		testOpts := getDefaultOptions()
		testOpts.withScope = s
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
	t.Run("WithDescription", func(t *testing.T) {
		opts := getOpts(WithDescription("test desc"))
		testOpts := getDefaultOptions()
		testOpts.withDescription = "test desc"
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
	t.Run("WithOperation", func(t *testing.T) {
		opts := getOpts(WithOperation(oplog.OpType_OP_TYPE_CREATE))
		testOpts := getDefaultOptions()
		testOpts.withOperation = oplog.OpType_OP_TYPE_CREATE
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
	t.Run("WithCreateNbf", func(t *testing.T) {
		nbfSecs := 10
		opts := getOpts(WithCreateNbf(nbfSecs))
		testOpts := getDefaultOptions()
		testOpts.withCreateNbf = &nbfSecs
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
}
