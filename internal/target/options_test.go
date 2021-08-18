package target

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithName", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithName("test"))
		testOpts := getDefaultOptions()
		testOpts.withName = "test"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDescription", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithDescription("test desc"))
		testOpts := getDefaultOptions()
		testOpts.withDescription = "test desc"
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
	t.Run("WithDefaultPort", func(t *testing.T) {
		assert := assert.New(t)
		// test default of 0
		opts := getOpts()
		testOpts := getDefaultOptions()
		testOpts.withDefaultPort = 0
		assert.Equal(opts, testOpts)

		opts = getOpts(WithDefaultPort(22))
		testOpts = getDefaultOptions()
		testOpts.withDefaultPort = uint32(22)
		assert.Equal(opts, testOpts)
	})
	t.Run("WithUserId", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithUserId("testId"))
		testOpts := getDefaultOptions()
		testOpts.withUserId = "testId"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithScopeId", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithScopeId("testId"))
		testOpts := getDefaultOptions()
		testOpts.withScopeId = "testId"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithScopeName", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithScopeName("testName"))
		testOpts := getDefaultOptions()
		testOpts.withScopeName = "testName"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithPublicId", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithPublicId("testId"))
		testOpts := getDefaultOptions()
		testOpts.withPublicId = "testId"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTargetType", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithTargetType(TcpTargetType))
		testOpts := getDefaultOptions()
		target := TcpTargetType
		testOpts.withTargetType = &target
		assert.Equal(opts, testOpts)
	})
	t.Run("WithHostSources", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithHostSources([]string{"alice", "bob"}))
		testOpts := getDefaultOptions()
		testOpts.withHostSources = []string{"alice", "bob"}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithWorkerFilter", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithWorkerFilter(`"/foo" == "bar"`))
		testOpts := getDefaultOptions()
		testOpts.withWorkerFilter = `"/foo" == "bar"`
		assert.Equal(opts, testOpts)
	})
	t.Run("WithCredentialSources", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithCredentialSources([]string{"alice", "bob"}))
		testOpts := getDefaultOptions()
		testOpts.withCredentialSources = []string{"alice", "bob"}
		assert.Equal(opts, testOpts)
	})
}
