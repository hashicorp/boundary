package session

import (
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
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
	t.Run("WithScopeId", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithScopeId("o_1234"))
		testOpts := getDefaultOptions()
		testOpts.withScopeId = "o_1234"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithOrder", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithOrder("create_time asc"))
		testOpts := getDefaultOptions()
		testOpts.withOrder = "create_time asc"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithUserId", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithUserId("u_1234"))
		testOpts := getDefaultOptions()
		testOpts.withUserId = "u_1234"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithExpirationTime", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		now, err := ptypes.TimestampProto(time.Now())
		require.NoError(err)
		opts := getOpts(WithExpirationTime(&timestamp.Timestamp{Timestamp: now}))
		testOpts := getDefaultOptions()
		testOpts.withExpirationTime = &timestamp.Timestamp{Timestamp: now}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTestTofu", func(t *testing.T) {
		assert := assert.New(t)
		tofu := TestTofu(t)
		opts := getOpts(WithTestTofu(tofu))
		testOpts := getDefaultOptions()
		testOpts.withTestTofu = make([]byte, len(tofu))
		copy(testOpts.withTestTofu, tofu)
		assert.Equal(opts, testOpts)
	})
}
