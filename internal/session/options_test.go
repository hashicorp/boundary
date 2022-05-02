package session

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
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
		opts := getOpts(WithScopeIds([]string{"o_1234"}))
		testOpts := getDefaultOptions()
		testOpts.withScopeIds = []string{"o_1234"}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithOrderByCreateTime", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithOrderByCreateTime(db.AscendingOrderBy))
		testOpts := getDefaultOptions()
		testOpts.withOrderByCreateTime = db.AscendingOrderBy
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
		assert := assert.New(t)
		now := timestamppb.Now()
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
	t.Run("WithSessionIds", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithSessionIds("s_1", "s_2", "s_3"))
		testOpts := getDefaultOptions()
		testOpts.withSessionIds = []string{"s_1", "s_2", "s_3"}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithWorkerId", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithWorkerId("worker1"))
		testOpts := getDefaultOptions()
		testOpts.withWorkerId = "worker1"
		assert.Equal(opts, testOpts)
	})
}
