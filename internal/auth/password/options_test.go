package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithPublicId", func(t *testing.T) {
		opts := GetOpts(WithPublicId("test id"))
		testOpts := getDefaultOptions()
		testOpts.withPublicId = "test id"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithLoginName", func(t *testing.T) {
		opts := GetOpts(WithLoginName("test"))
		testOpts := getDefaultOptions()
		testOpts.WithLoginName = "test"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithName", func(t *testing.T) {
		opts := GetOpts(WithName("test"))
		testOpts := getDefaultOptions()
		testOpts.withName = "test"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithDescription", func(t *testing.T) {
		opts := GetOpts(WithDescription("test desc"))
		testOpts := getDefaultOptions()
		testOpts.withDescription = "test desc"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithLimit", func(t *testing.T) {
		opts := GetOpts(WithLimit(5))
		testOpts := getDefaultOptions()
		testOpts.withLimit = 5
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithPassword", func(t *testing.T) {
		opts := GetOpts(WithPassword("test password"))
		testOpts := getDefaultOptions()
		testOpts.password = "test password"
		testOpts.withPassword = true
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithConfiguration", func(t *testing.T) {
		conf := NewArgon2Configuration()
		conf.KeyLength = conf.KeyLength * 2
		opts := GetOpts(WithConfiguration(conf))
		testOpts := getDefaultOptions()
		c, ok := testOpts.withConfig.(*Argon2Configuration)
		require.True(t, ok, "need an Argon2Configuration")
		c.KeyLength = c.KeyLength * 2
		testOpts.withConfig = c
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithOrderByCreateTime", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithOrderByCreateTime(true))
		testOpts := getDefaultOptions()
		testOpts.withOrderByCreateTime = true
		testOpts.ascending = true
		assert.Equal(opts, testOpts)
	})
}
