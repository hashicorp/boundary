package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	t.Run("WithName", func(t *testing.T) {
		opts := getOpts(WithName("test"))
		testOpts := getDefaultOptions()
		testOpts.withName = "test"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDescription", func(t *testing.T) {
		opts := getOpts(WithDescription("test desc"))
		testOpts := getDefaultOptions()
		testOpts.withDescription = "test desc"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithPassword", func(t *testing.T) {
		opts := getOpts(WithPassword("test password"))
		testOpts := getDefaultOptions()
		testOpts.password = "test password"
		testOpts.withPassword = true
		assert.Equal(opts, testOpts)
	})
}
