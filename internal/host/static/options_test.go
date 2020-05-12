package static

import (
	"reflect"
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
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
	t.Run("WithDescription", func(t *testing.T) {
		opts := getOpts(WithDescription("test desc"))
		testOpts := getDefaultOptions()
		testOpts.withDescription = "test desc"
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
	t.Run("WithPublicId", func(t *testing.T) {
		opts := getOpts(WithPublicId("1234567890"))
		testOpts := getDefaultOptions()
		testOpts.withPublicId = "1234567890"
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
}
