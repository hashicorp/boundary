package node

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_getOpts provides unit tests for getOpts and all the options
func Test_getOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithWrapper", func(t *testing.T) {
		assert := assert.New(t)
		w := TestWrapper(t)
		opts := getOpts(WithWrapper(w))
		testOpts := getDefaultOptions()
		testOpts.withWrapper = w
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSalt", func(t *testing.T) {
		assert := assert.New(t)
		salt := []byte("salty")
		opts := getOpts(WithSalt(salt))
		testOpts := getDefaultOptions()
		testOpts.withSalt = salt
		assert.Equal(opts, testOpts)
	})
	t.Run("WithInfo", func(t *testing.T) {
		assert := assert.New(t)
		info := []byte("info")
		opts := getOpts(WithInfo(info))
		testOpts := getDefaultOptions()
		testOpts.withInfo = info
		assert.Equal(opts, testOpts)
	})
	t.Run("withFilterOperations", func(t *testing.T) {
		assert := assert.New(t)
		filters := map[DataClassification]FilterOperation{
			UnknownClassification: RedactOperation,
			PublicClassification:  NoOperation,
			SecretClassification:  EncryptOperation,
		}
		opts := getOpts(withFilterOperations(filters))
		testOpts := getDefaultOptions()
		testOpts.withFilterOperations = filters
		assert.Equal(opts, testOpts)
	})
	t.Run("withPointer", func(t *testing.T) {
		assert := assert.New(t)
		m := TestTaggedMap{
			"foo": "bar",
		}
		opts := getOpts(withPointer(m, "/foo"))
		testOpts := getDefaultOptions()
		testOpts.withPointerstructureInfo = &pointerstructureInfo{
			i:       m,
			pointer: "/foo",
		}
		assert.Equal(opts, testOpts)
	})
}
