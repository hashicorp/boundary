package server

import (
	"context"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithName", func(t *testing.T) {
		opts := getOpts(WithName("test"))
		testOpts := getDefaultOptions()
		testOpts.withName = "test"
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithPublicId", func(t *testing.T) {
		opts := getOpts(WithPublicId("test"))
		testOpts := getDefaultOptions()
		testOpts.withPublicId = "test"
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithDescription", func(t *testing.T) {
		opts := getOpts(WithDescription("test desc"))
		testOpts := getDefaultOptions()
		testOpts.withDescription = "test desc"
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithLimit", func(t *testing.T) {
		opts := getOpts(WithLimit(5))
		testOpts := getDefaultOptions()
		testOpts.withLimit = 5
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithAddress", func(t *testing.T) {
		opts := getOpts(WithAddress("test"))
		testOpts := getDefaultOptions()
		testOpts.withAddress = "test"
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithLiveness", func(t *testing.T) {
		opts := getOpts(WithLiveness(time.Hour))
		testOpts := getDefaultOptions()
		testOpts.withLiveness = time.Hour
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithUpdateTags", func(t *testing.T) {
		opts := getOpts(WithUpdateTags(true))
		testOpts := getDefaultOptions()
		testOpts.withUpdateTags = true
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithWorkerTags", func(t *testing.T) {
		tags := []*Tag{
			{Key: "key1", Value: "val1"},
			{Key: "key2", Value: "val2"},
		}
		opts := getOpts(WithWorkerTags(tags...))
		testOpts := getDefaultOptions()
		testOpts.withWorkerTags = tags
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithWorkerKeys", func(t *testing.T) {
		assert := assert.New(t)
		testOpts := getDefaultOptions()

		keys := WorkerKeys{
			workerEncryptionPubKey: populateBytes(20),
			workerSigningPubKey:    populateBytes(20),
		}

		opts := getOpts(WithWorkerKeys(keys))
		testOpts = getDefaultOptions()
		testOpts.withWorkerKeys = keys
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(opts, testOpts)
	})
	t.Run("WithControllerEncryptionPrivateKey", func(t *testing.T) {
		assert := assert.New(t)
		testOpts := getDefaultOptions()

		key := populateBytes(20)

		opts := getOpts(WithControllerEncryptionPrivateKey(key))
		testOpts = getDefaultOptions()
		testOpts.withControllerEncryptionPrivateKey = key
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(opts, testOpts)
	})
	t.Run("WithKeyId", func(t *testing.T) {
		assert := assert.New(t)
		testOpts := getDefaultOptions()

		opts := getOpts(WithKeyId("hi i'm another key id"))
		testOpts = getDefaultOptions()
		testOpts.withKeyId = "hi i'm another key id"
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(opts, testOpts)
	})
	t.Run("WithNonce", func(t *testing.T) {
		assert := assert.New(t)
		testOpts := getDefaultOptions()

		nonce := populateBytes(20)

		opts := getOpts(WithNonce(nonce))
		testOpts = getDefaultOptions()
		testOpts.withNonce = nonce
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(opts, testOpts)
	})
	t.Run("WithNewIdFunc", func(t *testing.T) {
		assert := assert.New(t)
		testFn := func(context.Context) (string, error) { return "", nil }
		opts := getOpts(WithNewIdFunc(testFn))
		testOpts := getDefaultOptions()
		testOpts.withNewIdFunc = testFn
		assert.Equal(
			runtime.FuncForPC(reflect.ValueOf(opts.withNewIdFunc).Pointer()).Name(),
			runtime.FuncForPC(reflect.ValueOf(testOpts.withNewIdFunc).Pointer()).Name(),
		)
	})
	t.Run("WithTestPkiWorkerAuthorizedKeyId", func(t *testing.T) {
		assert := assert.New(t)
		testOpts := getDefaultOptions()

		var keyId string
		opts := getOpts(WithTestPkiWorkerAuthorizedKeyId(&keyId))
		testOpts = getDefaultOptions()
		testOpts.withTestPkiWorkerAuthorized = true
		testOpts.withTestPkiWorkerKeyId = &keyId
		testOpts.withNewIdFunc = nil
		opts.withNewIdFunc = nil
		assert.Equal(opts, testOpts)
	})
	t.Run("WithWorkerType", func(t *testing.T) {
		opts := getDefaultOptions()
		assert.Empty(t, opts.withWorkerType)
		opts = getOpts(WithWorkerType(KmsWorkerType))
		assert.Equal(t, KmsWorkerType, opts.withWorkerType)
	})
	t.Run("WithRoot", func(t *testing.T) {
		opts := getDefaultOptions()
		assert.Empty(t, opts.withRoot)
		opts = getOpts(WithRoot("a"))
		assert.Equal(t, "a", opts.withRoot)
	})
	t.Run("WithStopAfter", func(t *testing.T) {
		opts := getDefaultOptions()
		assert.Empty(t, opts.withStopAfter)
		opts = getOpts(WithStopAfter(10))
		assert.Equal(t, uint(10), opts.withStopAfter)
	})
}
