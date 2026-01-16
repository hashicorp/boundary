// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"io"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/version"
	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithName", func(t *testing.T) {
		opts := GetOpts(WithName("test"))
		testOpts := getDefaultOptions()
		testOpts.withName = "test"
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithPublicId", func(t *testing.T) {
		opts := GetOpts(WithPublicId("test"))
		testOpts := getDefaultOptions()
		testOpts.withPublicId = "test"
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithDescription", func(t *testing.T) {
		opts := GetOpts(WithDescription("test desc"))
		testOpts := getDefaultOptions()
		testOpts.withDescription = "test desc"
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithLimit", func(t *testing.T) {
		opts := GetOpts(WithLimit(5))
		testOpts := getDefaultOptions()
		testOpts.withLimit = 5
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithAddress", func(t *testing.T) {
		opts := GetOpts(WithAddress("test"))
		testOpts := getDefaultOptions()
		testOpts.withAddress = "test"
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithLiveness", func(t *testing.T) {
		opts := GetOpts(WithLiveness(time.Hour))
		testOpts := getDefaultOptions()
		testOpts.withLiveness = time.Hour
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithUpdateTags", func(t *testing.T) {
		opts := GetOpts(WithUpdateTags(true))
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
			nil,
		}
		opts := GetOpts(WithWorkerTags(tags...))
		testOpts := getDefaultOptions()
		testOpts.withWorkerTags = tags[:2]
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

		opts := GetOpts(WithWorkerKeys(keys))
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

		opts := GetOpts(WithControllerEncryptionPrivateKey(key))
		testOpts = getDefaultOptions()
		testOpts.withControllerEncryptionPrivateKey = key
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(opts, testOpts)
	})
	t.Run("WithKeyId", func(t *testing.T) {
		assert := assert.New(t)
		testOpts := getDefaultOptions()

		opts := GetOpts(WithKeyId("hi i'm another key id"))
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

		opts := GetOpts(WithNonce(nonce))
		testOpts = getDefaultOptions()
		testOpts.withNonce = nonce
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(opts, testOpts)
	})
	t.Run("WithNewIdFunc", func(t *testing.T) {
		assert := assert.New(t)
		testFn := func(context.Context) (string, error) { return "", nil }
		opts := GetOpts(WithNewIdFunc(testFn))
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
		opts := GetOpts(WithTestPkiWorkerAuthorizedKeyId(&keyId))
		testOpts = getDefaultOptions()
		testOpts.withTestPkiWorkerAuthorized = true
		testOpts.withTestPkiWorkerKeyId = &keyId
		testOpts.withNewIdFunc = nil
		opts.withNewIdFunc = nil
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTestUseInputTagsAsApiTags", func(t *testing.T) {
		assert := assert.New(t)
		testOpts := getDefaultOptions()
		assert.False(testOpts.withTestUseInputTagsAsApiTags)
		opts := GetOpts(WithTestUseInputTagsAsApiTags(true))
		assert.True(opts.withTestUseInputTagsAsApiTags)
	})
	t.Run("WithWorkerType", func(t *testing.T) {
		opts := getDefaultOptions()
		assert.Empty(t, opts.withWorkerType)
		opts = GetOpts(WithWorkerType(KmsWorkerType))
		assert.Equal(t, KmsWorkerType, opts.withWorkerType)
	})
	t.Run("WithRoot", func(t *testing.T) {
		opts := getDefaultOptions()
		assert.Empty(t, opts.withRoot)
		opts = GetOpts(WithRoot(RootInfo{
			RootId:  "a",
			RootVer: "0.1.0",
		}))
		assert.Equal(t, RootInfo{
			RootId:  "a",
			RootVer: "0.1.0",
		}, opts.withRoot)
	})
	t.Run("WithStopAfter", func(t *testing.T) {
		opts := getDefaultOptions()
		assert.Empty(t, opts.withStopAfter)
		opts = GetOpts(WithStopAfter(10))
		assert.Equal(t, uint(10), opts.withStopAfter)
	})
	t.Run("WithCreateControllerLedActivationToken", func(t *testing.T) {
		opts := getDefaultOptions()
		assert.False(t, opts.WithCreateControllerLedActivationToken)
		opts = GetOpts(WithCreateControllerLedActivationToken(true))
		assert.True(t, opts.WithCreateControllerLedActivationToken)
	})
	t.Run("WithReleaseVersion", func(t *testing.T) {
		opts := getDefaultOptions()
		assert.Empty(t, opts.withReleaseVersion)
		opts = GetOpts(WithReleaseVersion("version"))
		assert.Equal(t, "version", opts.withReleaseVersion)
	})
	t.Run("WithOperationalState", func(t *testing.T) {
		opts := GetOpts(WithOperationalState("test state"))
		testOpts := getDefaultOptions()
		testOpts.withOperationalState = "test state"
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithExcludeShutdown", func(t *testing.T) {
		opts := getDefaultOptions()
		assert.Empty(t, opts.withActiveWorkers)
		opts = GetOpts(WithActiveWorkers(true))
		assert.Equal(t, true, opts.withActiveWorkers)
	})
	t.Run("WithFeature", func(t *testing.T) {
		opts := GetOpts(WithFeature(version.MultiHopSessionFeature))
		testOpts := getDefaultOptions()
		testOpts.withFeature = version.MultiHopSessionFeature
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithDirectlyConnected", func(t *testing.T) {
		opts := GetOpts(WithDirectlyConnected(true))
		testOpts := getDefaultOptions()
		testOpts.withDirectlyConnected = true
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithWorkerPool", func(t *testing.T) {
		opts := GetOpts(WithWorkerPool([]string{"1", "2", "3"}))
		testOpts := getDefaultOptions()
		testOpts.withWorkerPool = []string{"1", "2", "3"}
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithLocalStorageState", func(t *testing.T) {
		opts := GetOpts(WithLocalStorageState(AvailableLocalStorageState.String()))
		testOpts := getDefaultOptions()
		testOpts.withLocalStorageState = AvailableLocalStorageState.String()
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithReaderWriter", func(t *testing.T) {
		reader := &db.Db{}
		writer := &db.Db{}
		testOpts := getDefaultOptions()
		assert.Nil(t, testOpts.WithReader)
		assert.Nil(t, testOpts.WithWriter)
		testOpts.WithReader = reader
		testOpts.WithWriter = writer
		opts := GetOpts(WithReaderWriter(reader, writer))
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, reader, opts.WithReader)
		assert.Equal(t, writer, opts.WithWriter)
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithRandomReader", func(t *testing.T) {
		reader := io.Reader(&strings.Reader{})
		opts := GetOpts(WithRandomReader(reader))
		testOpts := getDefaultOptions()
		testOpts.withRandomReader = reader
		opts.withNewIdFunc = nil
		testOpts.withNewIdFunc = nil
		assert.Equal(t, opts, testOpts)
	})
}
