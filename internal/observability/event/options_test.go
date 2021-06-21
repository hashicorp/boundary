package event

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithId", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithId("test"))
		testOpts := getDefaultOptions()
		testOpts.withId = "test"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDetails", func(t *testing.T) {
		assert := assert.New(t)
		d := map[string]interface{}{
			"name": "alice",
		}
		opts := getOpts(WithDetails(d))
		testOpts := getDefaultOptions()
		testOpts.withDetails = d
		assert.Equal(opts, testOpts)
	})
	t.Run("WithHeader", func(t *testing.T) {
		assert := assert.New(t)
		h := map[string]interface{}{
			"name": "alice",
		}
		opts := getOpts(WithHeader(h))
		testOpts := getDefaultOptions()
		testOpts.withHeader = h
		assert.Equal(opts, testOpts)
	})
	t.Run("WithFlush", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithFlush())
		testOpts := getDefaultOptions()
		testOpts.withFlush = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithRequestInfo", func(t *testing.T) {
		assert := assert.New(t)
		info := TestRequestInfo(t)
		opts := getOpts(WithRequestInfo(info))
		testOpts := getDefaultOptions()
		testOpts.withRequestInfo = info
		assert.Equal(opts, testOpts)
	})
	t.Run("WithNow", func(t *testing.T) {
		assert := assert.New(t)
		now := time.Now()
		opts := getOpts(WithNow(now))
		testOpts := getDefaultOptions()
		testOpts.withNow = now
		assert.Equal(opts, testOpts)
	})
	t.Run("WithRequest", func(t *testing.T) {
		assert := assert.New(t)
		r := testRequest(t)
		opts := getOpts(WithRequest(r))
		testOpts := getDefaultOptions()
		testOpts.withRequest = r
		assert.Equal(opts, testOpts)
	})
	t.Run("WithResponse", func(t *testing.T) {
		assert := assert.New(t)
		r := testResponse(t)
		opts := getOpts(WithResponse(r))
		testOpts := getDefaultOptions()
		testOpts.withResponse = r
		assert.Equal(opts, testOpts)
	})
	t.Run("WithAuth", func(t *testing.T) {
		assert := assert.New(t)
		auth := testAuth(t)
		opts := getOpts(WithAuth(auth))
		testOpts := getDefaultOptions()
		testOpts.withAuth = auth
		assert.Equal(opts, testOpts)
	})
	t.Run("WithEventer", func(t *testing.T) {
		assert := assert.New(t)
		eventer := Eventer{}
		opts := getOpts(WithEventer(&eventer))
		testOpts := getDefaultOptions()
		testOpts.withEventer = &eventer
		assert.Equal(opts, testOpts)
	})
	t.Run("WithEventerConfig", func(t *testing.T) {
		assert := assert.New(t)
		c := EventerConfig{}
		opts := getOpts(WithEventerConfig(&c))
		testOpts := getDefaultOptions()
		testOpts.withEventerConfig = &c
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSerializationLock", func(t *testing.T) {
		assert := assert.New(t)
		l := new(sync.Mutex)
		opts := getOpts(WithSerializationLock(l))
		testOpts := getDefaultOptions()
		testOpts.withSerializationLock = l
		assert.Equal(opts, testOpts)
	})
}
