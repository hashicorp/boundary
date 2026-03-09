// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		opts := getOpts(WithDetails("name", "alice"))
		testOpts := getDefaultOptions()
		testOpts.withDetails = map[string]any{
			"name": "alice",
		}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithHeader", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithHeader("name", "alice"))
		testOpts := getDefaultOptions()
		testOpts.withHeader = map[string]any{
			"name": "alice",
		}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithFlush", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithFlush())
		testOpts := getDefaultOptions()
		testOpts.withFlush = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithInfo", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithInfo("name", "alice"))
		testOpts := getDefaultOptions()
		testOpts.withInfo = map[string]any{"name": "alice"}
		assert.Equal(opts, testOpts)

		opts = getOpts(WithInfoMsg("test"), WithInfo("name", "alice"))
		testOpts.withInfo = map[string]any{"name": "alice"}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithInfoMsg", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithInfoMsg("test", "name", "alice"))
		testOpts := getDefaultOptions()
		testOpts.withInfo = map[string]any{msgField: "test", "name": "alice"}
		assert.Equal(opts, testOpts)

		opts = getOpts(WithInfo("name", "alice"), WithInfoMsg("test", "name", "eve"))
		testOpts.withInfo = map[string]any{
			"msg":  "test",
			"name": "eve",
		}
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
	t.Run("WithAllow", func(t *testing.T) {
		assert := assert.New(t)
		allow := []string{"foo == bar", "bar == foo"}
		opts := getOpts(WithAllow(allow...))
		testOpts := getDefaultOptions()
		testOpts.withAllow = allow
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDeny", func(t *testing.T) {
		assert := assert.New(t)
		deny := []string{"foo == bar", "bar == foo"}
		opts := getOpts(WithDeny(deny...))
		testOpts := getDefaultOptions()
		testOpts.withDeny = deny
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSchema", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		schema, err := url.Parse("https://alice.com")
		require.NoError(err)
		opts := getOpts(WithSchema(schema))
		testOpts := getDefaultOptions()
		testOpts.withSchema = schema
		assert.Equal(opts, testOpts)
	})
	t.Run("WithAuditWrapper", func(t *testing.T) {
		assert := assert.New(t)
		w := testWrapper(t)
		opts := getOpts(WithAuditWrapper(w))
		testOpts := getDefaultOptions()
		testOpts.withAuditWrapper = w
		assert.Equal(opts, testOpts)
	})
	t.Run("WithFilterOperations", func(t *testing.T) {
		assert := assert.New(t)
		overrides := DefaultAuditFilterOperations()
		opts := getOpts(WithFilterOperations(overrides))
		testOpts := getDefaultOptions()
		testOpts.withFilterOperations = overrides
		assert.Equal(opts, testOpts)
	})
	t.Run("WithHclogLevel", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithHclogLevel(hclog.Info))
		testOpts := getDefaultOptions()
		testOpts.withHclogLevel = hclog.Info
		assert.Equal(opts, testOpts)
	})
	t.Run("withEventGating", func(t *testing.T) {
		assert := assert.New(t)
		testOpts := getDefaultOptions()
		assert.False(testOpts.withGating)
		opts := getOpts(WithGating(true))
		assert.True(opts.withGating)
	})
	t.Run("withNoGateLocking", func(t *testing.T) {
		assert := assert.New(t)
		testOpts := getDefaultOptions()
		assert.False(testOpts.withNoGateLocking)
		opts := getOpts(WithNoGateLocking(true))
		assert.True(opts.withNoGateLocking)
	})
	t.Run("WithTelemetry", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithTelemetry())
		testOpts := getDefaultOptions()
		testOpts.withTelemetry = true
		assert.Equal(opts, testOpts)
	})
	t.Run("withCorrelationId", func(t *testing.T) {
		assert := assert.New(t)
		testOpts := getDefaultOptions()
		assert.Empty(testOpts.withCorrelationId)
		opts := getOpts(withCorrelationId("12345"))
		assert.Equal("12345", opts.withCorrelationId)
	})
}

// testWrapper initializes an AEAD wrapping.Wrapper for testing.  Note: this
// code was cut/pasted from internal/db to eliminate a circular dependency with
// the internal/errors pkg
func testWrapper(t *testing.T) wrapping.Wrapper {
	rootKey := make([]byte, 32)
	n, err := rand.Read(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Fatal(n)
	}
	root := aead.NewWrapper()
	_, err = root.SetConfig(
		context.Background(),
		wrapping.WithKeyId(base64.StdEncoding.EncodeToString(rootKey)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.SetAesGcmKeyBytes(rootKey); err != nil {
		t.Fatal(err)
	}
	return root
}
