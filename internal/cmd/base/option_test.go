// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package base

import (
	"testing"

	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("nil-options", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(nil, nil)
		testOpts := getDefaultOptions()
		assert.Equal(opts, testOpts)
	})
	t.Run("WithEventFlags", func(t *testing.T) {
		assert := assert.New(t)
		isTrue := true
		f := EventFlags{
			Format:              event.JSONSinkFormat,
			AuditEnabled:        &isTrue,
			ObservationsEnabled: &isTrue,
			SysEventsEnabled:    &isTrue,
		}
		opts := getOpts(WithEventFlags(&f))
		testOpts := getDefaultOptions()
		testOpts.withEventFlags = &f
		assert.Equal(opts, testOpts)
	})
	t.Run("WithEventerConfig", func(t *testing.T) {
		assert := assert.New(t)
		c := event.EventerConfig{
			Sinks: []*event.SinkConfig{
				// not a valid sink, but it doesn't need to be to test the
				// option is properly supported.
				{
					Name: "test-sink",
					Type: "Stderr",
				},
			},
		}
		opts := getOpts(WithEventerConfig(&c))
		testOpts := getDefaultOptions()
		testOpts.withEventerConfig = &c
		assert.Equal(opts, testOpts)
	})
	t.Run("WithNoTokenScope", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithNoTokenScope())
		testOpts := getDefaultOptions()
		testOpts.withNoTokenScope = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSkipDatabaseDestruction", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithSkipDatabaseDestruction())
		testOpts := getDefaultOptions()
		testOpts.withSkipDatabaseDestruction = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithNoTokenValue", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithNoTokenValue())
		testOpts := getDefaultOptions()
		testOpts.withNoTokenValue = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSkipAuthMethodCreation", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithSkipAuthMethodCreation())
		testOpts := getDefaultOptions()
		testOpts.withSkipAuthMethodCreation = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSkipOidcAuthMethodCreation", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithSkipOidcAuthMethodCreation())
		testOpts := getDefaultOptions()
		testOpts.withSkipOidcAuthMethodCreation = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSkipLdapAuthMethodCreation", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithSkipLdapAuthMethodCreation())
		testOpts := getDefaultOptions()
		testOpts.withSkipLdapAuthMethodCreation = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSkipScopesCreation", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithSkipScopesCreation())
		testOpts := getDefaultOptions()
		testOpts.withSkipScopesCreation = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSkipHostResourcesCreation", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithSkipHostResourcesCreation())
		testOpts := getDefaultOptions()
		testOpts.withSkipHostResourcesCreation = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSkipTargetCreation", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithSkipTargetCreation())
		testOpts := getDefaultOptions()
		testOpts.withSkipTargetCreation = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithContainerImage", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithContainerImage("test-container"))
		testOpts := getDefaultOptions()
		testOpts.withContainerImage = "test-container"
		assert.Equal(opts, testOpts)
	})
	t.Run("withDialect", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(withDialect("test-dialect"))
		testOpts := getDefaultOptions()
		testOpts.withDialect = "test-dialect"
		assert.Equal(opts, testOpts)
	})
	t.Run("withEventGating", func(t *testing.T) {
		assert := assert.New(t)
		testOpts := getDefaultOptions()
		assert.False(testOpts.withEventGating)
		opts := getOpts(WithEventGating(true))
		assert.True(opts.withEventGating)
	})
}
