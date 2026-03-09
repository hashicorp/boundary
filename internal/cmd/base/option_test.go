// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"testing"

	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("nil-options", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(nil, nil)
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
		opts := GetOpts(WithEventFlags(&f))
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
		opts := GetOpts(WithEventerConfig(&c))
		testOpts := getDefaultOptions()
		testOpts.withEventerConfig = &c
		assert.Equal(opts, testOpts)
	})
	t.Run("WithNoTokenScope", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithNoTokenScope())
		testOpts := getDefaultOptions()
		testOpts.withNoTokenScope = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSkipDatabaseDestruction", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithSkipDatabaseDestruction())
		testOpts := getDefaultOptions()
		testOpts.withSkipDatabaseDestruction = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithNoTokenValue", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithNoTokenValue())
		testOpts := getDefaultOptions()
		testOpts.withNoTokenValue = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSkipDefaultRoleCreation", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithSkipDefaultRoleCreation())
		testOpts := getDefaultOptions()
		testOpts.withSkipDefaultRoleCreation = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSkipAuthMethodCreation", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithSkipAuthMethodCreation())
		testOpts := getDefaultOptions()
		testOpts.withSkipAuthMethodCreation = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSkipOidcAuthMethodCreation", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithSkipOidcAuthMethodCreation())
		testOpts := getDefaultOptions()
		testOpts.withSkipOidcAuthMethodCreation = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSkipLdapAuthMethodCreation", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithSkipLdapAuthMethodCreation())
		testOpts := getDefaultOptions()
		testOpts.withSkipLdapAuthMethodCreation = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSkipScopesCreation", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithSkipScopesCreation())
		testOpts := getDefaultOptions()
		testOpts.withSkipScopesCreation = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSkipHostResourcesCreation", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithSkipHostResourcesCreation())
		testOpts := getDefaultOptions()
		testOpts.withSkipHostResourcesCreation = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSkipTargetCreation", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithSkipTargetCreation())
		testOpts := getDefaultOptions()
		testOpts.withSkipTargetCreation = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithContainerImage", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithContainerImage("test-container"))
		testOpts := getDefaultOptions()
		testOpts.withContainerImage = "test-container"
		assert.Equal(opts, testOpts)
	})
	t.Run("withDialect", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(withDialect("test-dialect"))
		testOpts := getDefaultOptions()
		testOpts.withDialect = "test-dialect"
		assert.Equal(opts, testOpts)
	})
	t.Run("withEventGating", func(t *testing.T) {
		assert := assert.New(t)
		testOpts := getDefaultOptions()
		assert.False(testOpts.withEventGating)
		opts := GetOpts(WithEventGating(true))
		assert.True(opts.withEventGating)
	})

	t.Run("WithSkipScopeIdFlag", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithSkipScopeIdFlag(true))
		testOpts := getDefaultOptions()
		testOpts.WithSkipScopeIdFlag = true
		assert.Equal(opts, testOpts)
	})

	t.Run("WithSkipScopeIdFlag", func(t *testing.T) {
		assert := assert.New(t)
		var s string
		opts := GetOpts(WithInterceptedToken(&s))
		testOpts := getDefaultOptions()
		testOpts.WithInterceptedToken = &s
		assert.Equal(opts, testOpts)
	})

	t.Run("WithAuthUserTargetAuthorizeSessionGrant", func(t *testing.T) {
		assert := assert.New(t)
		opts := getDefaultOptions()
		assert.False(opts.withAuthUserTargetAuthorizeSessionGrant)
		opts = GetOpts(WithAuthUserTargetAuthorizeSessionGrant(true))
		assert.True(opts.withAuthUserTargetAuthorizeSessionGrant)
	})

	t.Run("WithIamOptions", func(t *testing.T) {
		assert := assert.New(t)
		testOpts := getDefaultOptions()
		assert.Len(testOpts.withIamOptions, 0)
		opts := GetOpts(WithIamOptions(iam.WithSkipAdminRoleCreation(true)))
		assert.Len(opts.withIamOptions, 1)
	})
}
