// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithPublicId", func(t *testing.T) {
		opts := getOpts(WithPublicId("test"))
		testOpts := getDefaultOptions()
		testOpts.withPublicId = "test"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithName", func(t *testing.T) {
		opts := getOpts(WithName("test"))
		testOpts := getDefaultOptions()
		testOpts.withName = "test"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithSyncIntervalSeconds", func(t *testing.T) {
		opts := getOpts(WithSyncIntervalSeconds(5))
		testOpts := getDefaultOptions()
		testOpts.withSyncIntervalSeconds = 5
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithPluginId", func(t *testing.T) {
		opts := getOpts(withPluginId("test"))
		testOpts := getDefaultOptions()
		testOpts.withPluginId = "test"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithDescription", func(t *testing.T) {
		opts := getOpts(WithDescription("test desc"))
		testOpts := getDefaultOptions()
		testOpts.withDescription = "test desc"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithLimit", func(t *testing.T) {
		opts := getOpts(WithLimit(5))
		testOpts := getDefaultOptions()
		testOpts.withLimit = 5
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithPreferredEndpoints", func(t *testing.T) {
		opts := getOpts(WithPreferredEndpoints([]string{"foo"}))
		testOpts := getDefaultOptions()
		testOpts.withPreferredEndpoints = []string{"foo"}
		assert.EqualValues(t, opts, testOpts)
	})
	t.Run("withDnsNames", func(t *testing.T) {
		opts := getOpts(withDnsNames([]string{"foo"}))
		testOpts := getDefaultOptions()
		testOpts.withDnsNames = []string{"foo"}
		assert.EqualValues(t, opts, testOpts)
	})
	t.Run("withIpAddresses", func(t *testing.T) {
		opts := getOpts(withIpAddresses([]string{"foo"}))
		testOpts := getDefaultOptions()
		testOpts.withIpAddresses = []string{"foo"}
		assert.EqualValues(t, opts, testOpts)
	})
	t.Run("withSetIds", func(t *testing.T) {
		opts := getOpts(WithSetIds([]string{"foo"}))
		testOpts := getDefaultOptions()
		testOpts.withSetIds = []string{"foo"}
		assert.EqualValues(t, opts, testOpts)
	})
	t.Run("WithSecretsHmac", func(t *testing.T) {
		opts := getOpts(WithSecretsHmac([]byte("secrets-hmac")))
		testOpts := getDefaultOptions()
		testOpts.withSecretsHmac = []byte("secrets-hmac")
		assert.Equal(t, opts, testOpts)
	})
}
