// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authtoken

import (
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()

	t.Run("withTokenValue", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(withTokenValue())
		testOpts := getDefaultOptions()
		testOpts.withTokenValue = true
		assert.Equal(opts, testOpts)
	})

	t.Run("WithTokenTimeToLiveDuration", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithTokenTimeToLiveDuration(1 * time.Hour))
		testOpts := getDefaultOptions()
		testOpts.withTokenTimeToLiveDuration = 1 * time.Hour
		assert.Equal(opts, testOpts)
	})

	t.Run("WithTokenTimeToLiveStale", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithTokenTimeToStaleDuration(1 * time.Hour))
		testOpts := getDefaultOptions()
		testOpts.withTokenTimeToStaleDuration = 1 * time.Hour
		assert.Equal(opts, testOpts)
	})

	t.Run("withStatus", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithStatus(IssuedStatus))
		testOpts := getDefaultOptions()
		testOpts.withStatus = IssuedStatus
		assert.Equal(opts, testOpts)
	})

	t.Run("WithPublicId", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithPublicId("test-id"))
		testOpts := getDefaultOptions()
		testOpts.withPublicId = "test-id"
		assert.Equal(opts, testOpts)
	})

	t.Run("WithPasswordOptions", func(t *testing.T) {
		assert := assert.New(t)
		opts := getDefaultOptions()
		assert.Empty(opts.withPasswordOptions)
		opts = getOpts(WithPasswordOptions(password.WithName("foobar")))
		assert.NotEmpty(opts.withPasswordOptions)
	})

	t.Run("WithIamOptions", func(t *testing.T) {
		assert := assert.New(t)
		opts := getDefaultOptions()
		assert.Empty(opts.withIamOptions)
		opts = getOpts(WithIamOptions(iam.WithName("foobar")))
		assert.NotEmpty(opts.withIamOptions)
	})
}
