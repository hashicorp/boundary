// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package perms

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("nil", func(t *testing.T) {
		opts := getOpts(nil)
		assert.NotNil(t, opts)
	})
	t.Run("with-user-id", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts()
		assert.Empty(opts.withUserId)
		opts = getOpts(WithUserId("foo"))
		assert.Equal("foo", opts.withUserId)
	})
	t.Run("with-account-id", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts()
		assert.Empty(opts.withAccountId)
		opts = getOpts(WithAccountId("foo"))
		assert.Equal("foo", opts.withAccountId)
	})
	t.Run("with-skip-final-validation", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts()
		assert.False(opts.withSkipFinalValidation)
		opts = getOpts(WithSkipFinalValidation(true))
		assert.True(opts.withSkipFinalValidation)
	})
	t.Run("with-skip-anonymous-user-restrictions", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts()
		assert.False(opts.withSkipAnonymousUserRestrictions)
		opts = getOpts(WithSkipAnonymousUserRestrictions(true))
		assert.True(opts.withSkipAnonymousUserRestrictions)
	})
}
