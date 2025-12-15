// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package billing

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()

	oneMonthAgo := time.Now().AddDate(0, -1, 0)

	t.Run("WithStartTime", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithStartTime(&oneMonthAgo))
		testOpts := getDefaultOptions()
		testOpts.withStartTime = &oneMonthAgo
		assert.Equal(opts, testOpts)
	})

	t.Run("WithEndTime", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithEndTime(&oneMonthAgo))
		testOpts := getDefaultOptions()
		testOpts.withEndTime = &oneMonthAgo
		assert.Equal(opts, testOpts)
	})
}
