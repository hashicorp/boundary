// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package schema

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()

	t.Run("WithEditions", func(t *testing.T) {
		assert := assert.New(t)
		editions := TestCreatePartialEditions(Postgres, PartialEditions{"oss": 1})
		opts := getOpts(WithEditions(editions))
		assert.Equal(opts.withEditions, editions)
	})
	t.Run("WithDeleteLog", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithDeleteLog(true))
		testOpts := getDefaultOptions()
		testOpts.withDeleteLog = true
		assert.Equal(opts, testOpts)
	})
}
