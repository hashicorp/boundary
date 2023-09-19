// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithName", func(t *testing.T) {
		opts := getOpts(WithName("test"))
		testOpts := getDefaultOptions()
		testOpts.withName = "test"
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
	t.Run("WithPrivateKeyPassphrase", func(t *testing.T) {
		opts := getOpts(WithPrivateKeyPassphrase([]byte("my-pass")))
		testOpts := getDefaultOptions()
		assert.NotEqual(t, opts, testOpts)
		testOpts.withPrivateKeyPassphrase = []byte("my-pass")
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithStartPageAfterItem", func(t *testing.T) {
		assert := assert.New(t)
		updateTime := time.Now()
		opts := getOpts(WithStartPageAfterItem("s_1", updateTime))
		testOpts := getDefaultOptions()
		testOpts.withStartPageAfterItem = &sortItem{
			publicId:   "s_1",
			updateTime: updateTime,
		}
		assert.Equal(opts, testOpts)
	})
}
