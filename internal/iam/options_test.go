// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/stretchr/testify/assert"
)

type fakeItem struct {
	pagination.Item
	publicId   string
	updateTime time.Time
}

func (p *fakeItem) GetPublicId() string {
	return p.publicId
}

func (p *fakeItem) GetUpdateTime() *timestamp.Timestamp {
	return timestamp.New(p.updateTime)
}

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithName", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithName("test"))
		testOpts := getDefaultOptions()
		testOpts.withName = "test"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDescription", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithDescription("test desc"))
		testOpts := getDefaultOptions()
		testOpts.withDescription = "test desc"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithLimit", func(t *testing.T) {
		assert := assert.New(t)
		// test default of 0
		opts := getOpts()
		testOpts := getDefaultOptions()
		testOpts.withLimit = 0
		assert.Equal(opts, testOpts)

		opts = getOpts(WithLimit(-1))
		testOpts = getDefaultOptions()
		testOpts.withLimit = -1
		assert.Equal(opts, testOpts)

		opts = getOpts(WithLimit(1))
		testOpts = getDefaultOptions()
		testOpts.withLimit = 1
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDisassociate", func(t *testing.T) {
		assert := assert.New(t)
		// test default of false
		opts := getOpts()
		testOpts := getDefaultOptions()
		testOpts.withDisassociate = false
		assert.Equal(opts, testOpts)

		opts = getOpts(WithDisassociate(true))
		testOpts = getDefaultOptions()
		testOpts.withDisassociate = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithAccountIds", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts()
		testOpts := getDefaultOptions()
		testOpts.withAccountIds = nil
		assert.Equal(opts, testOpts)

		opts = getOpts(WithAccountIds("account-1", "account-2"))
		testOpts.withAccountIds = []string{"account-1", "account-2"}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithPrimaryAuthMethodId", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithPrimaryAuthMethodId("test"))
		testOpts := getDefaultOptions()
		testOpts.withPrimaryAuthMethodId = "test"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithStartPageAfterItem", func(t *testing.T) {
		assert := assert.New(t)
		updateTime := time.Now()
		opts := getOpts(WithStartPageAfterItem(&fakeItem{nil, "s_1", updateTime}))
		assert.Equal(opts.withStartPageAfterItem.GetPublicId(), "s_1")
		assert.Equal(opts.withStartPageAfterItem.GetUpdateTime(), timestamp.New(updateTime))
	})
	t.Run("WithRecursive", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithRecursive(true))
		defaultOpts := getDefaultOptions()
		assert.False(defaultOpts.withRecursive)
		assert.True(opts.withRecursive)
		falseRecurse := getOpts(WithRecursive(false))
		assert.False(falseRecurse.withRecursive)
	})
}
