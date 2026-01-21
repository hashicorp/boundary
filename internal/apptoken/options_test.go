// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/stretchr/testify/assert"
)

type fakeItem struct {
	pagination.Item
	publicId   string
	createTime time.Time
}

func (p *fakeItem) GetPublicId() string {
	return p.publicId
}

func (p *fakeItem) GetUpdateTime() *timestamp.Timestamp {
	return nil
}

func (p *fakeItem) GetCreateTime() *timestamp.Timestamp {
	return timestamp.New(p.createTime)
}

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()

	t.Run("withRecursive", func(t *testing.T) {
		assert := assert.New(t)

		// Test with default (false)
		opts := getOpts()
		testOpts := getDefaultOptions()
		assert.Equal(opts, testOpts)

		// Test with true
		opts = getOpts(WithRecursive(true))
		testOpts = getDefaultOptions()
		testOpts.withRecursive = true
		assert.Equal(opts, testOpts)
	})

	t.Run("withLimit", func(t *testing.T) {
		assert := assert.New(t)

		// Test with default limit
		opts := getOpts()
		testOpts := getDefaultOptions()
		assert.Equal(opts, testOpts)
		assert.Equal(db.DefaultLimit, opts.withLimit)

		// Test with custom limit
		opts = getOpts(WithLimit(10))
		testOpts = getDefaultOptions()
		testOpts.withLimit = 10
		assert.Equal(opts, testOpts)
	})

	t.Run("withStartPageAfterItem", func(t *testing.T) {
		assert := assert.New(t)

		// Test with default (nil)
		opts := getOpts()
		testOpts := getDefaultOptions()
		assert.Equal(opts, testOpts)

		createTime := time.Now()
		opts = getOpts(WithStartPageAfterItem(&fakeItem{nil, "s_1", createTime}))
		assert.Equal(opts.withStartPageAfterItem.GetPublicId(), "s_1")
		assert.Equal(opts.withStartPageAfterItem.GetCreateTime(), timestamp.New(createTime))
	})
}
