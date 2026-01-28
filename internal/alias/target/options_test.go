// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

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

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithName", func(t *testing.T) {
		opts, err := getOpts(WithName("test"))
		assert.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withName = "test"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithDescription", func(t *testing.T) {
		opts, err := getOpts(WithDescription("test desc"))
		assert.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withDescription = "test desc"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithDestinationId", func(t *testing.T) {
		opts, err := getOpts(WithDestinationId("test"))
		assert.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withDestinationId = "test"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithHostId", func(t *testing.T) {
		opts, err := getOpts(WithHostId("test"))
		assert.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withHostId = "test"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithLimit", func(t *testing.T) {
		opts, err := getOpts(WithLimit(5))
		assert.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withLimit = 5
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithStartPageAfterItem", func(t *testing.T) {
		updateTime := time.Now()
		opts, err := getOpts(WithStartPageAfterItem(&fakeItem{nil, "s_1", updateTime}))
		assert.NoError(t, err)
		assert.Equal(t, opts.withStartPageAfterItem.GetPublicId(), "s_1")
		assert.Equal(t, opts.withStartPageAfterItem.GetUpdateTime(), timestamp.New(updateTime))
	})
}
