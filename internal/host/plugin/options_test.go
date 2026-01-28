// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

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
	t.Run("WithExternalName", func(t *testing.T) {
		opts := getOpts(WithExternalName("external-name"))
		testOpts := getDefaultOptions()
		testOpts.withExternalName = "external-name"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithStartPageAfterItem", func(t *testing.T) {
		assert := assert.New(t)
		updateTime := time.Now()
		opts := getOpts(WithStartPageAfterItem(&fakeItem{nil, "s_1", updateTime}))
		assert.Equal(opts.withStartPageAfterItem.GetPublicId(), "s_1")
		assert.Equal(opts.withStartPageAfterItem.GetUpdateTime(), timestamp.New(updateTime))
	})
	t.Run("WithWorkerFilter", func(t *testing.T) {
		opts := getOpts(WithWorkerFilter(`"test" in "/tags/type"`))
		testOpts := getDefaultOptions()
		testOpts.withWorkerFilter = `"test" in "/tags/type"`
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithReaderWriter", func(t *testing.T) {
		reader := &db.Db{}
		writer := &db.Db{}
		opts := getOpts(WithReaderWriter(reader, writer))
		assert.Equal(t, reader, opts.WithReader)
		assert.Equal(t, writer, opts.withWriter)
	})
}
