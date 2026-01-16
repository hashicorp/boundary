// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
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
	t.Run("WithProjectIds", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithProjectIds([]string{"o_1234"}))
		testOpts := getDefaultOptions()
		testOpts.withProjectIds = []string{"o_1234"}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithOrderByCreateTime", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithOrderByCreateTime(db.AscendingOrderBy))
		testOpts := getDefaultOptions()
		testOpts.withOrderByCreateTime = db.AscendingOrderBy
		assert.Equal(opts, testOpts)
	})
	t.Run("WithUserId", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithUserId("u_1234"))
		testOpts := getDefaultOptions()
		testOpts.withUserId = "u_1234"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithExpirationTime", func(t *testing.T) {
		assert := assert.New(t)
		now := timestamppb.Now()
		opts := getOpts(WithExpirationTime(&timestamp.Timestamp{Timestamp: now}))
		testOpts := getDefaultOptions()
		testOpts.withExpirationTime = &timestamp.Timestamp{Timestamp: now}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTestTofu", func(t *testing.T) {
		assert := assert.New(t)
		tofu := TestTofu(t)
		opts := getOpts(WithTestTofu(tofu))
		testOpts := getDefaultOptions()
		testOpts.withTestTofu = make([]byte, len(tofu))
		copy(testOpts.withTestTofu, tofu)
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSessionIds", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithSessionIds("s_1", "s_2", "s_3"))
		testOpts := getDefaultOptions()
		testOpts.withSessionIds = []string{"s_1", "s_2", "s_3"}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithIgnoreDecryptionFailures", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithIgnoreDecryptionFailures(true))
		testOpts := getDefaultOptions()
		testOpts.withIgnoreDecryptionFailures = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithRandomReader", func(t *testing.T) {
		assert := assert.New(t)
		reader := strings.NewReader("notrandom")
		opts := getOpts(WithRandomReader(reader))
		testOpts := getDefaultOptions()
		testOpts.withRandomReader = reader
		assert.Equal(opts, testOpts)
	})
	t.Run("WithProxyCertificate", func(t *testing.T) {
		assert := assert.New(t)
		pc := &ProxyCertificate{
			Certificate: []byte("test-cert"),
			PrivateKey:  []byte("test-key"),
			SessionId:   "s_1234",
		}
		opts := getOpts(WithProxyCertificate(pc))
		testOpts := getDefaultOptions()
		testOpts.withProxyCertificate = pc
		assert.Equal(opts, testOpts)
	})
}
