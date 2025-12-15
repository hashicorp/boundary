// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package storagebucketcredential

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithSecret", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithSecret(
			&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"ACCESS_KEY_ID":     structpb.NewStringValue("access_key_id"),
					"SECRET_ACCESS_KEY": structpb.NewStringValue("secret_access_key"),
				},
			},
		))
		testOpts := getDefaultOptions()
		testOpts.WithSecret = &structpb.Struct{
			Fields: map[string]*structpb.Value{
				"ACCESS_KEY_ID":     structpb.NewStringValue("access_key_id"),
				"SECRET_ACCESS_KEY": structpb.NewStringValue("secret_access_key"),
			},
		}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithKeyId", func(t *testing.T) {
		assert := assert.New(t)
		opts := GetOpts(WithKeyId("test-key-id"))
		testOpts := getDefaultOptions()
		testOpts.WithKeyId = "test-key-id"
		assert.Equal(opts, testOpts)
	})
}
