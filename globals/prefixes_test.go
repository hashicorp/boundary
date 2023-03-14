// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package globals

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsTopLevelResourcePrefix(t *testing.T) {
	// Test a random sampling
	topLevel := []string{VaultCredentialStorePrefix, StaticCredentialStorePrefix, GroupPrefix, TcpTargetPrefix}
	child := []string{VaultCredentialLibraryPrefix, OidcManagedGroupPrefix, StaticHostSetPrefix, JsonCredentialPrefix}

	for _, prefix := range topLevel {
		assert.True(t, IsTopLevelResourcePrefix(prefix))
		assert.True(t, IsTopLevelResourcePrefix(fmt.Sprintf("%s_foobar", prefix)))
		assert.False(t, IsTopLevelResourcePrefix(fmt.Sprintf("%sfoobar", prefix)))
	}
	for _, prefix := range child {
		assert.False(t, IsTopLevelResourcePrefix(prefix))
		assert.False(t, IsTopLevelResourcePrefix(fmt.Sprintf("%s_foobar", prefix)))
		assert.False(t, IsTopLevelResourcePrefix(fmt.Sprintf("%sfoobar", prefix)))
	}
}
