// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package globals

import (
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
)

func TestResourceInfoFromPrefix(t *testing.T) {
	// Test a random sampling
	vals := map[string]resource.Type{
		VaultCredentialLibraryPrefix: resource.CredentialLibrary,
		OidcManagedGroupPrefix:       resource.ManagedGroup,
		StaticHostSetPrefix:          resource.HostSet,
		JsonCredentialPrefix:         resource.Credential,
	}

	for prefix, typ := range vals {
		assert.Equal(t, typ, ResourceInfoFromPrefix(prefix).Type)
		assert.Equal(t, typ, ResourceInfoFromPrefix(fmt.Sprintf("%s_foobar", prefix)).Type)
		assert.Equal(t, resource.Unknown, ResourceInfoFromPrefix(fmt.Sprintf("%sfoobar", prefix)).Type)
	}
}
