// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package globals

import (
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
)

func TestResourceTypeFromPrefix(t *testing.T) {
	// Test a random sampling
	vals := map[string]resource.Type{
		VaultCredentialLibraryPrefix: resource.CredentialLibrary,
		OidcManagedGroupPrefix:       resource.ManagedGroup,
		StaticHostSetPrefix:          resource.HostSet,
		JsonCredentialPrefix:         resource.Credential,
	}

	for prefix, typ := range vals {
		assert.Equal(t, typ, ResourceTypeFromPrefix(prefix))
		assert.Equal(t, typ, ResourceTypeFromPrefix(fmt.Sprintf("%s_foobar", prefix)))
		assert.Equal(t, resource.Unknown, ResourceTypeFromPrefix(fmt.Sprintf("%sfoobar", prefix)))
	}
}
