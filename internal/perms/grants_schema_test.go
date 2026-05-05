// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package perms_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/boundary/internal/perms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Import to trigger init() registrations in all service handlers
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/accounts"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/aliases"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/authmethods"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/authtokens"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/billing"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/credentiallibraries"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/credentials"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/credentialstores"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/groups"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/host_catalogs"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/host_sets"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/hosts"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/managed_groups"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/policies"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/roles"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/scopes"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/session_recordings"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/sessions"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/storage_buckets"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/users"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/workers"
)

func TestBuildGrantSchema(t *testing.T) {
	ctx := context.Background()
	schema, err := perms.BuildGrantSchema(ctx)
	require.NoError(t, err)
	require.NotNil(t, schema)
	assert.NotEmpty(t, schema.ResourceTypes, "resource types should not be empty")

	// JSON serialization should produce valid JSON
	data, err := perms.BuildGrantSchemaJSON(ctx)
	require.NoError(t, err)
	assert.True(t, json.Valid(data), "output should be valid JSON")
}

func TestBuildGrantSchema_PinPrefixes(t *testing.T) {
	ctx := context.Background()
	schema, err := perms.BuildGrantSchema(ctx)
	require.NoError(t, err)

	// Build a lookup by type name for easy assertions
	byType := make(map[string]perms.ResourceTypeSchema, len(schema.ResourceTypes))
	for _, rt := range schema.ResourceTypes {
		byType[rt.Type] = rt
	}

	// Child types must have PinPrefixes set to the parent's ID prefixes
	hostSet, ok := byType["host-set"]
	require.True(t, ok, "host-set should be in the schema")
	assert.Equal(t, "host-catalog", hostSet.ParentType)
	assert.NotEmpty(t, hostSet.PinPrefixes, "host-set should have pin prefixes")

	host, ok := byType["host"]
	require.True(t, ok, "host should be in the schema")
	assert.Equal(t, "host-catalog", host.ParentType)
	assert.NotEmpty(t, host.PinPrefixes, "host should have pin prefixes")

	account, ok := byType["account"]
	require.True(t, ok, "account should be in the schema")
	assert.Equal(t, "auth-method", account.ParentType)
	assert.NotEmpty(t, account.PinPrefixes, "account should have pin prefixes")

	credLib, ok := byType["credential-library"]
	require.True(t, ok, "credential-library should be in the schema")
	assert.Equal(t, "credential-store", credLib.ParentType)
	assert.NotEmpty(t, credLib.PinPrefixes, "credential-library should have pin prefixes")

	// Top-level types must not have PinPrefixes
	hostCatalog, ok := byType["host-catalog"]
	require.True(t, ok, "host-catalog should be in the schema")
	assert.Empty(t, hostCatalog.PinPrefixes, "host-catalog is a top-level type and should have no pin prefixes")

	authMethod, ok := byType["auth-method"]
	require.True(t, ok, "auth-method should be in the schema")
	assert.Empty(t, authMethod.PinPrefixes, "auth-method is a top-level type and should have no pin prefixes")

	// PinPrefixes for host-set should match host-catalog's IdPrefixes
	assert.ElementsMatch(t, hostCatalog.IdPrefixes, hostSet.PinPrefixes,
		"host-set's pin prefixes should match host-catalog's id prefixes")
}
