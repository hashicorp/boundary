// Copyright IBM Corp. 2020, 2025
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
