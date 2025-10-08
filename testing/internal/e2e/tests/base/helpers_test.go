// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

type boundaryResources struct {
	organizationId string
	projectId      string
	targetId       string
	storeId        string
}

// setupBoundaryResources sets up the following Boundary resources:
// Org, Project, Target, Credential Store.
// Also authenticates through CLI as admin.
func setupBoundaryCredentialStore(t *testing.T, ctx context.Context, hostname string, port string) *boundaryResources {
	boundary.AuthenticateAdminCli(t, ctx)

	orgId, err := boundary.CreateOrgCli(t, ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", orgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})

	projectId, err := boundary.CreateProjectCli(t, ctx, orgId)
	require.NoError(t, err)

	targetId, err := boundary.CreateTargetCli(
		t,
		ctx,
		projectId,
		port,
		target.WithAddress(hostname),
	)
	require.NoError(t, err)

	storeId, err := boundary.CreateCredentialStoreStaticCli(t, ctx, projectId)
	require.NoError(t, err)

	return &boundaryResources{
		targetId: targetId,
		storeId:  storeId,
	}
}
