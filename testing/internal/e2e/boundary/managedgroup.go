// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/managedgroups"
	"github.com/stretchr/testify/require"
)

// CreateNewManagedGroupApi creates a new managed group using the Go api.
// Returns the id of the new managed group.
func CreateNewManagedGroupApi(t testing.TB, ctx context.Context, client *api.Client, amId string) string {
	mgClient := managedgroups.NewClient(client)
	newMGResult, err := mgClient.Create(ctx, amId,
		managedgroups.WithOidcManagedGroupFilter(`"/token/zip" == "zap"`),
	)
	require.NoError(t, err)

	managedGroupId := newMGResult.Item.Id
	t.Logf("Created Managed Group: %s", managedGroupId)
	return managedGroupId
}
