// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/managedgroups"
	"github.com/hashicorp/go-secure-stdlib/base62"
)

// CreateManagedGroupApi creates a new managed group using the Go api.
// Returns the id of the new managed group.
func CreateManagedGroupApi(t testing.TB, ctx context.Context, client *api.Client, amId string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	mgClient := managedgroups.NewClient(client)
	newMGResult, err := mgClient.Create(ctx, amId,
		managedgroups.WithOidcManagedGroupFilter(`"/token/zip" == "zap"`),
		managedgroups.WithName(fmt.Sprintf("e2e Managed Group %s", name)),
	)
	if err != nil {
		return "", err
	}

	managedGroupId := newMGResult.Item.Id
	t.Logf("Created Managed Group: %s", managedGroupId)
	return managedGroupId, nil
}
