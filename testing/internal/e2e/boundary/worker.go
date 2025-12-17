// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/hashicorp/boundary/api/workers"
	"github.com/hashicorp/boundary/testing/internal/e2e"
)

// GetWorkerWithFilterCli returns a worker using the boundary CLI with a filter
// If no worker is found, an error is returned.
// If more than 1 worker is found, an error is returned.
func GetWorkerWithFilterCli(t testing.TB, ctx context.Context, filter string) (*workers.Worker, error) {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"workers", "list",
			"-format", "json",
			"-filter", filter,
		),
	)
	if output.Err != nil {
		return nil, fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	var workersListResult workers.WorkerListResult
	err := json.Unmarshal(output.Stdout, &workersListResult)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal workers list result: %w", err)
	}

	items := workersListResult.GetItems()
	if len(items) == 0 {
		return nil, fmt.Errorf("no workers found using filter: %s", filter)
	}
	if len(items) > 1 {
		return nil, fmt.Errorf("more than 1 worker found. Found %v workers using filter: %s", len(items), filter)
	}

	return items[0], nil
}

func GetWorkersByTagCli(t testing.TB, ctx context.Context, tagKey, tagValue string) ([]*workers.Worker, error) {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"workers", "list",
			"-format", "json",
		),
	)
	if output.Err != nil {
		return nil, fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	var workersListResult workers.WorkerListResult
	err := json.Unmarshal(output.Stdout, &workersListResult)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal workers list result: %w", err)
	}

	items := workersListResult.GetItems()
	if len(items) == 0 {
		return nil, fmt.Errorf("no workers found using tag key: %s", tagKey)
	}

	var workersWithTagKey []*workers.Worker
	for _, worker := range items {
		if slices.Contains(worker.CanonicalTags[tagKey], tagValue) {
			workersWithTagKey = append(workersWithTagKey, worker)
		}
	}

	return workersWithTagKey, nil
}
