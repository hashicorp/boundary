// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/clientcache"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliSearch asserts that the CLI can search for targets
func TestCliSearch(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := context.Background()

	// If daemon is already running, stop it so that we can start it with a
	// shorter refresh interval
	output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("daemon", "status", "-format", "json"))
	if output.Err == nil {
		t.Log("Stopping daemon...")
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("daemon", "stop"))
		require.NoError(t, output.Err, string(output.Stderr))
	}
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"daemon", "start",
			"-refresh-interval", "5s",
			"-background",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Cleanup(func() {
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("daemon", "stop"))
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Wait for daemon to start
	err = backoff.RetryNotify(
		func() error {
			output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("daemon", "status", "-format", "json"))
			if output.Err != nil {
				return errors.New("Daemon is still starting up...")
			}

			require.NoError(t, output.Err, string(output.Stderr))
			var statusResult clientcache.StatusResult
			err = json.Unmarshal(output.Stdout, &statusResult)
			require.NoError(t, err)
			require.Equal(t, statusResult.StatusCode, 200)
			require.GreaterOrEqual(t, statusResult.Item.Uptime, 0*time.Second)
			t.Log("Daemon has started")
			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(1*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)

	// Set up a new org and project
	boundary.AuthenticateAdminCli(t, ctx)
	newOrgId := boundary.CreateNewOrgCli(t, ctx)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", newOrgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	newProjectId := boundary.CreateNewProjectCli(t, ctx, newOrgId)

	// Create enough targets to overflow a single page.
	// Use the API to make creation faster.
	t.Log("Creating targets...")
	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	tClient := targets.NewClient(client)
	targetPort, err := strconv.ParseInt(c.TargetPort, 10, 32)
	require.NoError(t, err)
	var targetIds []string
	targetPrefix := "test-target"
	for i := 0; i < c.MaxPageSize+1; i++ {
		resp, err := tClient.Create(ctx, "tcp", newProjectId,
			targets.WithName(targetPrefix+strconv.Itoa(i)),
			targets.WithTcpTargetDefaultPort(uint32(targetPort)),
			targets.WithAddress(c.TargetAddress),
		)
		require.NoError(t, err)
		targetIds = append(targetIds, resp.Item.Id)
	}

	// List targets recursively.
	// This requests data from the controller/database.
	t.Log("Listing targets...")
	output = e2e.RunCommand(ctx, "boundary", e2e.WithArgs("targets", "list", "-scope-id", newProjectId, "-format", "json"))
	require.NoError(t, output.Err, string(output.Stderr))
	var targetListResult targets.TargetListResult
	err = json.Unmarshal(output.Stdout, &targetListResult)
	require.NoError(t, err)
	var listedIds []string
	for _, item := range targetListResult.Items {
		listedIds = append(listedIds, item.Id)
	}
	require.Equal(t, len(targetIds), len(listedIds))

	err = backoff.RetryNotify(
		func() error {
			output = e2e.RunCommand(ctx, "boundary",
				e2e.WithArgs(
					"search",
					"-resource", "targets",
					"-format", "json",
					"-query", fmt.Sprintf(`name %% "%s" and scope_id = "%s"`, targetPrefix, newProjectId),
				),
			)
			if output.Err != nil {
				return backoff.Permanent(errors.New(string(output.Stderr)))
			}

			var searchResult clientcache.SearchResult
			err = json.Unmarshal(output.Stdout, &searchResult)
			require.NoError(t, err)
			if err != nil {
				return backoff.Permanent(err)
			}

			targetCount := len(searchResult.Item.Targets)
			if targetCount == 0 {
				return errors.New("No targets are appearing in the search results")
			}

			t.Logf("Found %d target(s)", targetCount)
			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)

	// Search for targets that contain the target prefix.
	// This requests data from the client cache daemon.
	// The force refresh option forces the client daemon to fetch new data
	t.Log("Searching targets...")
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"search",
			"-resource", "targets",
			"-format", "json",
			"-query", fmt.Sprintf(`name %% "%s" and scope_id = "%s"`, targetPrefix, newProjectId),
			"-force-refresh",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var searchResult clientcache.SearchResult
	err = json.Unmarshal(output.Stdout, &searchResult)
	require.NoError(t, err)
	var searchedIds []string
	for _, target := range searchResult.Item.Targets {
		searchedIds = append(searchedIds, target.Id)
	}
	require.Equal(t, len(targetIds), len(searchedIds))
	require.Empty(t, cmp.Diff(listedIds, searchedIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))

	// Do another search for a specific target name. Expect only 1 result
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"search",
			"-resource", "targets",
			"-format", "json",
			"-query", fmt.Sprintf(`name = "%s1" and scope_id = "%s"`, targetPrefix, newProjectId),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	searchResult = clientcache.SearchResult{}
	err = json.Unmarshal(output.Stdout, &searchResult)
	require.NoError(t, err)
	require.Len(t, searchResult.Item.Targets, 1)
}
