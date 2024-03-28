// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/clientcache"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/hashicorp/boundary/version"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"
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

	// Wait for daemon to be up and running
	t.Log("Waiting for daemon to start...")
	var statusResult clientcache.StatusResult
	err = backoff.RetryNotify(
		func() error {
			output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("daemon", "status", "-format", "json"))
			if output.Err != nil {
				return errors.New(strings.TrimSpace(string(output.Stderr)))
			}

			err = json.Unmarshal(output.Stdout, &statusResult)
			if err != nil {
				return backoff.Permanent(err)
			}

			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(1*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)
	require.Equal(t, statusResult.StatusCode, 200)
	require.GreaterOrEqual(t, statusResult.Item.Uptime, 0*time.Second)

	// Confirm daemon version matches CLI version
	output = e2e.RunCommand(ctx, "boundary", e2e.WithArgs("version", "-format", "json"))
	require.NoError(t, output.Err, string(output.Stderr))
	var versionResult version.Info
	err = json.Unmarshal(output.Stdout, &versionResult)
	require.NoError(t, err)
	require.Contains(t, statusResult.Item.Version, versionResult.Revision)

	// Set up a new org and project
	boundary.AuthenticateAdminCli(t, ctx)
	orgId, err := boundary.CreateOrgCli(t, ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", orgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	newProjectId := boundary.CreateNewProjectCli(t, ctx, orgId)

	// Get current number of targets
	output = e2e.RunCommand(ctx, "boundary", e2e.WithArgs("daemon", "status", "-format", "json"))
	require.NoError(t, output.Err, string(output.Stderr))
	statusResult = clientcache.StatusResult{}
	err = json.Unmarshal(output.Stdout, &statusResult)
	require.Len(t, statusResult.Item.Users, 1)
	idx := slices.IndexFunc(
		statusResult.Item.Users[0].Resources,
		func(r clientcache.ResourceStatus) bool {
			return r.Name == "target"
		},
	)
	require.NotEqual(t, idx, -1)
	currentCount := statusResult.Item.Users[0].Resources[idx].Count

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

	// List targets.
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

	// Wait for data to be populated in the client cache
	t.Log("Waiting for client cache to populate data...")
	err = backoff.RetryNotify(
		func() error {
			output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("daemon", "status", "-format", "json"))
			if output.Err != nil {
				return backoff.Permanent(errors.New(string(output.Stderr)))
			}

			var statusResult clientcache.StatusResult
			err = json.Unmarshal(output.Stdout, &statusResult)
			if err != nil {
				return backoff.Permanent(err)
			}

			if len(statusResult.Item.Users) == 0 {
				return errors.New("No users are appearing in the status")
			}

			idx := slices.IndexFunc(
				statusResult.Item.Users[0].Resources,
				func(r clientcache.ResourceStatus) bool {
					return r.Name == "target"
				},
			)
			if idx == -1 {
				return errors.New("No targets are appearing in the status")
			}

			if statusResult.Item.Users[0].Resources[idx].Count != currentCount+c.MaxPageSize+1 {
				return errors.New(
					fmt.Sprintf(
						"Did not see expected number of targets in status, EXPECTED: %d, ACTUAL: %d",
						currentCount+c.MaxPageSize+1,
						statusResult.Item.Users[0].Resources[idx].Count,
					),
				)
			}

			t.Logf("Found %d target(s)", statusResult.Item.Users[0].Resources[idx].Count)
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
	t.Log("Searching targets...")
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"search",
			"-resource", "targets",
			"-format", "json",
			"-query", fmt.Sprintf(`name %% "%s" and scope_id = "%s"`, targetPrefix, newProjectId),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var searchResult clientcache.SearchResult
	err = json.Unmarshal(output.Stdout, &searchResult)
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

	// Do another search for sessions with the force-refresh option set to true
	// and no resources available.
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"search",
			"-resource", "sessions",
			"-force-refresh", "true",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	searchResult = clientcache.SearchResult{}
	err = json.Unmarshal(output.Stdout, &searchResult)
	require.NoError(t, err)
	require.Len(t, searchResult.Item.Sessions, 0)
}
