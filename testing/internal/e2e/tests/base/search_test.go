// Copyright IBM Corp. 2020, 2025
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

	ctx := t.Context()

	// If cache is already running, stop it so that we can start it with a
	// shorter refresh interval
	output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("cache", "status", "-format", "json"))
	if output.Err == nil {
		t.Log("Stopping cache...")
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("cache", "stop"))
		require.NoError(t, output.Err, string(output.Stderr))
	}
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"cache", "start",
			"-refresh-interval", "5s",
			"-background",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Cleanup(func() {
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("cache", "stop"))
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Wait for cache to be up and running
	t.Log("Waiting for cache to start...")
	var statusResult clientcache.StatusResult
	err = backoff.RetryNotify(
		func() error {
			output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("cache", "status", "-format", "json"))
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

	// Confirm cache version matches CLI version
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
	projectId, err := boundary.CreateProjectCli(t, ctx, orgId)
	require.NoError(t, err)

	// Get current number of targets
	// Do a force-refresh first to ensure cache has the latest information
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"search",
			"-resource", "targets",
			"-force-refresh", "true",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var currentCount int
	err = backoff.RetryNotify(
		func() error {
			output = e2e.RunCommand(ctx, "boundary", e2e.WithArgs("cache", "status", "-format", "json"))
			if output.Err != nil {
				return backoff.Permanent(errors.New(string(output.Stderr)))
			}

			statusResult = clientcache.StatusResult{}
			err = json.Unmarshal(output.Stdout, &statusResult)
			if err != nil {
				return errors.New("Failed to unmarshal status result")
			}

			if len(statusResult.Item.Users) == 0 {
				output = e2e.RunCommand(ctx, "cat", e2e.WithArgs(statusResult.Item.LogLocation))
				t.Log("Printing cache log...")
				t.Log(string(output.Stdout))
				return errors.New("No users are appearing in the status")
			}
			idx := slices.IndexFunc(
				statusResult.Item.Users[0].Resources,
				func(r clientcache.ResourceStatus) bool {
					return r.Name == "target"
				},
			)
			if idx == -1 {
				output = e2e.RunCommand(ctx, "cat", e2e.WithArgs(statusResult.Item.LogLocation))
				t.Log("Printing cache log...")
				t.Log(string(output.Stdout))
				return errors.New("Targets not found in cache")
			}
			currentCount = statusResult.Item.Users[0].Resources[idx].Count

			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)

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
		resp, err := tClient.Create(ctx, "tcp", projectId,
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
	output = e2e.RunCommand(ctx, "boundary", e2e.WithArgs("targets", "list", "-scope-id", projectId, "-format", "json"))
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
			output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("cache", "status", "-format", "json"))
			if output.Err != nil {
				return backoff.Permanent(errors.New(string(output.Stderr)))
			}

			var statusResult clientcache.StatusResult
			err = json.Unmarshal(output.Stdout, &statusResult)
			if err != nil {
				return backoff.Permanent(err)
			}

			if len(statusResult.Item.Users) == 0 {
				output = e2e.RunCommand(ctx, "cat", e2e.WithArgs(statusResult.Item.LogLocation))
				t.Log("Printing cache log...")
				t.Log(string(output.Stdout))
				return errors.New("No users are appearing in the status")
			}

			idx := slices.IndexFunc(
				statusResult.Item.Users[0].Resources,
				func(r clientcache.ResourceStatus) bool {
					return r.Name == "target"
				},
			)
			if idx == -1 {
				output = e2e.RunCommand(ctx, "cat", e2e.WithArgs(statusResult.Item.LogLocation))
				t.Log("Printing cache log...")
				t.Log(string(output.Stdout))
				return errors.New("No targets are appearing in the status")
			}

			if statusResult.Item.Users[0].Resources[idx].Count != currentCount+c.MaxPageSize+1 {
				return fmt.Errorf(
					"Did not see expected number of targets in status, EXPECTED: %d, ACTUAL: %d",
					currentCount+c.MaxPageSize+1,
					statusResult.Item.Users[0].Resources[idx].Count,
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
	// This requests data from the client cache.
	t.Log("Searching targets...")
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"search",
			"-resource", "targets",
			"-format", "json",
			"-query", fmt.Sprintf(`name %% "%s" and scope_id = "%s"`, targetPrefix, projectId),
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
			"-query", fmt.Sprintf(`name = "%s1" and scope_id = "%s"`, targetPrefix, projectId),
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
			"-query", fmt.Sprintf(`scope_id = "%s"`, projectId),
			"-force-refresh", "true",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	searchResult = clientcache.SearchResult{}
	err = json.Unmarshal(output.Stdout, &searchResult)
	require.NoError(t, err)
	require.Len(t, searchResult.Item.Sessions, 0)

	// Log out and confirm search does not work
	output = e2e.RunCommand(ctx, "boundary", e2e.WithArgs("logout"))
	require.NoError(t, output.Err, string(output.Stderr))
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"search",
			"-resource", "targets",
			"-format", "json",
			"-query", fmt.Sprintf(`name %% "%s" and scope_id = "%s"`, targetPrefix, projectId),
		),
	)
	require.Error(t, output.Err)

	// Log back in and confirm search works
	boundary.AuthenticateAdminCli(t, ctx)
	err = backoff.RetryNotify(
		func() error {
			output := e2e.RunCommand(ctx, "boundary",
				e2e.WithArgs(
					"search",
					"-resource", "targets",
					"-format", "json",
					"-query", fmt.Sprintf(`name %% "%s" and scope_id = "%s"`, targetPrefix, projectId),
				),
			)
			if output.Err != nil {
				outputStatus := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("cache", "status", "-format", "json"))
				t.Log("Printing cache status...")
				t.Log(string(outputStatus.Stdout))
				var statusResult clientcache.StatusResult
				err = json.Unmarshal(outputStatus.Stdout, &statusResult)
				if err != nil {
					return backoff.Permanent(err)
				}

				outputLog := e2e.RunCommand(ctx, "cat", e2e.WithArgs(statusResult.Item.LogLocation))
				t.Log("Printing cache log...")
				t.Log(string(outputLog.Stdout))

				// BUG WORKAROUND: It seems like there's some weird interaction where
				// occasionally, the cache fails to update after authentication
				// on Linux environments
				// https://hashicorp.atlassian.net/browse/ICU-16595
				boundary.AuthenticateAdminCli(t, ctx)

				return errors.New(string(output.Stderr))
			}

			searchResult := clientcache.SearchResult{}
			err := json.Unmarshal(output.Stdout, &searchResult)
			if err != nil {
				return backoff.Permanent(err)
			}

			if len(searchResult.Item.Targets) != len(targetIds) {
				return fmt.Errorf(
					"Search did not return expected number of targets, EXPECTED: %d, ACTUAL: %d",
					len(targetIds),
					len(searchResult.Item.Targets),
				)
			}

			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(1*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)

	// Restart cache and confirm search works
	t.Log("Stopping cache...")
	output = e2e.RunCommand(ctx, "boundary", e2e.WithArgs("cache", "stop"))
	require.NoError(t, output.Err, string(output.Stderr))
	err = backoff.RetryNotify(
		func() error {
			output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("cache", "status", "-format", "json"))

			if strings.Contains(string(output.Stderr), "The cache process is not running") {
				return nil
			}

			return fmt.Errorf("Waiting for cache to stop: %s", string(output.Stdout))
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(1*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)
	t.Log("Starting cache...")
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"cache", "start",
			"-refresh-interval", "5s",
			"-background",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	err = backoff.RetryNotify(
		func() error {
			output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("cache", "status", "-format", "json"))
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
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"search",
			"-resource", "targets",
			"-format", "json",
			"-query", fmt.Sprintf(`name %% "%s" and scope_id = "%s"`, targetPrefix, projectId),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	searchResult = clientcache.SearchResult{}
	err = json.Unmarshal(output.Stdout, &searchResult)
	require.NoError(t, err)
	require.Len(t, searchResult.Item.Targets, len(targetIds))

	// Log out and restart cache. Log in and confirm search works
	output = e2e.RunCommand(ctx, "boundary", e2e.WithArgs("logout"))
	t.Log("Stopping cache...")
	output = e2e.RunCommand(ctx, "boundary", e2e.WithArgs("cache", "stop"))
	require.NoError(t, output.Err, string(output.Stderr))
	err = backoff.RetryNotify(
		func() error {
			output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("cache", "status", "-format", "json"))

			if strings.Contains(string(output.Stderr), "The cache process is not running") {
				return nil
			}

			return fmt.Errorf("Waiting for cache to stop: %s", string(output.Stdout))
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(1*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)
	t.Log("Starting cache...")
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"cache", "start",
			"-refresh-interval", "5s",
			"-background",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	err = backoff.RetryNotify(
		func() error {
			output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("cache", "status", "-format", "json"))
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
	boundary.AuthenticateAdminCli(t, ctx)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"search",
			"-resource", "targets",
			"-format", "json",
			"-query", fmt.Sprintf(`name %% "%s" and scope_id = "%s"`, targetPrefix, projectId),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	searchResult = clientcache.SearchResult{}
	err = json.Unmarshal(output.Stdout, &searchResult)
	require.NoError(t, err)
	require.Len(t, searchResult.Item.Targets, len(targetIds))
}
