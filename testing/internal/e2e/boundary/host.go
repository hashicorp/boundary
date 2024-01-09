// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/stretchr/testify/require"
)

// CreateNewHostCatalogApi uses the Go api to create a new host catalog.
// Returns the id of the new host catalog.
func CreateNewHostCatalogApi(t testing.TB, ctx context.Context, client *api.Client, projectId string) string {
	hcClient := hostcatalogs.NewClient(client)
	newHostCatalogResult, err := hcClient.Create(ctx, "static", projectId)
	require.NoError(t, err)
	newHostCatalogId := newHostCatalogResult.Item.Id
	t.Logf("Created Host Catalog: %s", newHostCatalogId)

	return newHostCatalogId
}

// CreateNewHostSetApi uses the Go api to create a new host set.
// Returns the id of the new host set.
func CreateNewHostSetApi(t testing.TB, ctx context.Context, client *api.Client, hostCatalogId string) string {
	hsClient := hostsets.NewClient(client)
	newHostSetResult, err := hsClient.Create(ctx, hostCatalogId)
	require.NoError(t, err)
	newHostSetId := newHostSetResult.Item.Id
	t.Logf("Created Host Set: %s", newHostSetId)

	return newHostSetId
}

// CreateNewHostApi uses the Go api to create a new host.
// Returns the id of the new host.
func CreateNewHostApi(t testing.TB, ctx context.Context, client *api.Client, hostCatalogId string, address string) string {
	hClient := hosts.NewClient(client)
	newHostResult, err := hClient.Create(ctx, hostCatalogId,
		hosts.WithStaticHostAddress(address),
	)
	require.NoError(t, err)
	newHostId := newHostResult.Item.Id
	t.Logf("Created Host: %s", newHostId)

	return newHostId
}

// AddHostToHostSetApi uses the Go api to add a host to a host set
func AddHostToHostSetApi(t testing.TB, ctx context.Context, client *api.Client, hostSetId string, hostId string) {
	hsClient := hostsets.NewClient(client)
	_, err := hsClient.AddHosts(ctx, hostSetId, 0, []string{hostId}, hostsets.WithAutomaticVersioning(true))
	require.NoError(t, err)
}

// CreateNewHostCatalogCli uses the cli to create a new host catalog.
// Returns the id of the new host catalog.
func CreateNewHostCatalogCli(t testing.TB, ctx context.Context, projectId string) string {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"host-catalogs", "create", "static",
			"-scope-id", projectId,
			"-name", "e2e Host Catalog",
			"-description", "e2e",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostCatalogResult hostcatalogs.HostCatalogCreateResult
	err := json.Unmarshal(output.Stdout, &newHostCatalogResult)
	require.NoError(t, err)
	newHostCatalogId := newHostCatalogResult.Item.Id

	t.Logf("Created Host Catalog: %s", newHostCatalogId)
	return newHostCatalogId
}

// CreateNewHostSetCli uses the cli to create a new host set.
// Returns the id of the new host set.
func CreateNewHostSetCli(t testing.TB, ctx context.Context, hostCatalogId string) string {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"host-sets", "create", "static",
			"-host-catalog-id", hostCatalogId,
			"-name", "e2e Host Set",
			"-description", "e2e",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostSetResult hostsets.HostSetCreateResult
	err := json.Unmarshal(output.Stdout, &newHostSetResult)
	require.NoError(t, err)
	newHostSetId := newHostSetResult.Item.Id
	t.Logf("Created Host Set: %s", newHostSetId)

	return newHostSetId
}

// CreateNewHostCli uses the cli to create a new host.
// Returns the id of the new host.
func CreateNewHostCli(t testing.TB, ctx context.Context, hostCatalogId string, address string) string {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"hosts", "create", "static",
			"-host-catalog-id", hostCatalogId,
			"-name", address,
			"-description", "e2e",
			"-address", address,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostResult hosts.HostCreateResult
	err := json.Unmarshal(output.Stdout, &newHostResult)
	require.NoError(t, err)
	newHostId := newHostResult.Item.Id
	t.Logf("Created Host: %s", newHostId)

	return newHostId
}

// AddHostToHostSetCli uses the cli to add a host to a host set
func AddHostToHostSetCli(t testing.TB, ctx context.Context, hostSetId string, hostId string) {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("host-sets", "add-hosts", "-id", hostSetId, "-host", hostId),
	)
	require.NoError(t, output.Err, string(output.Stderr))
}

// CreateNewAwsHostCatalogCli uses the cli to create a new AWS dynamic host catalog.
// Returns the id of the new host catalog.
func CreateNewAwsHostCatalogCli(t testing.TB, ctx context.Context, projectId string, accessKeyId string, secretAccessKey string) string {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"host-catalogs", "create", "plugin",
			"-scope-id", projectId,
			"-plugin-name", "aws",
			"-attr", "disable_credential_rotation=true",
			"-attr", "region=us-east-1",
			"-secret", "access_key_id=env://E2E_AWS_ACCESS_KEY_ID",
			"-secret", "secret_access_key=env://E2E_AWS_SECRET_ACCESS_KEY",
			"-description", "e2e",
			"-format", "json",
		),
		e2e.WithEnv("E2E_AWS_ACCESS_KEY_ID", accessKeyId),
		e2e.WithEnv("E2E_AWS_SECRET_ACCESS_KEY", secretAccessKey),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostCatalogResult hostcatalogs.HostCatalogCreateResult
	err := json.Unmarshal(output.Stdout, &newHostCatalogResult)
	require.NoError(t, err)
	newHostCatalogId := newHostCatalogResult.Item.Id
	t.Logf("Created Host Catalog: %s", newHostCatalogId)

	return newHostCatalogId
}

// CreateNewAwsHostSetCli uses the cli to create a new host set from an AWS dynamic host catalog.
// Returns the id of the new host set.
func CreateNewAwsHostSetCli(t testing.TB, ctx context.Context, hostCatalogId string, filter string) string {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"host-sets", "create", "plugin",
			"-host-catalog-id", hostCatalogId,
			"-attr", "filters="+filter,
			"-description", "e2e",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostSetResult hostsets.HostSetCreateResult
	err := json.Unmarshal(output.Stdout, &newHostSetResult)
	require.NoError(t, err)

	newHostSetId := newHostSetResult.Item.Id
	t.Logf("Created Host Set: %s", newHostSetId)
	return newHostSetId
}

// WaitForHostsInHostSetCli uses the cli to check if there are any hosts in a host set. It will check a
// few times before returning a result. The method will fail if there are 0 hosts found.
func WaitForHostsInHostSetCli(t testing.TB, ctx context.Context, hostSetId string) int {
	t.Logf("Looking for items in the host set...")
	var actualHostSetCount int
	err := backoff.RetryNotify(
		func() error {
			output := e2e.RunCommand(ctx, "boundary",
				e2e.WithArgs(
					"host-sets", "read",
					"-id", hostSetId,
					"-format", "json",
				),
			)
			if output.Err != nil {
				return backoff.Permanent(errors.New(string(output.Stderr)))
			}

			var hostSetsReadResult hostsets.HostSetReadResult
			err := json.Unmarshal(output.Stdout, &hostSetsReadResult)
			if err != nil {
				return backoff.Permanent(err)
			}

			actualHostSetCount = len(hostSetsReadResult.Item.HostIds)
			if actualHostSetCount == 0 {
				return errors.New("No items are appearing in the host set")
			}

			t.Logf("Found %d host(s)", actualHostSetCount)
			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)

	return actualHostSetCount
}

// WaitForNumberOfHostsInHostSetCli uses the cli to check if the number of hosts
// in a host set match the expected. The method will throw an error if it does
// not match after some retries.
func WaitForNumberOfHostsInHostSetCli(t testing.TB, ctx context.Context, hostSetId string, expectedHostCount int) {
	t.Logf("Looking for items in the host set...")
	var actualHostSetCount int
	err := backoff.RetryNotify(
		func() error {
			output := e2e.RunCommand(ctx, "boundary",
				e2e.WithArgs(
					"host-sets", "read",
					"-id", hostSetId,
					"-format", "json",
				),
			)
			if output.Err != nil {
				return backoff.Permanent(errors.New(string(output.Stderr)))
			}

			var hostSetsReadResult hostsets.HostSetReadResult
			err := json.Unmarshal(output.Stdout, &hostSetsReadResult)
			if err != nil {
				return backoff.Permanent(err)
			}

			actualHostSetCount = len(hostSetsReadResult.Item.HostIds)
			if actualHostSetCount != expectedHostCount {
				return errors.New(
					fmt.Sprintf("Number of hosts in host set do not match expected. EXPECTED: %d, ACTUAL: %d",
						expectedHostCount,
						actualHostSetCount,
					))
			}

			t.Logf("Found %d host(s)", actualHostSetCount)
			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)
}
