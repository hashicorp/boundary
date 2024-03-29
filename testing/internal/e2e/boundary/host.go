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
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/stretchr/testify/require"
)

// CreateHostCatalogApi uses the Go api to create a new host catalog.
// Returns the id of the new host catalog.
func CreateHostCatalogApi(t testing.TB, ctx context.Context, client *api.Client, projectId string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	hcClient := hostcatalogs.NewClient(client)
	createHostCatalogResult, err := hcClient.Create(
		ctx,
		"static",
		projectId,
		hostcatalogs.WithName(fmt.Sprintf("e2e Host Catalog %s", name)))
	if err != nil {
		return "", err
	}

	hostCatalogId := createHostCatalogResult.Item.Id
	t.Logf("Created Host Catalog: %s", hostCatalogId)
	return hostCatalogId, nil
}

// CreateHostSetApi uses the Go api to create a new host set.
// Returns the id of the new host set.
func CreateHostSetApi(t testing.TB, ctx context.Context, client *api.Client, hostCatalogId string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	hsClient := hostsets.NewClient(client)
	createHostSetResult, err := hsClient.Create(ctx, hostCatalogId, hostsets.WithName(fmt.Sprintf("e2e Host Set %s", name)))
	if err != nil {
		return "", err
	}

	hostSetId := createHostSetResult.Item.Id
	t.Logf("Created Host Set: %s", hostSetId)
	return hostSetId, nil
}

// CreateHostApi uses the Go api to create a new host.
// Returns the id of the new host.
func CreateHostApi(t testing.TB, ctx context.Context, client *api.Client, hostCatalogId string, address string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	hClient := hosts.NewClient(client)
	createHostResult, err := hClient.Create(ctx, hostCatalogId,
		hosts.WithStaticHostAddress(address),
		hosts.WithName(fmt.Sprintf("e2e Host %s", name)),
	)
	if err != nil {
		return "", err
	}

	hostId := createHostResult.Item.Id
	t.Logf("Created Host: %s", hostId)
	return hostId, nil
}

// AddHostToHostSetApi uses the Go api to add a host to a host set
func AddHostToHostSetApi(t testing.TB, ctx context.Context, client *api.Client, hostSetId string, hostId string) error {
	hsClient := hostsets.NewClient(client)
	_, err := hsClient.AddHosts(ctx, hostSetId, 0, []string{hostId}, hostsets.WithAutomaticVersioning(true))
	return err
}

// CreateHostCatalogCli uses the cli to create a new host catalog.
// Returns the id of the new host catalog.
func CreateHostCatalogCli(t testing.TB, ctx context.Context, projectId string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"host-catalogs", "create", "static",
			"-scope-id", projectId,
			"-name", fmt.Sprintf("e2e Host Catalog %s", name),
			"-description", "e2e",
			"-format", "json",
		),
	)
	if output.Err != nil {
		return "", fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	var createHostCatalogResult hostcatalogs.HostCatalogCreateResult
	err = json.Unmarshal(output.Stdout, &createHostCatalogResult)
	if err != nil {
		return "", err
	}

	hostCatalogId := createHostCatalogResult.Item.Id
	t.Logf("Created Host Catalog: %s", hostCatalogId)
	return hostCatalogId, nil
}

// CreateHostSetCli uses the cli to create a new host set.
// Returns the id of the new host set.
func CreateHostSetCli(t testing.TB, ctx context.Context, hostCatalogId string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"host-sets", "create", "static",
			"-host-catalog-id", hostCatalogId,
			"-name", fmt.Sprintf("e2e Host Set %s", name),
			"-description", "e2e",
			"-format", "json",
		),
	)
	if output.Err != nil {
		return "", fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	var createHostSetResult hostsets.HostSetCreateResult
	err = json.Unmarshal(output.Stdout, &createHostSetResult)
	if err != nil {
		return "", err
	}

	hostSetId := createHostSetResult.Item.Id
	t.Logf("Created Host Set: %s", hostSetId)
	return hostSetId, nil
}

// CreateHostCli uses the cli to create a new host.
// Returns the id of the new host.
func CreateHostCli(t testing.TB, ctx context.Context, hostCatalogId string, address string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"hosts", "create", "static",
			"-host-catalog-id", hostCatalogId,
			"-name", fmt.Sprintf("e2e Host %s", name),
			"-description", "e2e",
			"-address", address,
			"-format", "json",
		),
	)
	if output.Err != nil {
		return "", fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	var createHostResult hosts.HostCreateResult
	err = json.Unmarshal(output.Stdout, &createHostResult)
	if err != nil {
		return "", err
	}

	hostId := createHostResult.Item.Id
	t.Logf("Created Host: %s", hostId)
	return hostId, nil
}

// AddHostToHostSetCli uses the cli to add a host to a host set
func AddHostToHostSetCli(t testing.TB, ctx context.Context, hostSetId string, hostId string) error {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("host-sets", "add-hosts", "-id", hostSetId, "-host", hostId),
	)
	if output.Err != nil {
		return fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	return nil
}

// CreateAwsHostCatalogCli uses the cli to create a new AWS dynamic host catalog.
// Returns the id of the new host catalog.
func CreateAwsHostCatalogCli(t testing.TB, ctx context.Context, projectId string, accessKeyId string, secretAccessKey string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"host-catalogs", "create", "plugin",
			"-scope-id", projectId,
			"-plugin-name", "aws",
			"-attr", "disable_credential_rotation=true",
			"-attr", "region=us-east-1",
			"-secret", "access_key_id=env://E2E_AWS_ACCESS_KEY_ID",
			"-secret", "secret_access_key=env://E2E_AWS_SECRET_ACCESS_KEY",
			"-name", fmt.Sprintf("e2e Host Catalog %s", name),
			"-description", "e2e",
			"-format", "json",
		),
		e2e.WithEnv("E2E_AWS_ACCESS_KEY_ID", accessKeyId),
		e2e.WithEnv("E2E_AWS_SECRET_ACCESS_KEY", secretAccessKey),
	)
	if output.Err != nil {
		return "", fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	var createHostCatalogResult hostcatalogs.HostCatalogCreateResult
	err = json.Unmarshal(output.Stdout, &createHostCatalogResult)
	if err != nil {
		return "", err
	}

	hostCatalogId := createHostCatalogResult.Item.Id
	t.Logf("Created Host Catalog: %s", hostCatalogId)
	return hostCatalogId, nil
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
