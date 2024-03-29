// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/go-secure-stdlib/base62"
)

// CreateTargetApi uses the Go api to create a new target in boundary
// Returns the id of the new target.
func CreateTargetApi(t testing.TB, ctx context.Context, client *api.Client, projectId string, defaultPort string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	tClient := targets.NewClient(client)
	targetPort, err := strconv.ParseInt(defaultPort, 10, 32)
	if err != nil {
		return "", err
	}

	newTargetResult, err := tClient.Create(ctx, "tcp", projectId,
		targets.WithName(fmt.Sprintf("e2e Target %s", name)),
		targets.WithTcpTargetDefaultPort(uint32(targetPort)),
	)
	if err != nil {
		return "", err
	}

	targetId := newTargetResult.Item.Id
	t.Logf("Created Target: %s", targetId)
	return targetId, nil
}

// AddHostSourceToTargetApi uses the Go api to add a host source (host set or host) to a target
func AddHostSourceToTargetApi(t testing.TB, ctx context.Context, client *api.Client, targetId string, hostSourceId string) error {
	tClient := targets.NewClient(client)
	_, err := tClient.AddHostSources(ctx, targetId, 0,
		[]string{hostSourceId},
		targets.WithAutomaticVersioning(true),
	)
	return err
}

// CreateTargetCli uses the cli to create a new target in boundary
// Returns the id of the new target.
func CreateTargetCli(t testing.TB, ctx context.Context, projectId string, defaultPort string, opt ...target.Option) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	opts := target.GetOpts(opt...)
	var args []string

	// Set target type. Default to tcp if not specified
	if opts.WithType != "" {
		args = append(args, string(opts.WithType))
	} else {
		args = append(args, "tcp")
	}

	args = append(args,
		"-scope-id", projectId,
		"-default-port", defaultPort,
		"-description", "e2e",
		"-format", "json",
	)

	if opts.WithName != "" {
		args = append(args, "-name", opts.WithName)
	} else {
		args = append(args, "-name", fmt.Sprintf("e2e Target %s", name))
	}
	if opts.WithAddress != "" {
		args = append(args, "-address", opts.WithAddress)
	}
	if opts.WithDefaultClientPort != 0 {
		args = append(args, "-default-client-port", fmt.Sprintf("%d", opts.WithDefaultClientPort))
	}
	if opts.WithEnableSessionRecording != false {
		args = append(args, "-enable-session-recording", fmt.Sprintf("%v", opts.WithEnableSessionRecording))
	}
	if opts.WithStorageBucketId != "" {
		args = append(args, "-storage-bucket-id", opts.WithStorageBucketId)
	}
	if opts.WithIngressWorkerFilter != "" {
		args = append(args, "-ingress-worker-filter", opts.WithIngressWorkerFilter)
	}
	if opts.WithEgressWorkerFilter != "" {
		args = append(args, "-egress-worker-filter", opts.WithEgressWorkerFilter)
	}
	if opts.WithSessionConnectionLimit != 0 {
		args = append(args, "-session-connection-limit", fmt.Sprintf("%d", opts.WithSessionConnectionLimit))
	}
	if opts.WithSessionMaxSeconds != 0 {
		args = append(args, "-session-max-seconds", fmt.Sprintf("%d", opts.WithSessionMaxSeconds))
	}

	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("targets", "create"),
		e2e.WithArgs(args...),
	)
	if output.Err != nil {
		return "", fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	var createTargetResult targets.TargetCreateResult
	err = json.Unmarshal(output.Stdout, &createTargetResult)
	if err != nil {
		return "", err
	}

	targetId := createTargetResult.Item.Id
	t.Logf("Created Target: %s", targetId)
	return targetId, nil
}

// AddHostSourceToTargetCli uses the cli to add a host source (host set or host)
// to a target.
// Boundary's `add-host-sources` functionality appends a new host source to the
// existing set of host sources in the target.
func AddHostSourceToTargetCli(t testing.TB, ctx context.Context, targetId, hostSourceId string) {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("targets", "add-host-sources", "-id", targetId, "-host-source", hostSourceId),
	)
	require.NoError(t, output.Err, string(output.Stderr))
}

// SetHostSourceToTargetCli uses the cli to set a host source (host set or host)
// to a target.
// Boundary's `set-host-sources` functionality replaces all existing host sets
// on a target with the provided one.
func SetHostSourceToTargetCli(t testing.TB, ctx context.Context, targetId, hostSourceId string) {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("targets", "set-host-sources", "-id", targetId, "-host-source", hostSourceId),
	)
	require.NoError(t, output.Err, string(output.Stderr))
}

// RemoveHostSourceFromTargetCli uses the cli to remove a host source (host set or host) to a target
func RemoveHostSourceFromTargetCli(t testing.TB, ctx context.Context, targetId, hostSourceId string) {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "remove-host-sources",
			"-id", targetId,
			"-host-source", hostSourceId,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
}

// AddBrokeredCredentialSourceToTargetCli uses the cli to add a credential source (credential library or
// credential) to a target
func AddBrokeredCredentialSourceToTargetCli(t testing.TB, ctx context.Context, targetId string, credentialSourceId string) {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "add-credential-sources",
			"-id", targetId,
			"-brokered-credential-source", credentialSourceId,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
}

// RemoveBrokeredCredentialSourceFromTargetCli uses the cli to remove a credential source (credential library or
// credential) from a target
func RemoveBrokeredCredentialSourceFromTargetCli(t testing.TB, ctx context.Context, targetId string, credentialSourceId string) {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "remove-credential-sources",
			"-id", targetId,
			"-brokered-credential-source", credentialSourceId,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
}
