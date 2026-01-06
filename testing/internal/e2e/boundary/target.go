// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/go-secure-stdlib/base62"
)

// ReadTargetApi uses the Go API to read a target given its id.
func ReadTargetApi(t testing.TB, ctx context.Context, client *api.Client, targetId string) (*targets.Target, error) {
	tClient := targets.NewClient(client)
	trr, err := tClient.Read(ctx, targetId)
	if err != nil {
		return nil, err
	}
	if trr == nil {
		return nil, fmt.Errorf("target read response was empty")
	}
	if trr.GetItem() == nil {
		return nil, fmt.Errorf("target read response item was empty")
	}

	return trr.GetItem(), nil
}

// ListTargetsApi uses the Go API to list targets in a project scope.
func ListTargetsApi(t testing.TB, ctx context.Context, client *api.Client, projectId string) ([]*targets.Target, error) {
	tClient := targets.NewClient(client)
	tlr, err := tClient.List(ctx, projectId)
	if err != nil {
		return nil, err
	}
	if tlr == nil {
		return nil, fmt.Errorf("target list response was empty")
	}

	return tlr.GetItems(), nil
}

// DeleteTargetApi uses the Go API to delete a target with the given id.
func DeleteTargetApi(t testing.TB, ctx context.Context, client *api.Client, targetId string) error {
	tClient := targets.NewClient(client)
	_, err := tClient.Delete(ctx, targetId)
	return err
}

// CreateTargetApi uses the Go API to create a new target of the provided type
// in Boundary. Automatically sets a random target name.
// Returns the id of the new target.
func CreateTargetApi(t testing.TB, ctx context.Context, client *api.Client, projectId, targetType string, opts ...targets.Option) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}
	opts = append(opts, targets.WithName(fmt.Sprintf("e2e Target %s", name)))

	tClient := targets.NewClient(client)
	newTargetResult, err := tClient.Create(ctx, targetType, projectId, opts...)
	if err != nil {
		return "", err
	}

	targetId := newTargetResult.Item.Id
	t.Logf("Created Target: %s", targetId)
	return targetId, nil
}

// UpdateTargetApi uses the Go API to update a Boundary target given its id.
func UpdateTargetApi(t testing.TB, ctx context.Context, client *api.Client, targetId string, opts ...targets.Option) error {
	tClient := targets.NewClient(client)

	opts = append(opts, targets.WithAutomaticVersioning(true))
	_, err := tClient.Update(ctx, targetId, 0, opts...)
	return err
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

// AddBrokeredCredentialSourceToTargetApi uses the Go API to add a brokered
// credential source to a target.
func AddBrokeredCredentialSourceToTargetApi(t testing.TB, ctx context.Context, client *api.Client, targetId, credentialSourceId string) error {
	tClient := targets.NewClient(client)
	_, err := tClient.AddCredentialSources(ctx, targetId, 0,
		targets.WithAutomaticVersioning(true),
		targets.WithBrokeredCredentialSourceIds([]string{credentialSourceId}),
	)
	return err
}

// CreateTargetCli uses the cli to create a new target in boundary
// Returns the id of the new target.
func CreateTargetCli(t testing.TB, ctx context.Context, projectId string, defaultPort string, targetOpts []target.Option, opt ...e2e.Option) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	opts := target.GetOpts(targetOpts...)
	var args []e2e.Option

	args = append(args, e2e.WithArgs("targets", "create"))
	// Set target type. Default to tcp if not specified
	if opts.WithType != "" {
		args = append(args, e2e.WithArgs(string(opts.WithType)))
	} else {
		args = append(args, e2e.WithArgs("tcp"))
	}

	args = append(args,
		e2e.WithArgs("-scope-id", projectId,
			"-default-port", defaultPort,
			"-description", "e2e",
			"-format", "json"),
	)

	if opts.WithName != "" {
		args = append(args, e2e.WithArgs("-name", opts.WithName))
	} else {
		args = append(args, e2e.WithArgs("-name", fmt.Sprintf("e2e Target %s", name)))
	}
	if opts.WithDescription != "" {
		args = append(args, e2e.WithArgs("-description", opts.WithDescription))
	}
	if opts.WithAddress != "" {
		args = append(args, e2e.WithArgs("-address", opts.WithAddress))
	}
	if opts.WithDefaultClientPort != 0 {
		args = append(args, e2e.WithArgs("-default-client-port", fmt.Sprintf("%d", opts.WithDefaultClientPort)))
	}
	if opts.WithEnableSessionRecording {
		args = append(args, e2e.WithArgs("-enable-session-recording", fmt.Sprintf("%v", opts.WithEnableSessionRecording)))
	}
	if opts.WithStorageBucketId != "" {
		args = append(args, e2e.WithArgs("-storage-bucket-id", opts.WithStorageBucketId))
	}
	if opts.WithIngressWorkerFilter != "" {
		args = append(args, e2e.WithArgs("-ingress-worker-filter", opts.WithIngressWorkerFilter))
	}
	if opts.WithEgressWorkerFilter != "" {
		args = append(args, e2e.WithArgs("-egress-worker-filter", opts.WithEgressWorkerFilter))
	}
	if opts.WithSessionConnectionLimit != 0 {
		args = append(args, e2e.WithArgs("-session-connection-limit", fmt.Sprintf("%d", opts.WithSessionConnectionLimit)))
	}
	if opts.WithSessionMaxSeconds != 0 {
		args = append(args, e2e.WithArgs("-session-max-seconds", fmt.Sprintf("%d", opts.WithSessionMaxSeconds)))
	}
	args = append(args, opt...)

	output := e2e.RunCommand(ctx, "boundary",
		args...,
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

// UpdateTargetCli uses the CLI to update a Boundary target.
func UpdateTargetCli(t testing.TB, ctx context.Context, targetId string, opt ...target.Option) error {
	opts := target.GetOpts(opt...)
	var args []string

	// Set target type. Default to tcp if not specified
	if opts.WithType != "" {
		args = append(args, string(opts.WithType))
	} else {
		args = append(args, "tcp")
	}

	args = append(args, "-format", "json")
	args = append(args, "-id", targetId)
	if opts.WithName != "" {
		args = append(args, "-name", opts.WithName)
	}
	if opts.WithDescription != "" {
		args = append(args, "-description", opts.WithDescription)
	}
	if opts.WithAddress != "" {
		args = append(args, "-address", opts.WithAddress)
	}
	if opts.WithDefaultPort != 0 {
		args = append(args, "-default-port", fmt.Sprintf("%d", opts.WithDefaultPort))
	}
	if opts.WithDefaultClientPort != 0 {
		args = append(args, "-default-client-port", fmt.Sprintf("%d", opts.WithDefaultClientPort))
	}
	if opts.WithEnableSessionRecording {
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
		e2e.WithArgs("targets", "update"),
		e2e.WithArgs(args...),
	)
	if output.Err != nil {
		return fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	return nil
}

// ReadTargetCli uses the CLI to read a Boundary target with the given id.
func ReadTargetCli(t testing.TB, ctx context.Context, targetId string) (*targets.Target, error) {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("targets", "read"),
		e2e.WithArgs("-id", targetId),
		e2e.WithArgs("-format", "json"),
	)
	if output.Err != nil {
		return nil, fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	var readTargetResult targets.TargetReadResult
	err := json.Unmarshal(output.Stdout, &readTargetResult)
	if err != nil {
		return nil, err
	}
	if readTargetResult.GetItem() == nil {
		return nil, fmt.Errorf("target read response item was empty")
	}

	return readTargetResult.GetItem(), nil
}

// ListTargetsCli uses the CLI to list Boundary targets in a given project scope.
func ListTargetsCli(t testing.TB, ctx context.Context, projectId string) ([]*targets.Target, error) {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("targets", "list"),
		e2e.WithArgs("-scope-id", projectId),
		e2e.WithArgs("-format", "json"),
	)
	if output.Err != nil {
		return nil, fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	var listTargetResult targets.TargetListResult
	err := json.Unmarshal(output.Stdout, &listTargetResult)
	if err != nil {
		return nil, err
	}

	return listTargetResult.GetItems(), nil
}

// DeleteTargetCli uses the CLI to delete a Boundary target with the given id.
func DeleteTargetCli(t testing.TB, ctx context.Context, targetId string) error {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("targets", "delete"),
		e2e.WithArgs("-id", targetId),
		e2e.WithArgs("-format", "json"),
	)
	if output.Err != nil {
		return fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	return nil
}

// AddHostSourceToTargetCli uses the cli to add a host source (host set or host)
// to a target.
// Boundary's `add-host-sources` functionality appends a new host source to the
// existing set of host sources in the target.
func AddHostSourceToTargetCli(t testing.TB, ctx context.Context, targetId, hostSourceId string) error {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("targets", "add-host-sources", "-id", targetId, "-host-source", hostSourceId),
	)
	if output.Err != nil {
		return fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	return nil
}

// SetHostSourceToTargetCli uses the cli to set a host source (host set or host)
// to a target.
// Boundary's `set-host-sources` functionality replaces all existing host sets
// on a target with the provided one.
func SetHostSourceToTargetCli(t testing.TB, ctx context.Context, targetId, hostSourceId string) error {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("targets", "set-host-sources", "-id", targetId, "-host-source", hostSourceId),
	)
	if output.Err != nil {
		return fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	return nil
}

// RemoveHostSourceFromTargetCli uses the cli to remove a host source (host set or host) to a target
func RemoveHostSourceFromTargetCli(t testing.TB, ctx context.Context, targetId, hostSourceId string) error {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "remove-host-sources",
			"-id", targetId,
			"-host-source", hostSourceId,
		),
	)
	if output.Err != nil {
		return fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	return nil
}

// AddBrokeredCredentialSourceToTargetCli uses the cli to add a credential source (credential library or
// credential) to a target
func AddBrokeredCredentialSourceToTargetCli(t testing.TB, ctx context.Context, targetId string, credentialSourceId string) error {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "add-credential-sources",
			"-id", targetId,
			"-brokered-credential-source", credentialSourceId,
		),
	)
	if output.Err != nil {
		return fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	return nil
}

// RemoveBrokeredCredentialSourceFromTargetCli uses the cli to remove a credential source (credential library or
// credential) from a target
func RemoveBrokeredCredentialSourceFromTargetCli(t testing.TB, ctx context.Context, targetId string, credentialSourceId string) error {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "remove-credential-sources",
			"-id", targetId,
			"-brokered-credential-source", credentialSourceId,
		),
	)
	if output.Err != nil {
		return fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	return nil
}
