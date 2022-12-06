package boundary

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/stretchr/testify/require"
)

// CreateNewTargetApi uses the Go api to create a new target in boundary
// Returns the id of the new target.
func CreateNewTargetApi(t testing.TB, ctx context.Context, client *api.Client, projectId string, defaultPort string) string {
	tClient := targets.NewClient(client)
	targetPort, err := strconv.ParseInt(defaultPort, 10, 32)
	require.NoError(t, err)
	newTargetResult, err := tClient.Create(ctx, "tcp", projectId,
		targets.WithName("e2e Target"),
		targets.WithTcpTargetDefaultPort(uint32(targetPort)),
	)
	require.NoError(t, err)
	newTargetId := newTargetResult.Item.Id
	t.Logf("Created Target: %s", newTargetId)

	return newTargetId
}

// AddHostSourceToTargetApi uses the Go api to add a host source (host set or host) to a target
func AddHostSourceToTargetApi(t testing.TB, ctx context.Context, client *api.Client, targetId string, hostSourceId string) {
	tClient := targets.NewClient(client)
	_, err := tClient.AddHostSources(ctx, targetId, 0,
		[]string{hostSourceId},
		targets.WithAutomaticVersioning(true),
	)
	require.NoError(t, err)
}

// CreateNewTargetCli uses the cli to create a new target in boundary
// Returns the id of the new target.
func CreateNewTargetCli(t testing.TB, ctx context.Context, projectId string, defaultPort string) string {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "create", "tcp",
			"-scope-id", projectId,
			"-default-port", defaultPort,
			"-name", "e2e Target",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newTargetResult targets.TargetCreateResult
	err := json.Unmarshal(output.Stdout, &newTargetResult)
	require.NoError(t, err)
	newTargetId := newTargetResult.Item.Id
	t.Logf("Created Target: %s", newTargetId)

	return newTargetId
}

// AddHostSourceToTargetCli uses the cli to add a host source (host set or host) to a target
func AddHostSourceToTargetCli(t testing.TB, ctx context.Context, targetId string, hostSourceId string) {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("targets", "add-host-sources", "-id", targetId, "-host-source", hostSourceId),
	)
	require.NoError(t, output.Err, string(output.Stderr))
}

// AddCredentialSourceToTargetCli uses the cli to add a credential source (credential library or
// credential) to a target
func AddCredentialSourceToTargetCli(t testing.TB, ctx context.Context, targetId string, credentialSourceId string) {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "add-credential-sources",
			"-id", targetId,
			"-brokered-credential-source", credentialSourceId,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
}
